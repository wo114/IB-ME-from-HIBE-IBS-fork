"""Independent Wang--PW fixed-issuer storage and crash regressions.

Run with WSL ~/miniconda3/envs/sage/bin/python -m pytest. Real roots, KeyExt
and signatures use the unchanged q=17/n=1/m_bar=5/m=10/dimension=15 backend.
Identities Alice/Bob are 5/3 bytes and lifecycle messages are 15 bytes. Fixed
random streams are TEST-ONLY; the system-random lifecycle uses the default
Backend. Fault doubles are used only to interrupt or corrupt genuine outputs.
Each case executes once, with two fresh processes and six cached-reader threads
for concurrency. No security level, distribution proof or benchmark is claimed;
security_claim remains none and backend_admitted remains false. Private state
stays in pytest temporary directories; comparisons and child reports use hashes.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

import pytest

pytest.importorskip("sage.all", reason="Use prescribed WSL ~/miniconda3/envs/sage")

from ibme.cli_state import LOCK_FILE, StateBusyError, key_issuance_lock
from ibme.core.errors import EncodingError
from ibme.core.randomness import DeterministicRandom
from ibme.ibs import wang_pw_service as service
from ibme.ibs.wang_pw_service import (
    FixedIssuer, IssuerCapacityError, IssuerPendingError, IssuerStateError,
)
from experiments.research.candidates.wang_pw import (
    Backend, MasterSecret, Params, SigningKey,
)
from experiments.research.candidates.wang_pw.codec import PREFIX, canonical
from experiments.research.gaussian_reference import SamplingAbort


IDENTITY = b"Alice"
MESSAGE = b"service-message"


class NoEntropy:
    def __init__(self):
        self.calls = 0

    def read(self, size):
        self.calls += 1
        raise AssertionError("unexpected entropy consumption")


class CountingRandom:
    def __init__(self, seed=b"wang-pw-service-user-v1", before_read=None):
        self.source = DeterministicRandom(seed)
        self.calls = 0
        self.before_read = before_read

    def read(self, size):
        if self.before_read is not None:
            self.before_read()
        self.calls += 1
        return self.source.read(size)


def digest(value):
    if not isinstance(value, bytes):
        value = value.to_bytes()
    return hashlib.sha256(value).hexdigest()


@dataclass(repr=False)
class Snapshot:
    raw: bytes
    public_digest: str
    key_digest: str | None = None


def state_path(instance):
    return instance.path / service.STATE_FILE


def read_record(instance):
    prefix = PREFIX + b"ISSUER\x00"
    raw = state_path(instance).read_bytes()
    if not raw.startswith(prefix):
        raise AssertionError("issuer wire prefix mismatch")
    return json.loads(raw[len(prefix):])


def write_record(instance, record):
    state_path(instance).write_bytes(PREFIX + b"ISSUER\x00" + canonical(record))


def restore(path, snapshot, rng=None):
    path.mkdir(mode=0o700)
    target = path / service.STATE_FILE
    target.write_bytes(snapshot.raw)
    target.chmod(0o600)
    return FixedIssuer(path, Backend(rng=NoEntropy() if rng is None else rng))


@pytest.fixture(scope="module")
def root_snapshot(tmp_path_factory):
    instance = FixedIssuer(tmp_path_factory.mktemp("wang-pw-root") / "issuer",
                           Backend(rng=DeterministicRandom(b"wang-pw-service-root-v1")))
    public = instance.initialize(Params())
    return Snapshot(state_path(instance).read_bytes(), digest(public))


@pytest.fixture(scope="module")
def issued_snapshot(tmp_path_factory, root_snapshot):
    instance = restore(tmp_path_factory.mktemp("wang-pw-issued") / "issuer",
                       root_snapshot, CountingRandom())
    key = instance.key_extract(IDENTITY)
    return Snapshot(state_path(instance).read_bytes(), digest(instance.public_key()), digest(key))


@pytest.fixture
def issuer(tmp_path, root_snapshot):
    return restore(tmp_path / "issuer", root_snapshot)


@pytest.fixture
def cached_issuer(tmp_path, issued_snapshot):
    return restore(tmp_path / "issuer", issued_snapshot)


def assert_blocked(path, *, marker=True):
    zero = NoEntropy()
    instance = FixedIssuer(path, Backend(rng=zero))
    if marker:
        assert os.path.lexists(path / service.PENDING_FILE)
    for identity in (IDENTITY, b"Bob"):
        with pytest.raises(IssuerPendingError):
            instance.key_extract(identity)
    with pytest.raises(IssuerPendingError):
        instance.public_key()
    if marker:
        with pytest.raises(IssuerPendingError):
            instance.initialize(Params())
    else:
        with pytest.raises((FileExistsError, IssuerPendingError)):
            instance.initialize(Params())
    assert zero.calls == 0


_CHILD = r'''
import hashlib,json,os,sys,time
from ibme.core.randomness import DeterministicRandom
from ibme.ibs.wang_pw_service import FixedIssuer
from experiments.research.candidates.wang_pw import Backend

class Source:
    def __init__(self, mode):
        self.mode,self.calls = mode,0
        self.source = DeterministicRandom(b"wang-pw-service-user-v1")
    def read(self, size):
        self.calls += 1
        if self.mode == "cached":
            raise AssertionError("cached recovery consumed entropy")
        if self.mode == "crash":
            os._exit(73)
        if self.calls == 1:
            time.sleep(0.1)
        return self.source.read(size)

source = Source(sys.argv[2])
issuer = FixedIssuer(sys.argv[1], Backend(rng=source))
key = issuer.key_extract(b"Alice")
signer = Backend(rng=DeterministicRandom(b"wang-pw-service-child-sign-v1"))
signature = signer.sign(key,b"service-message")
assert signer.verify(issuer.public_key(),b"Alice",b"service-message",signature)
print(json.dumps({"key_digest":hashlib.sha256(key.to_bytes()).hexdigest(),
                  "entropy_calls":source.calls,"verified":True}),flush=True)
'''


def child_args(path, mode):
    return [sys.executable, "-B", "-c", _CHILD, str(path), mode]


def child_env():
    root = Path(__file__).resolve().parents[1]
    return {**os.environ, "PYTHONPATH": os.pathsep.join((str(root / "src"), str(root))),
            "PYTHONDONTWRITEBYTECODE": "1"}


def run_child(path, mode):
    return subprocess.run(child_args(path, mode), env=child_env(), capture_output=True,
                          text=True, timeout=180)


def test_contract_constants_and_research_parameters():
    p = Params()
    assert (p.q, p.n, p.m_bar, p.m, p.dimension) == (17, 1, 5, 10, 15)
    assert p.security_claim == "none" and p.backend_admitted is False
    assert (service.STATE_FILE, service.PENDING_FILE) == ("master.bin", "master.bin.pending")
    assert service.MAX_STATE_BYTES == 2**20
    assert service.MAX_USERS == 64


def test_real_pending_precedes_sampling_and_issued_precedes_return(issuer):
    master_before = read_record(issuer)["master"]
    observations = []

    def before_entropy():
        if observations:
            return
        record = read_record(issuer)
        assert (issuer.path / service.PENDING_FILE).is_file()
        assert len(record["entries"]) == 1
        row = record["entries"][0]
        assert row["status"] == "pending" and row["key"] is None
        assert row["identity"] == IDENTITY.hex()
        observations.append(True)

    source = CountingRandom(before_read=before_entropy)
    instance = FixedIssuer(issuer.path, Backend(rng=source))
    key = instance.key_extract(IDENTITY)
    record = read_record(instance)
    assert observations == [True] and source.calls > 0
    assert record["entries"][0]["status"] == "issued"
    assert digest(bytes.fromhex(record["entries"][0]["key"])) == digest(key)
    assert digest(bytes.fromhex(record["master"])) == digest(bytes.fromhex(master_before))
    assert not (instance.path / service.PENDING_FILE).exists()
    signer = Backend(rng=DeterministicRandom(b"wang-pw-service-sign-v1"))
    signature = signer.sign(key, MESSAGE)
    assert signer.verify(instance.public_key(), IDENTITY, MESSAGE, signature)
    assert signature.identity_salt == key.identity_salt
    assert {entry.name for entry in instance.path.iterdir()} == {LOCK_FILE, service.STATE_FILE}
    if os.name == "posix":
        assert state_path(instance).stat().st_mode & 0o077 == 0
        assert instance.path.stat().st_mode & 0o077 == 0


def test_system_random_real_lifecycle(tmp_path):
    instance = FixedIssuer(tmp_path / "system-random")
    public = instance.initialize(Params(), max_users=1)
    key = instance.key_extract(b"Bob")
    signature = Backend().sign(key, MESSAGE)
    assert Backend().verify(public, b"Bob", MESSAGE, signature)
    assert digest(FixedIssuer(instance.path).key_extract(b"Bob")) == digest(key)


def test_cached_recovery_zero_entropy_no_write_and_fresh_signatures(cached_issuer, issued_snapshot, monkeypatch):
    before = digest(state_path(cached_issuer).read_bytes())

    def forbidden_replace(*args, **kwargs):
        pytest.fail("cache hit attempted state replacement")

    monkeypatch.setattr(service.os, "replace", forbidden_replace)
    zero = NoEntropy()
    recovered = FixedIssuer(cached_issuer.path, Backend(rng=zero))
    key = recovered.key_extract(memoryview(IDENTITY))
    again = recovered.key_extract(bytearray(IDENTITY))
    assert digest(key) == digest(again) == issued_snapshot.key_digest
    assert digest(recovered.public_key()) == issued_snapshot.public_digest
    assert digest(state_path(recovered).read_bytes()) == before
    assert zero.calls == 0
    signer = Backend(rng=CountingRandom(b"wang-pw-service-fresh-signatures"))
    first, second = signer.sign(key, MESSAGE), signer.sign(again, MESSAGE)
    assert signer.verify(recovered.public_key(), IDENTITY, MESSAGE, first)
    assert signer.verify(recovered.public_key(), IDENTITY, MESSAGE, second)
    assert first.message_salt != second.message_salt
    assert first.identity_salt == second.identity_salt


def test_fresh_process_recovers_cached_key(cached_issuer, issued_snapshot):
    result = run_child(cached_issuer.path, "cached")
    assert result.returncode == 0, "fresh-process cache/signature check failed"
    report = json.loads(result.stdout)
    assert report == {"key_digest": issued_snapshot.key_digest, "entropy_calls": 0, "verified": True}


def test_existing_instance_reloads_after_another_process(issuer):
    before = digest(issuer.public_key())
    result = run_child(issuer.path, "issue")
    assert result.returncode == 0, "subprocess issuance failed"
    report = json.loads(result.stdout)
    assert digest(issuer.key_extract(IDENTITY)) == report["key_digest"]
    assert digest(issuer.public_key()) == before


def test_six_cached_threads_use_no_entropy(cached_issuer, issued_snapshot):
    before = digest(state_path(cached_issuer).read_bytes())
    barrier = threading.Barrier(6)

    def cached_read(_):
        barrier.wait(timeout=20)
        instance = FixedIssuer(cached_issuer.path, Backend(rng=NoEntropy()))
        assert digest(instance.public_key()) == issued_snapshot.public_digest
        return digest(instance.key_extract(IDENTITY))

    with ThreadPoolExecutor(max_workers=6) as pool:
        reports = list(pool.map(cached_read, range(6)))
    assert set(reports) == {issued_snapshot.key_digest}
    assert digest(state_path(cached_issuer).read_bytes()) == before


def test_two_processes_issue_same_identity_exactly_once(issuer):
    children = [subprocess.Popen(child_args(issuer.path, "issue"), env=child_env(),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                for _ in range(2)]
    reports = []
    try:
        for child in children:
            stdout, _ = child.communicate(timeout=180)
            assert child.returncode == 0, "competing issuer process failed"
            reports.append(json.loads(stdout))
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.communicate()
    assert len({item["key_digest"] for item in reports}) == 1
    assert sum(item["entropy_calls"] > 0 for item in reports) == 1
    assert len(read_record(issuer)["entries"]) == 1
    assert digest(issuer.key_extract(IDENTITY)) == reports[0]["key_digest"]


def test_hard_process_exit_leaves_pending_ledger_and_releases_os_lock(issuer):
    result = run_child(issuer.path, "crash")
    assert result.returncode == 73
    with key_issuance_lock(issuer.path, timeout=0):
        pass
    assert read_record(issuer)["entries"][0]["status"] == "pending"
    assert_blocked(issuer.path)
    (issuer.path / service.PENDING_FILE).unlink()
    assert_blocked(issuer.path, marker=False)


@pytest.mark.parametrize("failure", [SamplingAbort, OSError, RuntimeError, KeyboardInterrupt])
def test_sampling_or_interrupt_saves_failed_ledger_without_retry(issuer, failure):
    calls = []

    class Interrupted(Backend):
        def key_extract(self, master, identity):
            assert read_record(issuer)["entries"][0]["status"] == "pending"
            calls.append(True)
            raise failure("injected extraction failure")

    instance = FixedIssuer(issuer.path, Interrupted(rng=NoEntropy()))
    with pytest.raises(failure):
        instance.key_extract(IDENTITY)
    assert calls == [True]
    assert read_record(instance)["entries"][0]["status"] == "failed"
    assert_blocked(instance.path)
    (instance.path / service.PENDING_FILE).unlink()
    assert_blocked(instance.path, marker=False)


def test_failed_new_identity_also_blocks_older_cached_identity(cached_issuer):
    class Interrupted(Backend):
        def key_extract(self, master, identity):
            raise SamplingAbort("injected new-identity abort")

    instance = FixedIssuer(cached_issuer.path, Interrupted(rng=NoEntropy()))
    with pytest.raises(SamplingAbort):
        instance.key_extract(b"Bob")
    assert [row["status"] for row in read_record(instance)["entries"]] == ["issued", "failed"]
    assert_blocked(instance.path)
    (instance.path / service.PENDING_FILE).unlink()
    assert_blocked(instance.path, marker=False)


@pytest.mark.parametrize("write_number", [1, 2])
@pytest.mark.parametrize("after_effect", [False, True])
def test_state_replace_failure_before_or_after_effect_blocks_all(issuer, monkeypatch, write_number, after_effect):
    original = service.os.replace
    count = 0

    def broken(source, target):
        nonlocal count
        if Path(target) == state_path(issuer):
            count += 1
            if count == write_number:
                if after_effect:
                    original(source, target)
                raise OSError("injected state publication failure")
        return original(source, target)

    rng = CountingRandom()
    monkeypatch.setattr(service.os, "replace", broken)
    instance = FixedIssuer(issuer.path, Backend(rng=rng))
    with pytest.raises(OSError):
        instance.key_extract(IDENTITY)
    assert (rng.calls > 0) is (write_number == 2)
    assert read_record(instance)["entries"][0]["status"] == "failed"
    assert_blocked(instance.path)
    (instance.path / service.PENDING_FILE).unlink()
    assert_blocked(instance.path, marker=False)


@pytest.mark.parametrize("after_effect", [False, True])
def test_finish_unlink_failure_rearms_and_saves_failure(issuer, monkeypatch, after_effect):
    original = Path.unlink
    fired = False

    def broken(path, *args, **kwargs):
        nonlocal fired
        if path == issuer.path / service.PENDING_FILE and not fired:
            fired = True
            if after_effect:
                original(path, *args, **kwargs)
            raise OSError("injected marker finish failure")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", broken)
    instance = FixedIssuer(issuer.path, Backend(rng=CountingRandom()))
    with pytest.raises(OSError):
        instance.key_extract(IDENTITY)
    assert fired
    assert_blocked(instance.path)
    assert read_record(instance)["entries"][0]["status"] == "failed"


def test_reservation_fsync_failure_is_before_entropy(issuer, monkeypatch):
    def broken(*args, **kwargs):
        raise OSError("injected reservation fsync failure")

    rng = NoEntropy()
    monkeypatch.setattr(service.os, "fsync", broken)
    instance = FixedIssuer(issuer.path, Backend(rng=rng))
    with pytest.raises(OSError):
        instance.key_extract(IDENTITY)
    assert rng.calls == 0
    assert_blocked(instance.path)


def test_completed_finish_then_interrupt_does_not_release_new_key(issuer, monkeypatch):
    instance = FixedIssuer(issuer.path, Backend(rng=CountingRandom()))
    original = instance._finish

    def interrupted():
        original()
        raise KeyboardInterrupt("injected post-finish interruption")

    monkeypatch.setattr(instance, "_finish", interrupted)
    with pytest.raises(KeyboardInterrupt):
        instance.key_extract(IDENTITY)
    assert_blocked(instance.path)


def test_marker_rearm_failure_still_attempts_writable_failed_ledger(issuer, monkeypatch):
    instance = FixedIssuer(issuer.path, Backend(rng=CountingRandom()))
    original_begin, original_finish = instance._begin, instance._finish
    begin_calls = 0

    def begin():
        nonlocal begin_calls
        begin_calls += 1
        if begin_calls > 1:
            raise OSError("injected marker recreation failure")
        return original_begin()

    def finish():
        original_finish()
        raise KeyboardInterrupt("injected interrupt after successful marker removal")

    monkeypatch.setattr(instance, "_begin", begin)
    monkeypatch.setattr(instance, "_finish", finish)
    with pytest.raises(KeyboardInterrupt):
        instance.key_extract(IDENTITY)
    assert begin_calls >= 2
    assert not (instance.path / service.PENDING_FILE).exists()
    row = read_record(instance)["entries"][0]
    assert row["status"] == "failed" and row["key"] is None
    assert_blocked(instance.path, marker=False)


def test_directory_fsync_failure_after_marker_removal_rearms(issuer, monkeypatch):
    original = service._sync_directory
    fired = False

    def broken(path):
        nonlocal fired
        if path == issuer.path and not (path / service.PENDING_FILE).exists() and not fired:
            fired = True
            raise OSError("injected completion directory fsync failure")
        return original(path)

    monkeypatch.setattr(service, "_sync_directory", broken)
    instance = FixedIssuer(issuer.path, Backend(rng=CountingRandom()))
    with pytest.raises(OSError):
        instance.key_extract(IDENTITY)
    assert fired
    assert_blocked(instance.path)


@pytest.mark.parametrize("operation", ["initialize", "key_extract"])
def test_real_finish_preserves_interrupt_when_marker_recreation_fails(tmp_path, root_snapshot, monkeypatch, operation):
    if operation == "initialize":
        instance = FixedIssuer(tmp_path / "new-root", Backend(
            rng=DeterministicRandom(b"wang-pw-service-root-v1")))
    else:
        instance = restore(tmp_path / "issuer", root_snapshot, CountingRandom())
    marker = instance.path / service.PENDING_FILE
    original_sync, original_open = service._sync_directory, service.os.open
    interrupt = KeyboardInterrupt("injected real-finish directory sync interruption")
    interrupted = False
    rearm_attempts = []

    def sync_directory(path):
        nonlocal interrupted
        # The real _finish has already unlinked the marker. Other directory
        # syncs and the later failed-ledger publication remain writable.
        if path == instance.path and not os.path.lexists(marker) and not interrupted:
            interrupted = True
            raise interrupt
        return original_sync(path)

    def open_file(path, flags, *args, **kwargs):
        if interrupted and Path(path) == marker and flags & os.O_CREAT:
            rearm_attempts.append(True)
            raise OSError("injected pending-marker recreation failure")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(service, "_sync_directory", sync_directory)
    monkeypatch.setattr(service.os, "open", open_file)
    with pytest.raises(KeyboardInterrupt) as caught:
        if operation == "initialize":
            instance.initialize(Params(), max_users=1)
        else:
            instance.key_extract(IDENTITY)
    assert caught.value is interrupt
    assert interrupted and rearm_attempts
    assert not os.path.lexists(marker)
    record = read_record(instance)
    assert record["status"] == "failed"
    if operation == "key_extract":
        row = record["entries"][0]
        assert row["status"] == "failed" and row["key"] is None
    else:
        assert record["entries"] == []
    assert_blocked(instance.path, marker=False)


@pytest.mark.parametrize("after_effect", [False, True])
def test_initial_state_publication_failure_never_allows_reinitialization(tmp_path, monkeypatch, after_effect):
    # Setup output is a genuine keypair. Reuse the real root to isolate I/O
    # failure here; no claim that replaying Setup represents fresh randomness.
    instance = FixedIssuer(tmp_path / "new-root", Backend(
        rng=DeterministicRandom(b"wang-pw-service-root-v1")))
    original = service.os.replace

    def broken(source, target):
        if Path(target) == state_path(instance):
            if after_effect:
                original(source, target)
            raise OSError("injected initial publication failure")
        return original(source, target)

    monkeypatch.setattr(service.os, "replace", broken)
    with pytest.raises(OSError):
        instance.initialize(Params(), max_users=1)
    assert state_path(instance).exists() is after_effect
    assert_blocked(instance.path)


def test_setup_interruption_blocks_instead_of_retrying(tmp_path):
    class Interrupted(Backend):
        def setup(self, params):
            raise KeyboardInterrupt("injected setup interruption")

    instance = FixedIssuer(tmp_path / "new-root", Interrupted(rng=NoEntropy()))
    with pytest.raises(KeyboardInterrupt):
        instance.initialize(Params())
    assert not state_path(instance).exists()
    assert_blocked(instance.path)


def test_setup_finish_interrupt_after_effect_rearms_pending(tmp_path, monkeypatch):
    instance = FixedIssuer(tmp_path / "new-root", Backend(
        rng=DeterministicRandom(b"wang-pw-service-root-v1")))
    original = instance._finish

    def interrupted():
        original()
        raise KeyboardInterrupt("injected initialization completion interruption")

    monkeypatch.setattr(instance, "_finish", interrupted)
    with pytest.raises(KeyboardInterrupt):
        instance.initialize(Params(), max_users=1)
    assert_blocked(instance.path)
    assert read_record(instance)["status"] == "failed"
    (instance.path / service.PENDING_FILE).unlink()
    assert_blocked(instance.path, marker=False)


def test_wrong_identity_output_is_not_published(issuer, issued_snapshot):
    class WrongIdentity(Backend):
        def key_extract(self, master, identity):
            record = json.loads(issued_snapshot.raw.split(b"\x00", 1)[1])
            return SigningKey.from_bytes(bytes.fromhex(record["entries"][0]["key"]))

    instance = FixedIssuer(issuer.path, WrongIdentity(rng=NoEntropy()))
    with pytest.raises(IssuerStateError):
        instance.key_extract(b"Bob")
    record = read_record(instance)
    assert record["entries"][0]["status"] == "failed"
    assert record["entries"][0]["key"] is None
    assert_blocked(instance.path)


@pytest.mark.parametrize("params", [None, {}, "debug", 17])
def test_bad_params_before_filesystem_or_entropy(tmp_path, params):
    zero = NoEntropy()
    instance = FixedIssuer(tmp_path / "uncreated", Backend(rng=zero))
    with pytest.raises(TypeError):
        instance.initialize(params)
    assert not instance.path.exists()
    assert zero.calls == 0


@pytest.mark.parametrize("max_users", [0, 65, True, 1.5, "2"])
def test_invalid_capacity_before_filesystem_or_entropy(tmp_path, max_users):
    zero = NoEntropy()
    instance = FixedIssuer(tmp_path / "uncreated", Backend(rng=zero))
    with pytest.raises(ValueError):
        instance.initialize(Params(), max_users=max_users)
    assert not instance.path.exists()
    assert zero.calls == 0


def test_whole_ledger_budget_rejected_before_filesystem_or_entropy(tmp_path):
    zero = NoEntropy()
    instance = FixedIssuer(tmp_path / "uncreated", Backend(rng=zero))
    with pytest.raises(IssuerCapacityError):
        instance.initialize(Params(identity_max_bytes=4096), max_users=64)
    assert not instance.path.exists()
    assert zero.calls == 0


@pytest.mark.parametrize("identity", [b"", "Alice", None, b"a" * 257])
def test_bad_identity_before_reservation_or_entropy(issuer, identity):
    before = digest(state_path(issuer).read_bytes())
    with pytest.raises(EncodingError):
        issuer.key_extract(identity)
    assert digest(state_path(issuer).read_bytes()) == before
    assert not (issuer.path / service.PENDING_FILE).exists()
    issuer.public_key()


def test_capacity_full_still_allows_original_cached_identity(cached_issuer, issued_snapshot):
    record = read_record(cached_issuer)
    record["max_users"] = 1
    write_record(cached_issuer, record)
    before = digest(state_path(cached_issuer).read_bytes())
    assert digest(cached_issuer.key_extract(IDENTITY)) == issued_snapshot.key_digest
    with pytest.raises(IssuerCapacityError):
        cached_issuer.key_extract(b"Bob")
    assert digest(state_path(cached_issuer).read_bytes()) == before
    assert not (cached_issuer.path / service.PENDING_FILE).exists()


def test_initialize_existing_state_or_unrelated_files_never_overwrites(issuer, tmp_path):
    before = digest(state_path(issuer).read_bytes())
    with pytest.raises(FileExistsError):
        issuer.initialize(Params())
    assert digest(state_path(issuer).read_bytes()) == before
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    (unrelated / "keep").write_bytes(b"keep")
    with pytest.raises(FileExistsError):
        FixedIssuer(unrelated, Backend(rng=NoEntropy())).initialize(Params())
    assert {entry.name for entry in unrelated.iterdir()} == {"keep"}


def test_bad_constructor_and_uninitialized_paths_do_not_touch_unrelated_files(tmp_path):
    zero = NoEntropy()
    backend = Backend(rng=zero)
    for path in ("", tmp_path.anchor):
        with pytest.raises(ValueError):
            FixedIssuer(path, backend)
    ordinary_file = tmp_path / "ordinary"
    ordinary_file.write_bytes(b"unrelated")
    with pytest.raises(IssuerStateError):
        FixedIssuer(ordinary_file, backend).initialize(Params())
    assert ordinary_file.read_bytes() == b"unrelated"
    empty = tmp_path / "empty"
    empty.mkdir()
    for operation, args in (("public_key", ()), ("key_extract", (IDENTITY,))):
        with pytest.raises(IssuerStateError):
            getattr(FixedIssuer(empty, backend), operation)(*args)
    assert list(empty.iterdir()) == []
    missing = tmp_path / "missing" / "issuer"
    with pytest.raises(FileNotFoundError):
        FixedIssuer(missing, backend).initialize(Params())
    assert not missing.parent.exists()
    assert zero.calls == 0


@pytest.mark.parametrize("wire_kind", ["empty", "invalid", "truncated", "appended", "duplicate", "hex"])
def test_malformed_state_is_rejected_without_replacement(cached_issuer, wire_kind):
    raw = state_path(cached_issuer).read_bytes()
    if wire_kind == "empty":
        damaged = b""
    elif wire_kind == "invalid":
        damaged = b"malformed-private-marker-never-log"
    elif wire_kind == "truncated":
        damaged = raw[:-1]
    elif wire_kind == "appended":
        damaged = raw + b"\x00"
    elif wire_kind == "duplicate":
        damaged = raw[:-1] + b',"version":1}'
    else:
        record = read_record(cached_issuer)
        record["master"] = "NOTHEX"
        damaged = PREFIX + b"ISSUER\x00" + canonical(record)
    state_path(cached_issuer).write_bytes(damaged)
    with pytest.raises(IssuerStateError) as error:
        cached_issuer.public_key()
    assert "malformed-private-marker-never-log" not in str(error.value)
    with pytest.raises(IssuerStateError):
        cached_issuer.key_extract(IDENTITY)
    with pytest.raises(FileExistsError):
        cached_issuer.initialize(Params())
    assert digest(state_path(cached_issuer).read_bytes()) == digest(damaged)


@pytest.mark.parametrize("change", ["identity", "context", "duplicate_identity", "status", "key_hex", "unknown", "capacity_bool"])
def test_ledger_context_identity_and_schema_checks(cached_issuer, change):
    record = read_record(cached_issuer)
    row = record["entries"][0]
    if change == "identity":
        row["identity"] = b"Bob".hex()
    elif change == "context":
        record["context"] = "00" * 32
    elif change == "duplicate_identity":
        record["entries"].append(dict(row))
    elif change == "status":
        row["status"] = "ready"
    elif change == "key_hex":
        row["key"] = "f "
    elif change == "unknown":
        row["extra"] = 1
    else:
        record["max_users"] = True
    write_record(cached_issuer, record)
    with pytest.raises(IssuerStateError):
        cached_issuer.public_key()
    with pytest.raises(IssuerStateError):
        cached_issuer.key_extract(IDENTITY)


@pytest.mark.parametrize("damage", ["pending", "failed", "context", "root_failed",
                                   "params", "identity", "key_public_key"])
def test_cheap_ledger_and_context_rejection_precedes_master_decode(cached_issuer, monkeypatch, damage):
    record = read_record(cached_issuer)
    if damage == "context":
        record["context"] = "00" * 32
    elif damage in ("pending", "failed"):
        record["entries"][0]["status"] = damage
        record["entries"][0]["key"] = None
    elif damage == "root_failed":
        record["status"] = "failed"
    elif damage == "identity":
        record["entries"][0]["identity"] = b"Bob".hex()
    elif damage == "params":
        master = json.loads(bytes.fromhex(record["master"]).split(b"\x00", 1)[1])
        public = json.loads(bytes.fromhex(master["pk"]).split(b"\x00", 1)[1])
        public["params"]["mass_bits"] = True
        public_raw = PREFIX + b"PK\x00" + canonical(public)
        master["pk"] = public_raw.hex()
        record["master"] = (PREFIX + b"MSK\x00" + canonical(master)).hex()
        record["context"] = digest(public_raw)
    else:
        row = record["entries"][0]
        key = json.loads(bytes.fromhex(row["key"]).split(b"\x00", 1)[1])
        public = json.loads(bytes.fromhex(key["pk"]).split(b"\x00", 1)[1])
        public["params"]["message_max_bytes"] -= 1
        key["pk"] = (PREFIX + b"PK\x00" + canonical(public)).hex()
        row["key"] = (PREFIX + b"SK\x00" + canonical(key)).hex()
    write_record(cached_issuer, record)
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError("private decoder must not run after public rejection")

    monkeypatch.setattr(MasterSecret, "from_bytes", forbidden)
    monkeypatch.setattr(SigningKey, "from_bytes", forbidden)
    for operation, args in (("public_key", ()), ("key_extract", (IDENTITY,))):
        with pytest.raises((IssuerPendingError, IssuerStateError)):
            getattr(cached_issuer, operation)(*args)
    assert calls == []


def test_foreign_public_key_in_cached_entry_is_rejected(cached_issuer, tmp_path):
    other = FixedIssuer(tmp_path / "other", Backend(rng=DeterministicRandom(b"wang-pw-service-other-root")))
    other.initialize(Params(), max_users=1)
    other_key = other.key_extract(IDENTITY)
    assert digest(other.public_key()) != digest(cached_issuer.public_key())
    record = read_record(cached_issuer)
    record["entries"][0]["key"] = other_key.to_bytes().hex()
    write_record(cached_issuer, record)
    with pytest.raises(IssuerStateError):
        cached_issuer.key_extract(IDENTITY)


def test_secret_decoder_errors_are_sanitized_and_not_logged(issuer, monkeypatch, capsys, caplog):
    sentinel = "injected-private-parser-value-never-log"

    def broken(*args, **kwargs):
        raise ValueError(sentinel)

    monkeypatch.setattr(MasterSecret, "from_bytes", broken)
    with pytest.raises(IssuerStateError) as error:
        issuer.public_key()
    assert sentinel not in str(error.value)
    output = capsys.readouterr()
    assert output.out == output.err == ""
    assert not caplog.records


def test_oversize_read_is_rejected_before_secret_decoder(issuer, monkeypatch):
    with state_path(issuer).open("r+b") as handle:
        handle.truncate(service.MAX_STATE_BYTES + 1)

    def forbidden(*args, **kwargs):
        pytest.fail("oversized state reached master decoder")

    monkeypatch.setattr(MasterSecret, "from_bytes", forbidden)
    with pytest.raises(IssuerStateError):
        issuer.public_key()
    with pytest.raises(IssuerStateError):
        issuer.key_extract(IDENTITY)
    assert not (issuer.path / service.PENDING_FILE).exists()


@pytest.mark.parametrize("name", [service.STATE_FILE, LOCK_FILE])
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "directory"])
def test_nonordinary_state_and_lock_paths_are_rejected(issuer, tmp_path, name, kind):
    external = tmp_path / "external"
    external.write_bytes(b"unrelated")
    target = issuer.path / name
    target.unlink(missing_ok=True)
    if kind == "symlink":
        target.symlink_to(external)
    elif kind == "hardlink":
        os.link(external, target)
    elif kind == "fifo":
        os.mkfifo(target)
    else:
        target.mkdir()
    with pytest.raises(IssuerStateError):
        issuer.public_key()
    with pytest.raises(IssuerStateError):
        issuer.key_extract(IDENTITY)
    assert external.read_bytes() == b"unrelated"


def test_symlink_root_and_dangling_marker_fail_closed(issuer, tmp_path):
    alias = tmp_path / "alias"
    alias.symlink_to(issuer.path, target_is_directory=True)
    with pytest.raises(IssuerStateError):
        FixedIssuer(alias).public_key()
    (issuer.path / service.PENDING_FILE).symlink_to(tmp_path / "absent")
    assert_blocked(issuer.path)


@pytest.mark.parametrize("kind", ["empty", "unknown", "directory"])
def test_any_marker_blocks_cached_reads_and_issuance(cached_issuer, kind):
    marker = cached_issuer.path / service.PENDING_FILE
    if kind == "directory":
        marker.mkdir()
    else:
        marker.write_bytes(b"" if kind == "empty" else b"unrecognized")
    assert_blocked(cached_issuer.path)


@pytest.mark.parametrize("operation", ["public_key", "key_extract"])
def test_same_thread_lock_reentry_fails_without_state_changes(issuer, operation):
    before = digest(state_path(issuer).read_bytes())
    with key_issuance_lock(issuer.path):
        with pytest.raises(StateBusyError):
            getattr(issuer, operation)(*({"public_key": (), "key_extract": (IDENTITY,)}[operation]))
    assert digest(state_path(issuer).read_bytes()) == before
    assert not (issuer.path / service.PENDING_FILE).exists()


def test_initialization_lock_reentry_rejects_before_setup_entropy(tmp_path):
    path = tmp_path / "empty-root"
    path.mkdir()
    zero = NoEntropy()
    with key_issuance_lock(path):
        with pytest.raises(StateBusyError):
            FixedIssuer(path, Backend(rng=zero)).initialize(Params())
    assert zero.calls == 0
    assert {entry.name for entry in path.iterdir()} == {LOCK_FILE}
