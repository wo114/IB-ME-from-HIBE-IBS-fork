"""Yu fixed-issuer storage, recovery, and fault checks.

Storage test structure adapted from tests/test_foo_li_service.py (46529e0),
without importing Foo--Li. Run with WSL ~/miniconda3/envs/sage. The default
byte profile uses n=1, q=3 and REAL AP09/RandBasis/LLL/GPV operations, hence
security_claim=none, backend_admitted=False, parameters_are_formal=False.
Identities/messages are one byte (empty messages also tested), not hashes.
A module-scoped real root and a single issued snapshot limit repeat setup.
Per-case isolated copies are TEST-ONLY fixture recovery, never production
rollback. Each parametrized case runs once; two-process concurrency succeeds,
six unsupported background threads are rejected before state/entropy changes.
Fault injection is not counted as a real successful primitive.
Private snapshots remain in pytest temporary directories, not evidence.
Yu signatures use fresh randomness; only identity KEYS stay fixed.
"""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

import pytest

import sage.all  # Required environment: absence is an error, never a passing skip.

from ibme.cli_state import LOCK_FILE, StateBusyError, key_issuance_lock
from ibme.core.errors import EncodingError, IBMEError, SerializationError
from ibme.core.randomness import DeterministicRandom
from ibme.ibs.yu import (
    YuIBS, YuParams, YuSamplingAbort, IssuancePending, MasterSecret,
)
from ibme.ibs.yu import codec, service
from ibme.ibs.yu.service import (
    FixedIssuer, IssuerPendingError, IssuerStateError, IssuerThreadError,
)


class NoEntropy:
    def __init__(self):
        self.calls = 0

    def read(self, size):
        self.calls += 1
        raise AssertionError("unexpected entropy consumption")


class CountingRandom:
    def __init__(self, seed=b"yu-service-user-v1", before_read=None):
        self.source = DeterministicRandom(seed)
        self.calls = []
        self.before_read = before_read

    def read(self, size):
        if self.before_read is not None:
            self.before_read()
        self.calls.append(size)
        return self.source.read(size)


def fingerprint(key):
    # Comparing digests prevents pytest assertion rewriting from printing keys.
    return hashlib.sha256(key.to_bytes()).hexdigest()


@pytest.fixture(scope="module")
def root_snapshot(tmp_path_factory):
    instance = FixedIssuer(tmp_path_factory.mktemp("yu-real-root") / "issuer",
                           YuIBS(rng=DeterministicRandom(b"yu-service-root-v1")))
    instance.initialize(YuParams())
    return (instance.path / service.STATE_FILE).read_bytes()


def restore_fixture(path, snapshot, rng=None):
    # Isolated recovery from a genuine private fixture, no mock algorithm.
    path.mkdir(mode=0o700)
    target = path / service.STATE_FILE
    with target.open("xb") as handle:
        handle.write(snapshot)
    target.chmod(0o600)
    return FixedIssuer(path, YuIBS(rng=NoEntropy() if rng is None else rng))


@pytest.fixture
def issuer(tmp_path, root_snapshot):
    return restore_fixture(tmp_path / "issuer", root_snapshot)


@pytest.fixture(scope="module")
def issued_snapshot(tmp_path_factory, root_snapshot):
    instance = restore_fixture(tmp_path_factory.mktemp("yu-issued") / "issuer",
                               root_snapshot, CountingRandom())
    key = instance.key_extract(b"A")
    return (state_path(instance).read_bytes(), fingerprint(key))


@pytest.fixture
def cached_issuer(tmp_path, issued_snapshot):
    return restore_fixture(tmp_path / "issuer", issued_snapshot[0])


def state_path(issuer):
    return issuer.path / service.STATE_FILE


def assert_blocked(path):
    rng = NoEntropy()
    recovered = FixedIssuer(path, YuIBS(rng=rng))
    assert (path / service.PENDING_FILE).is_file()
    for identity in (b"A", b"B"):
        with pytest.raises(IssuerPendingError, match="automatic retry"):
            recovered.key_extract(identity)
    with pytest.raises(IssuerPendingError):
        recovered.public_key()
    with pytest.raises(IssuerPendingError):
        recovered.initialize(YuParams())
    assert rng.calls == 0


_CHILD = r'''
import hashlib,json,os,sys,time
from ibme.core.randomness import DeterministicRandom
from ibme.ibs.yu import YuIBS
from ibme.ibs.yu.service import FixedIssuer

class Source:
    def __init__(self, mode):
        self.mode, self.calls = mode, []
        self.source = DeterministicRandom(b"yu-service-user-v1")
    def read(self, size):
        self.calls.append(size)
        if self.mode == "cached":
            raise AssertionError("cached recovery consumed entropy")
        value = self.source.read(size)
        if self.mode == "crash":
            os._exit(73)
        if len(self.calls) == 1:
            time.sleep(0.02)
        return value

source = Source(sys.argv[2])
issuer = FixedIssuer(sys.argv[1], YuIBS(rng=source))
key = issuer.key_extract(b"A")
signature = YuIBS(rng=DeterministicRandom(b"yu-child-sign-v1")).sign(key, b"M")
assert issuer.backend.verify(issuer.public_key(), b"A", b"M", signature)
print(json.dumps({"key_digest": hashlib.sha256(key.to_bytes()).hexdigest(),
                  "entropy_calls": source.calls}), flush=True)
'''


def child_args(path, mode):
    return [sys.executable, "-B", "-c", _CHILD, str(path), mode]


def child_env():
    root = Path(__file__).resolve().parents[1]
    return {**os.environ, "PYTHONPATH": os.pathsep.join((str(root / "src"), str(root))),
            "PYTHONDONTWRITEBYTECODE": "1"}


def run_child(path, mode):
    return subprocess.run(child_args(path, mode), env=child_env(),
                          capture_output=True, text=True, timeout=180)


def test_real_initialize_cache_zero_entropy_and_lifecycle(issuer):
    rng = CountingRandom()
    issuer.backend = YuIBS(rng=rng)
    public = issuer.public_key()
    key = issuer.key_extract(b"A")
    assert rng.calls
    before = hashlib.sha256(state_path(issuer).read_bytes()).digest()
    zero = NoEntropy()
    recovered = FixedIssuer(issuer.path, YuIBS(rng=zero))
    duplicate = recovered.key_extract(bytearray(b"A"))
    assert fingerprint(duplicate) == fingerprint(key)
    assert zero.calls == 0
    assert hashlib.sha256(state_path(issuer).read_bytes()).digest() == before
    message = b"M"
    signer = YuIBS(rng=DeterministicRandom(b"yu-service-sign-v1"))
    signature = signer.sign(duplicate, message)
    assert recovered.backend.verify(public, b"A", message, signature)
    # q=3 permits accidental wrong-identity verifier collisions. The storage
    # contract pins the key's identity; this configuration is not secure.
    assert duplicate.identity == b"A"
    assert not recovered.backend.verify(public, b"", message, signature)
    assert set(p.name for p in issuer.path.iterdir()) == {LOCK_FILE, service.STATE_FILE}
    if os.name == "posix":
        assert state_path(issuer).stat().st_mode & 0o077 == 0
        assert issuer.path.stat().st_mode & 0o077 == 0


def test_pending_snapshot_precedes_entropy_and_issued_precedes_return(issuer):
    observations = []

    def before_entropy():
        if observations:
            return
        assert (issuer.path / service.PENDING_FILE).read_bytes() == service._PENDING_CONTENT
        persisted = MasterSecret.from_bytes(state_path(issuer).read_bytes())
        zero = NoEntropy()
        with pytest.raises(IssuancePending):
            YuIBS(rng=zero).key_extract(persisted, b"A")
        assert zero.calls == 0
        observations.append("pending")

    issuer.backend = YuIBS(rng=CountingRandom(before_read=before_entropy))
    key = issuer.key_extract(b"A")
    persisted = MasterSecret.from_bytes(state_path(issuer).read_bytes())
    assert fingerprint(YuIBS(rng=NoEntropy()).key_extract(persisted, b"A")) == fingerprint(key)
    assert observations == ["pending"]
    assert not (issuer.path / service.PENDING_FILE).exists()


def test_fresh_process_recovers_cached_key_without_entropy(cached_issuer, issued_snapshot):
    issuer = cached_issuer
    result = run_child(issuer.path, "cached")
    assert result.returncode == 0, "fresh-process cached recovery failed"
    report = json.loads(result.stdout)
    assert report == {"key_digest": issued_snapshot[1], "entropy_calls": []}


def test_existing_service_reloads_after_another_process_issues(issuer):
    zero = NoEntropy()
    issuer.backend = YuIBS(rng=zero)
    issuer.public_key()  # A prior read must not become the next operation's state.
    result = run_child(issuer.path, "new")
    assert result.returncode == 0, "fresh-process issuance failed"
    report = json.loads(result.stdout)
    assert report["entropy_calls"]
    assert fingerprint(issuer.key_extract(b"A")) == report["key_digest"]
    assert zero.calls == 0


@pytest.mark.parametrize("operation", ["initialize", "public_key", "key_extract"])
def test_six_background_threads_rejected_without_state_or_entropy(issuer, operation):
    barrier = threading.Barrier(6)
    sources = [CountingRandom() for _ in range(6)]

    def work(index):
        peer = FixedIssuer(issuer.path, YuIBS(rng=sources[index]))
        barrier.wait(timeout=15)
        arguments = {"initialize": (YuParams(),), "public_key": (), "key_extract": (b"A",)}
        with pytest.raises(IssuerThreadError, match="main thread"):
            getattr(peer, operation)(*arguments[operation])

    before = hashlib.sha256(state_path(issuer).read_bytes()).digest()
    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(work, range(6)))
    assert hashlib.sha256(state_path(issuer).read_bytes()).digest() == before
    assert not (issuer.path / service.PENDING_FILE).exists()
    assert all(not rng.calls for rng in sources)


def test_two_processes_same_identity_issue_once(issuer):
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: run_child(issuer.path, "new"), range(2)))
    assert all(result.returncode == 0 for result in results), "process issuance failed"
    reports = [json.loads(result.stdout) for result in results]
    assert len({report["key_digest"] for report in reports}) == 1
    assert sum(bool(report["entropy_calls"]) for report in reports) == 1


@pytest.mark.parametrize("failure", [OSError, RuntimeError, KeyboardInterrupt])
def test_entropy_or_software_interrupt_keeps_failed_state_and_marker(issuer, failure):
    class Broken(CountingRandom):
        def read(self, size):
            super().read(size)
            raise failure("injected failure after entropy")

    rng = Broken()
    issuer.backend = YuIBS(rng=rng)
    with pytest.raises(failure, match="injected failure"):
        issuer.key_extract(b"A")
    assert len(rng.calls) == 1
    assert_blocked(issuer.path)
    persisted = MasterSecret.from_bytes(state_path(issuer).read_bytes())
    with pytest.raises(IssuancePending):
        YuIBS(rng=NoEntropy()).key_extract(persisted, b"A")


def test_backend_sampling_abort_keeps_marker(issuer, monkeypatch):
    from experiments.research.candidates.yu import standalone
    from experiments.research.gaussian_reference import SamplingAbort

    # Inject the finite sampler failure AFTER the real backend reservation;
    # the failed ledger and service marker must both survive, without retry.
    def abort(*args, **kwargs):
        raise SamplingAbort("injected sampling abort")
    monkeypatch.setattr(standalone, "keygen", abort)
    with pytest.raises(YuSamplingAbort):
        issuer.key_extract(b"A")
    assert_blocked(issuer.path)
    persisted = MasterSecret.from_bytes(state_path(issuer).read_bytes())
    zero = NoEntropy()
    with pytest.raises(IssuancePending):
        YuIBS(rng=zero).key_extract(persisted, b"A")
    assert zero.calls == 0


def test_process_hard_exit_keeps_durable_pending_and_releases_lock(issuer):
    result = run_child(issuer.path, "crash")
    assert result.returncode == 73
    with key_issuance_lock(issuer.path, timeout=0):
        pass
    assert_blocked(issuer.path)
    persisted = MasterSecret.from_bytes(state_path(issuer).read_bytes())
    with pytest.raises(IssuancePending):
        YuIBS(rng=NoEntropy()).key_extract(persisted, b"A")


@pytest.mark.parametrize("write_number", [1, 2])
@pytest.mark.parametrize("after_effect", [False, True])
def test_pending_or_issued_persistence_failure_blocks_retry(issuer, monkeypatch, write_number, after_effect):
    original = issuer._atomic_write
    calls = []

    def broken(raw):
        calls.append(1)
        if len(calls) == write_number:
            if after_effect:
                original(raw)
            raise OSError("injected uncertain persistence")
        original(raw)

    rng = CountingRandom()
    issuer.backend = YuIBS(rng=rng)
    monkeypatch.setattr(issuer, "_atomic_write", broken)
    with pytest.raises(OSError, match="uncertain persistence"):
        issuer.key_extract(b"A")
    assert bool(rng.calls) is (write_number != 1)
    assert_blocked(issuer.path)


def test_replace_reporting_failure_after_effect_still_blocks(issuer, monkeypatch):
    original = service.os.replace

    def broken(source, target):
        original(source, target)
        raise OSError("replace effect uncertain")

    rng = CountingRandom()
    issuer.backend = YuIBS(rng=rng)
    monkeypatch.setattr(service.os, "replace", broken)
    with pytest.raises(OSError, match="replace effect uncertain"):
        issuer.key_extract(b"A")
    assert rng.calls == []
    assert_blocked(issuer.path)


@pytest.mark.parametrize("operation", ["file_fsync", "directory_fsync"])
def test_reservation_fsync_failure_blocks_before_entropy(issuer, monkeypatch, operation):
    def broken(*args):
        raise OSError("injected fsync failure")

    if operation == "file_fsync":
        monkeypatch.setattr(service.os, "fsync", broken)
    else:
        monkeypatch.setattr(service, "_sync_directory", broken)
    rng = CountingRandom()
    issuer.backend = YuIBS(rng=rng)
    with pytest.raises(OSError, match="fsync failure"):
        issuer.key_extract(b"A")
    assert rng.calls == []
    assert_blocked(issuer.path)


@pytest.mark.parametrize("after_effect", [False, True])
def test_marker_unlink_failure_rearms_and_blocks(cached_issuer, monkeypatch, after_effect):
    issuer = cached_issuer
    original = Path.unlink
    fired = False

    def broken(path, *args, **kwargs):
        nonlocal fired
        if path == issuer.path / service.PENDING_FILE and not fired:
            fired = True
            if after_effect:
                original(path, *args, **kwargs)
            raise OSError("injected marker unlink failure")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", broken)
    issuer.backend = YuIBS(rng=CountingRandom())
    with pytest.raises(OSError, match="marker unlink failure"):
        issuer.key_extract(b"A")
    assert fired
    assert_blocked(issuer.path)


def test_directory_fsync_after_marker_unlink_rearms(cached_issuer, monkeypatch):
    issuer = cached_issuer
    original = service._sync_directory
    fired = False

    def broken(path):
        nonlocal fired
        if not (path / service.PENDING_FILE).exists() and not fired:
            fired = True
            raise OSError("injected completion fsync failure")
        original(path)

    monkeypatch.setattr(service, "_sync_directory", broken)
    issuer.backend = YuIBS(rng=CountingRandom())
    with pytest.raises(OSError, match="completion fsync failure"):
        issuer.key_extract(b"A")
    assert fired
    assert_blocked(issuer.path)


def test_interrupt_after_completion_before_return_rearms(cached_issuer, monkeypatch):
    issuer = cached_issuer
    original = issuer._finish

    def interrupted():
        original()
        raise KeyboardInterrupt("injected interrupt before key return")

    monkeypatch.setattr(issuer, "_finish", interrupted)
    issuer.backend = YuIBS(rng=CountingRandom())
    with pytest.raises(KeyboardInterrupt):
        issuer.key_extract(b"A")
    assert_blocked(issuer.path)


def test_repeat_initialize_does_not_overwrite_or_consume_entropy(issuer):
    before = hashlib.sha256(state_path(issuer).read_bytes()).digest()
    rng = NoEntropy()
    other = FixedIssuer(issuer.path, YuIBS(rng=rng))
    with pytest.raises(FileExistsError):
        other.initialize(YuParams())
    assert hashlib.sha256(state_path(issuer).read_bytes()).digest() == before
    assert rng.calls == 0
    assert not (issuer.path / service.PENDING_FILE).exists()


def test_concurrent_initializers_never_replace_the_winner(tmp_path):
    path = tmp_path / "issuer"
    script = r'''
import hashlib,json,sys
from ibme.core.randomness import DeterministicRandom
from ibme.ibs.yu import YuIBS, YuParams
from ibme.ibs.yu.service import FixedIssuer, IssuerPendingError
class Count:
    def __init__(self):
        self.source=DeterministicRandom(b"yu-service-root-v1")
        self.calls=0
    def read(self,n):
        self.calls+=1
        return self.source.read(n)
rng=Count()
instance=FixedIssuer(sys.argv[1],YuIBS(rng=rng))
try:
    public=instance.initialize(YuParams())
    outcome=hashlib.sha256(public.to_bytes()).hexdigest()
except (FileExistsError,IssuerPendingError):
    outcome=None
print(json.dumps({"public_digest":outcome,"entropy_calls":rng.calls}))
'''
    def work(_):
        return subprocess.run([sys.executable, "-B", "-c", script, str(path)],
                              env=child_env(), capture_output=True, text=True, timeout=180)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(work, range(2)))
    assert all(item.returncode == 0 for item in results), "concurrent setup failed"
    reports = [json.loads(item.stdout) for item in results]
    assert sum(item["public_digest"] is None for item in reports) == 1
    assert sum(bool(item["entropy_calls"]) for item in reports) == 1
    assert fingerprint(FixedIssuer(path).public_key()) in [item["public_digest"] for item in reports]


@pytest.mark.parametrize("after_effect", [False, True])
def test_failed_initial_state_publication_blocks_reinitialization(tmp_path, monkeypatch, after_effect):
    instance = FixedIssuer(tmp_path / "issuer", YuIBS(
        rng=DeterministicRandom(b"yu-service-root-v1")))
    original = instance._atomic_write

    def broken(raw):
        if after_effect:
            original(raw)
        raise OSError("injected initial publication failure")

    monkeypatch.setattr(instance, "_atomic_write", broken)
    with pytest.raises(OSError, match="publication failure"):
        instance.initialize(YuParams())
    assert state_path(instance).exists() is after_effect
    assert_blocked(instance.path)


def test_failed_initialization_cannot_be_retried(tmp_path):
    class Interrupted(YuIBS):
        def setup(self, params):
            raise KeyboardInterrupt("injected setup interruption")

    instance = FixedIssuer(tmp_path / "issuer", Interrupted(rng=NoEntropy()))
    with pytest.raises(KeyboardInterrupt):
        instance.initialize(YuParams())
    assert not state_path(instance).exists()
    assert_blocked(instance.path)


def test_wrong_paths_and_unrelated_contents_are_not_overwritten(tmp_path):
    rng = NoEntropy()
    backend = YuIBS(rng=rng)
    with pytest.raises(ValueError):
        FixedIssuer("", backend)
    with pytest.raises(ValueError):
        FixedIssuer(tmp_path.anchor, backend)
    file = tmp_path / "ordinary-file"
    file.write_bytes(b"unrelated")
    with pytest.raises(IssuerStateError):
        FixedIssuer(file, backend).initialize(YuParams())
    assert file.read_bytes() == b"unrelated"
    directory = tmp_path / "unrelated-directory"
    directory.mkdir()
    (directory / "keep").write_bytes(b"unrelated")
    with pytest.raises(FileExistsError):
        FixedIssuer(directory, backend).initialize(YuParams())
    assert {p.name for p in directory.iterdir()} == {"keep"}
    empty = tmp_path / "empty"
    empty.mkdir()
    for operation in ("public_key", "key_extract"):
        instance = FixedIssuer(empty, backend)
        with pytest.raises(IssuerStateError):
            getattr(instance, operation)(*(() if operation == "public_key" else (b"A",)))
    assert list(empty.iterdir()) == []
    missing = tmp_path / "missing-parent" / "issuer"
    with pytest.raises(FileNotFoundError):
        FixedIssuer(missing, backend).initialize(YuParams())
    assert not missing.parent.exists()
    assert rng.calls == 0


@pytest.mark.parametrize("identity", [b"", "A", b"AB"])
def test_invalid_identity_rejected_before_reservation(issuer, identity):
    issuer.backend = YuIBS(rng=NoEntropy())
    with pytest.raises(EncodingError):
        issuer.key_extract(identity)
    assert not (issuer.path / service.PENDING_FILE).exists()
    issuer.public_key()


def test_read_size_limit_precedes_secret_decoder(issuer, monkeypatch):
    # Sparse oversized input checks the actual codec budget, not an artificially
    # lowered test limit that could miss drift between reader and decoder caps.
    with state_path(issuer).open("r+b") as handle:
        handle.truncate(codec.MAX_OBJECT + 1)

    def must_not_decode(*args, **kwargs):
        pytest.fail("oversize state reached the secret decoder")

    monkeypatch.setattr(MasterSecret, "from_bytes", must_not_decode)
    with pytest.raises(IssuerStateError, match="size limit"):
        issuer.public_key()
    with pytest.raises(IssuerStateError, match="size limit"):
        issuer.key_extract(b"A")
    assert not (issuer.path / service.PENDING_FILE).exists()


@pytest.mark.parametrize("raw", [b"", b"invalid-state"])
def test_invalid_state_is_never_replaced_or_reinitialized(issuer, raw):
    state_path(issuer).write_bytes(raw)
    with pytest.raises(IssuerStateError):
        issuer.public_key()
    with pytest.raises(IssuerStateError):
        issuer.key_extract(b"A")
    with pytest.raises(FileExistsError):
        issuer.initialize(YuParams())
    assert state_path(issuer).read_bytes() == raw


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlinks/FIFOs tested in prescribed WSL")
@pytest.mark.parametrize("name", [service.STATE_FILE, LOCK_FILE])
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "directory"])
def test_nonordinary_state_or_lock_rejected_without_touching_target(issuer, tmp_path, name, kind):
    target = tmp_path / "external"
    target.write_bytes(b"unchanged")
    path = issuer.path / name
    path.unlink(missing_ok=True)
    if kind == "symlink":
        path.symlink_to(target)
    elif kind == "hardlink":
        os.link(target, path)
    elif kind == "fifo":
        os.mkfifo(path)
    else:
        path.mkdir()
    with pytest.raises(IssuerStateError):
        issuer.public_key()
    with pytest.raises(IssuerStateError):
        issuer.key_extract(b"A")
    assert target.read_bytes() == b"unchanged"


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlinks tested in prescribed WSL")
def test_symlink_root_and_dangling_pending_rejected(issuer, tmp_path):
    alias = tmp_path / "alias"
    alias.symlink_to(issuer.path, target_is_directory=True)
    with pytest.raises(IssuerStateError):
        FixedIssuer(alias).public_key()
    (issuer.path / service.PENDING_FILE).symlink_to(tmp_path / "absent")
    with pytest.raises(IssuerPendingError):
        issuer.key_extract(b"A")


def test_same_thread_reentry_uses_existing_lock_guard(issuer):
    with key_issuance_lock(issuer.path):
        with pytest.raises(StateBusyError, match="reentry"):
            issuer.key_extract(b"A")
    assert not (issuer.path / service.PENDING_FILE).exists()


def test_cache_hit_has_no_entropy_or_snapshot_rewrite(cached_issuer, issued_snapshot, monkeypatch):
    def must_not_write(*args):
        pytest.fail("cache hit rewrote the fixed master snapshot")

    monkeypatch.setattr(cached_issuer, "_atomic_write", must_not_write)
    key = cached_issuer.key_extract(b"A")
    assert fingerprint(key) == issued_snapshot[1]
    assert cached_issuer.backend.rng.calls == 0


def test_recovered_key_signatures_use_fresh_randomness_not_fixed_replay(cached_issuer):
    key = cached_issuer.key_extract(b"A")
    public = cached_issuer.public_key()
    before = hashlib.sha256(state_path(cached_issuer).read_bytes()).digest()
    rng = CountingRandom(b"yu-service-fresh-signatures")
    signer = YuIBS(rng=rng)
    for message in (b"", b"M", b"M"):
        count = len(rng.calls)
        signature = signer.sign(key, message)
        assert len(rng.calls) > count
        assert signer.verify(public, b"A", message, signature)
    # No equality/inequality assumption on signatures sampled in tiny domains.
    assert hashlib.sha256(state_path(cached_issuer).read_bytes()).digest() == before


@pytest.mark.parametrize("params", [None, {}, "debug", 1])
def test_bad_parameter_type_rejected_before_directory_creation(tmp_path, params):
    rng = NoEntropy()
    instance = FixedIssuer(tmp_path / "must-not-exist", YuIBS(rng=rng))
    with pytest.raises((TypeError, IBMEError)):
        instance.initialize(params)
    assert not instance.path.exists()
    assert rng.calls == 0


def test_public_preflight_failure_has_no_storage_or_entropy(tmp_path, monkeypatch):
    from ibme.ibs.yu import params

    def reject(*args):
        raise ValueError("injected parameter preflight failure")

    monkeypatch.setattr(params, "preflight", reject)
    rng = NoEntropy()
    instance = FixedIssuer(tmp_path / "must-not-exist", YuIBS(rng=rng))
    with pytest.raises(ValueError, match="preflight failure"):
        instance.initialize(YuParams())
    assert not instance.path.exists()
    assert rng.calls == 0


@pytest.mark.parametrize("raw", [b"", bytearray(b"state"), b"x" * (codec.MAX_OBJECT + 1)],
                         ids=["empty", "not-bytes", "oversize"])
def test_atomic_writer_rejects_bad_size_and_type_without_replacing(issuer, raw):
    before = hashlib.sha256(state_path(issuer).read_bytes()).digest()
    with pytest.raises(SerializationError):
        issuer._atomic_write(raw)
    assert hashlib.sha256(state_path(issuer).read_bytes()).digest() == before
    assert not list(issuer.path.glob(".yu-*.tmp"))


def test_malformed_state_error_is_serialization_error_without_private_text(issuer, monkeypatch):
    sentinel = "TEST-PRIVATE-SENTINEL-NOT-A-REAL-SECRET"

    def bad_decoder(*args):
        raise SerializationError(sentinel)

    monkeypatch.setattr(MasterSecret, "from_bytes", bad_decoder)
    with pytest.raises(SerializationError) as result:
        issuer.public_key()
    assert sentinel not in str(result.value)
    assert result.value.__suppress_context__


@pytest.mark.parametrize("kind", ["empty", "unknown", "directory"])
def test_any_pending_marker_blocks_even_cached_identity(cached_issuer, kind):
    marker = cached_issuer.path / service.PENDING_FILE
    if kind == "directory":
        marker.mkdir()
    else:
        marker.write_bytes(b"" if kind == "empty" else b"unknown-version")
    before = hashlib.sha256(state_path(cached_issuer).read_bytes()).digest()
    for operation in (cached_issuer.public_key, lambda: cached_issuer.key_extract(b"A")):
        with pytest.raises(IssuerPendingError):
            operation()
    assert hashlib.sha256(state_path(cached_issuer).read_bytes()).digest() == before
    assert cached_issuer.backend.rng.calls == 0


def test_callback_cannot_persist_a_different_master(issuer, root_snapshot, monkeypatch):
    def wrong_callback(master, identity):
        master.persist_callback(MasterSecret.from_bytes(root_snapshot))
        pytest.fail("foreign master callback was accepted")

    monkeypatch.setattr(issuer.backend, "key_extract", wrong_callback)
    with pytest.raises(IssuerStateError, match="unexpected master"):
        issuer.key_extract(b"A")
    assert_blocked(issuer.path)


def test_setup_completion_interrupt_rearms_pending(tmp_path, monkeypatch):
    instance = FixedIssuer(tmp_path / "issuer", YuIBS(
        rng=DeterministicRandom(b"yu-service-root-v1")))
    original = instance._finish

    def interrupted():
        original()
        raise KeyboardInterrupt("injected completed setup interruption")

    monkeypatch.setattr(instance, "_finish", interrupted)
    with pytest.raises(KeyboardInterrupt):
        instance.initialize(YuParams())
    assert state_path(instance).is_file()
    assert_blocked(instance.path)
