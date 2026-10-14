"""Real q=3 Foo--Li storage checks; no security/ROM instantiation claim.

Run in WSL ~/miniconda3/envs/sage. Default FooLiParams is the existing finite
small_config regression (n=1, m_bar=1, q=3), with deterministic TEST-ONLY RNGs.
Alice/Bob identities are 5/3 bytes; lifecycle message is 15 bytes. Cases execute
once per parameter value; concurrency uses 6 threads and 2 fresh processes.
These are functional/fault tests, not security proofs or benchmarks. Secret
snapshots stay in pytest temporary directories, never in logs or repo evidence.
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

pytest.importorskip("sage.all", reason="Use prescribed WSL ~/miniconda3/envs/sage")

from ibme.cli_state import LOCK_FILE, StateBusyError, key_issuance_lock
from ibme.core.errors import EncodingError
from ibme.core.randomness import DeterministicRandom
from ibme.ibs.foo_li import (
    FooLiIBS, FooLiParams, FooLiSamplingAbort, IssuancePending, MasterSecret,
)
from ibme.ibs.foo_li import codec, service
from ibme.ibs.foo_li.service import FixedIssuer, IssuerPendingError, IssuerStateError


class NoEntropy:
    def __init__(self):
        self.calls = 0

    def read(self, size):
        self.calls += 1
        raise AssertionError("unexpected entropy consumption")


class CountingRandom:
    def __init__(self, seed=b"runtime-user-Alice", before_read=None):
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


@pytest.fixture
def issuer(tmp_path):
    instance = FixedIssuer(tmp_path / "issuer", FooLiIBS(
        epoch=b"test-epoch", rng=DeterministicRandom(b"runtime-master-0")))
    instance.initialize(FooLiParams())
    return instance


def state_path(issuer):
    return issuer.path / service.STATE_FILE


def assert_blocked(path):
    rng = NoEntropy()
    recovered = FixedIssuer(path, FooLiIBS(rng=rng))
    assert (path / service.PENDING_FILE).is_file()
    for identity in (b"Alice", b"Bob"):
        with pytest.raises(IssuerPendingError, match="automatic retry"):
            recovered.key_extract(identity)
    with pytest.raises(IssuerPendingError):
        recovered.public_key()
    with pytest.raises(IssuerPendingError):
        recovered.initialize(FooLiParams())
    assert rng.calls == 0


_CHILD = r'''
import hashlib,json,os,sys,time
from ibme.core.randomness import DeterministicRandom
from ibme.ibs.foo_li import FooLiIBS
from ibme.ibs.foo_li.service import FixedIssuer

class Source:
    def __init__(self, mode):
        self.mode, self.calls = mode, []
        self.source = DeterministicRandom(b"runtime-user-Alice")
    def read(self, size):
        self.calls.append(size)
        if self.mode == "cached":
            raise AssertionError("cached recovery consumed entropy")
        value = self.source.read(size)
        if self.mode == "crash":
            os._exit(73)
        time.sleep(0.1)
        return value

source = Source(sys.argv[2])
issuer = FixedIssuer(sys.argv[1], FooLiIBS(rng=source))
key = issuer.key_extract(b"Alice")
signature = issuer.backend.sign(key, b"service-message")
assert issuer.backend.verify(issuer.public_key(), b"Alice", b"service-message", signature)
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
                          capture_output=True, text=True, timeout=60)


def test_real_initialize_cache_zero_entropy_and_lifecycle(issuer):
    rng = CountingRandom()
    issuer.backend = FooLiIBS(rng=rng)
    public = issuer.public_key()
    key = issuer.key_extract(b"Alice")
    assert rng.calls == [32]
    before = hashlib.sha256(state_path(issuer).read_bytes()).digest()
    zero = NoEntropy()
    recovered = FixedIssuer(issuer.path, FooLiIBS(rng=zero))
    duplicate = recovered.key_extract(bytearray(b"Alice"))
    assert fingerprint(duplicate) == fingerprint(key)
    assert zero.calls == 0
    assert hashlib.sha256(state_path(issuer).read_bytes()).digest() == before
    message = b"service-message"
    signature = recovered.backend.sign(duplicate, message)
    assert recovered.backend.verify(public, b"Alice", message, signature)
    # q=3 permits accidental wrong-identity verifier collisions. The storage
    # contract pins the key's identity; this configuration is not secure.
    assert duplicate.identity == b"Alice"
    assert not recovered.backend.verify(public, b"", message, signature)
    assert set(p.name for p in issuer.path.iterdir()) == {LOCK_FILE, service.STATE_FILE}
    if os.name == "posix":
        assert state_path(issuer).stat().st_mode & 0o077 == 0
        assert issuer.path.stat().st_mode & 0o077 == 0


def test_pending_snapshot_precedes_entropy_and_issued_precedes_return(issuer):
    observations = []

    def before_entropy():
        assert (issuer.path / service.PENDING_FILE).read_bytes() == service._PENDING_CONTENT
        persisted = MasterSecret.from_bytes(state_path(issuer).read_bytes())
        zero = NoEntropy()
        with pytest.raises(IssuancePending):
            FooLiIBS(rng=zero).key_extract(persisted, b"Alice")
        assert zero.calls == 0
        observations.append("pending")

    issuer.backend = FooLiIBS(rng=CountingRandom(before_read=before_entropy))
    key = issuer.key_extract(b"Alice")
    persisted = MasterSecret.from_bytes(state_path(issuer).read_bytes())
    assert fingerprint(FooLiIBS(rng=NoEntropy()).key_extract(persisted, b"Alice")) == fingerprint(key)
    assert observations == ["pending"]
    assert not (issuer.path / service.PENDING_FILE).exists()


def test_fresh_process_recovers_cached_key_without_entropy(issuer):
    issuer.backend = FooLiIBS(rng=CountingRandom())
    key = issuer.key_extract(b"Alice")
    result = run_child(issuer.path, "cached")
    assert result.returncode == 0, "fresh-process cached recovery failed"
    report = json.loads(result.stdout)
    assert report == {"key_digest": fingerprint(key), "entropy_calls": []}


def test_existing_service_reloads_after_another_process_issues(issuer):
    zero = NoEntropy()
    issuer.backend = FooLiIBS(rng=zero)
    issuer.public_key()  # A prior read must not become the next operation's state.
    result = run_child(issuer.path, "new")
    assert result.returncode == 0, "fresh-process issuance failed"
    report = json.loads(result.stdout)
    assert report["entropy_calls"] == [32]
    assert fingerprint(issuer.key_extract(b"Alice")) == report["key_digest"]
    assert zero.calls == 0


def test_six_threads_same_identity_issue_once(issuer):
    barrier = threading.Barrier(6)
    sources = [CountingRandom() for _ in range(6)]

    def work(index):
        peer = FixedIssuer(issuer.path, FooLiIBS(rng=sources[index]))
        barrier.wait(timeout=15)
        return fingerprint(peer.key_extract(b"Alice"))

    with ThreadPoolExecutor(max_workers=6) as pool:
        keys = list(pool.map(work, range(6)))
    assert len(set(keys)) == 1
    assert sum(len(rng.calls) for rng in sources) == 1
    assert sum(sum(rng.calls) for rng in sources) == 32


def test_two_processes_same_identity_issue_once(issuer):
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: run_child(issuer.path, "new"), range(2)))
    assert all(result.returncode == 0 for result in results), "process issuance failed"
    reports = [json.loads(result.stdout) for result in results]
    assert len({report["key_digest"] for report in reports}) == 1
    assert sorted(report["entropy_calls"] for report in reports) == [[], [32]]


@pytest.mark.parametrize("failure", [OSError, RuntimeError, KeyboardInterrupt])
def test_entropy_or_software_interrupt_keeps_failed_state_and_marker(issuer, failure):
    class Broken(CountingRandom):
        def read(self, size):
            super().read(size)
            raise failure("injected failure after entropy")

    rng = Broken()
    issuer.backend = FooLiIBS(rng=rng)
    with pytest.raises(failure, match="injected failure"):
        issuer.key_extract(b"Alice")
    assert rng.calls == [32]
    assert_blocked(issuer.path)
    persisted = MasterSecret.from_bytes(state_path(issuer).read_bytes())
    with pytest.raises(IssuancePending):
        FooLiIBS(rng=NoEntropy()).key_extract(persisted, b"Alice")


def test_backend_sampling_abort_keeps_marker(issuer, monkeypatch):
    from experiments.research.foo_li_runtime_reference import Outcome, ResearchSession

    # Fault injection into a real restored master; no successful mock primitive.
    monkeypatch.setattr(ResearchSession, "extract", lambda *a, **k: Outcome("sampling_abort"))
    issuer.backend = FooLiIBS(rng=NoEntropy())
    with pytest.raises(FooLiSamplingAbort):
        issuer.key_extract(b"Alice")
    assert_blocked(issuer.path)


def test_process_hard_exit_keeps_durable_pending_and_releases_lock(issuer):
    result = run_child(issuer.path, "crash")
    assert result.returncode == 73
    with key_issuance_lock(issuer.path, timeout=0):
        pass
    assert_blocked(issuer.path)
    persisted = MasterSecret.from_bytes(state_path(issuer).read_bytes())
    with pytest.raises(IssuancePending):
        FooLiIBS(rng=NoEntropy()).key_extract(persisted, b"Alice")


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
    issuer.backend = FooLiIBS(rng=rng)
    monkeypatch.setattr(issuer, "_atomic_write", broken)
    with pytest.raises(OSError, match="uncertain persistence"):
        issuer.key_extract(b"Alice")
    assert rng.calls == ([] if write_number == 1 else [32])
    assert_blocked(issuer.path)


def test_replace_reporting_failure_after_effect_still_blocks(issuer, monkeypatch):
    original = service.os.replace

    def broken(source, target):
        original(source, target)
        raise OSError("replace effect uncertain")

    rng = CountingRandom()
    issuer.backend = FooLiIBS(rng=rng)
    monkeypatch.setattr(service.os, "replace", broken)
    with pytest.raises(OSError, match="replace effect uncertain"):
        issuer.key_extract(b"Alice")
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
    issuer.backend = FooLiIBS(rng=rng)
    with pytest.raises(OSError, match="fsync failure"):
        issuer.key_extract(b"Alice")
    assert rng.calls == []
    assert_blocked(issuer.path)


@pytest.mark.parametrize("after_effect", [False, True])
def test_marker_unlink_failure_rearms_and_blocks(issuer, monkeypatch, after_effect):
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
    issuer.backend = FooLiIBS(rng=CountingRandom())
    with pytest.raises(OSError, match="marker unlink failure"):
        issuer.key_extract(b"Alice")
    assert fired
    assert_blocked(issuer.path)


def test_directory_fsync_after_marker_unlink_rearms(issuer, monkeypatch):
    original = service._sync_directory
    fired = False

    def broken(path):
        nonlocal fired
        if not (path / service.PENDING_FILE).exists() and not fired:
            fired = True
            raise OSError("injected completion fsync failure")
        original(path)

    monkeypatch.setattr(service, "_sync_directory", broken)
    issuer.backend = FooLiIBS(rng=CountingRandom())
    with pytest.raises(OSError, match="completion fsync failure"):
        issuer.key_extract(b"Alice")
    assert fired
    assert_blocked(issuer.path)


def test_interrupt_after_completion_before_return_rearms(issuer, monkeypatch):
    original = issuer._finish

    def interrupted():
        original()
        raise KeyboardInterrupt("injected interrupt before key return")

    monkeypatch.setattr(issuer, "_finish", interrupted)
    issuer.backend = FooLiIBS(rng=CountingRandom())
    with pytest.raises(KeyboardInterrupt):
        issuer.key_extract(b"Alice")
    assert_blocked(issuer.path)


def test_repeat_initialize_does_not_overwrite_or_consume_entropy(issuer):
    before = hashlib.sha256(state_path(issuer).read_bytes()).digest()
    rng = NoEntropy()
    other = FixedIssuer(issuer.path, FooLiIBS(rng=rng))
    with pytest.raises(FileExistsError):
        other.initialize(FooLiParams())
    assert hashlib.sha256(state_path(issuer).read_bytes()).digest() == before
    assert rng.calls == 0
    assert not (issuer.path / service.PENDING_FILE).exists()


def test_concurrent_initializers_never_replace_the_winner(tmp_path):
    barrier = threading.Barrier(2)
    sources = [CountingRandom(b"runtime-master-0") for _ in range(2)]
    path = tmp_path / "issuer"

    def work(index):
        instance = FixedIssuer(path, FooLiIBS(rng=sources[index], epoch=b"test-epoch"))
        barrier.wait(timeout=15)
        try:
            return fingerprint(instance.initialize(FooLiParams()))
        except (FileExistsError, IssuerPendingError):
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(work, range(2)))
    assert results.count(None) == 1
    assert sum(bool(rng.calls) for rng in sources) == 1
    assert fingerprint(FixedIssuer(path).public_key()) in results


@pytest.mark.parametrize("after_effect", [False, True])
def test_failed_initial_state_publication_blocks_reinitialization(tmp_path, monkeypatch, after_effect):
    instance = FixedIssuer(tmp_path / "issuer", FooLiIBS(
        epoch=b"test-epoch", rng=DeterministicRandom(b"runtime-master-0")))
    original = instance._atomic_write

    def broken(raw):
        if after_effect:
            original(raw)
        raise OSError("injected initial publication failure")

    monkeypatch.setattr(instance, "_atomic_write", broken)
    with pytest.raises(OSError, match="publication failure"):
        instance.initialize(FooLiParams())
    assert state_path(instance).exists() is after_effect
    assert_blocked(instance.path)


def test_failed_initialization_cannot_be_retried(tmp_path):
    class Interrupted(FooLiIBS):
        def setup(self, params):
            raise KeyboardInterrupt("injected setup interruption")

    instance = FixedIssuer(tmp_path / "issuer", Interrupted(rng=NoEntropy()))
    with pytest.raises(KeyboardInterrupt):
        instance.initialize(FooLiParams())
    assert not state_path(instance).exists()
    assert_blocked(instance.path)


def test_wrong_paths_and_unrelated_contents_are_not_overwritten(tmp_path):
    rng = NoEntropy()
    backend = FooLiIBS(rng=rng)
    with pytest.raises(ValueError):
        FixedIssuer("", backend)
    with pytest.raises(ValueError):
        FixedIssuer(tmp_path.anchor, backend)
    file = tmp_path / "ordinary-file"
    file.write_bytes(b"unrelated")
    with pytest.raises(IssuerStateError):
        FixedIssuer(file, backend).initialize(FooLiParams())
    assert file.read_bytes() == b"unrelated"
    directory = tmp_path / "unrelated-directory"
    directory.mkdir()
    (directory / "keep").write_bytes(b"unrelated")
    with pytest.raises(FileExistsError):
        FixedIssuer(directory, backend).initialize(FooLiParams())
    assert {p.name for p in directory.iterdir()} == {"keep"}
    empty = tmp_path / "empty"
    empty.mkdir()
    for operation in ("public_key", "key_extract"):
        instance = FixedIssuer(empty, backend)
        with pytest.raises(IssuerStateError):
            getattr(instance, operation)(*(() if operation == "public_key" else (b"Alice",)))
    assert list(empty.iterdir()) == []
    missing = tmp_path / "missing-parent" / "issuer"
    with pytest.raises(FileNotFoundError):
        FixedIssuer(missing, backend).initialize(FooLiParams())
    assert not missing.parent.exists()
    assert rng.calls == 0


@pytest.mark.parametrize("identity", [b"", "Alice", b"a" * 257])
def test_invalid_identity_rejected_before_reservation(issuer, identity):
    issuer.backend = FooLiIBS(rng=NoEntropy())
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
        issuer.key_extract(b"Alice")
    assert not (issuer.path / service.PENDING_FILE).exists()


@pytest.mark.parametrize("raw", [b"", b"invalid-state"])
def test_invalid_state_is_never_replaced_or_reinitialized(issuer, raw):
    state_path(issuer).write_bytes(raw)
    with pytest.raises(IssuerStateError):
        issuer.public_key()
    with pytest.raises(IssuerStateError):
        issuer.key_extract(b"Alice")
    with pytest.raises(FileExistsError):
        issuer.initialize(FooLiParams())
    assert state_path(issuer).read_bytes() == raw


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlinks/FIFOs tested in prescribed WSL")
@pytest.mark.parametrize("name", [service.STATE_FILE, LOCK_FILE])
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "directory"])
def test_nonordinary_state_or_lock_rejected_without_touching_target(issuer, tmp_path, name, kind):
    target = tmp_path / "external"
    target.write_bytes(b"unchanged")
    path = issuer.path / name
    path.unlink()
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
        issuer.key_extract(b"Alice")
    assert target.read_bytes() == b"unchanged"


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlinks tested in prescribed WSL")
def test_symlink_root_and_dangling_pending_rejected(issuer, tmp_path):
    alias = tmp_path / "alias"
    alias.symlink_to(issuer.path, target_is_directory=True)
    with pytest.raises(IssuerStateError):
        FixedIssuer(alias).public_key()
    (issuer.path / service.PENDING_FILE).symlink_to(tmp_path / "absent")
    with pytest.raises(IssuerPendingError):
        issuer.key_extract(b"Alice")


def test_same_thread_reentry_uses_existing_lock_guard(issuer):
    with key_issuance_lock(issuer.path):
        with pytest.raises(StateBusyError, match="reentry"):
            issuer.key_extract(b"Alice")
    assert not (issuer.path / service.PENDING_FILE).exists()
