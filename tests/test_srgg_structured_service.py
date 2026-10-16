"""Real structured SRGG issuance, recovery, concurrency, and crash checks.

All private state lives under pytest's temporary directory. Small n=8 research
parameters test behavior only; failures are injected after a real root/key.
"""
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from time import monotonic, sleep

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

from ibme.core.errors import EncodingError
from ibme.core.randomness import DeterministicRandom
from ibme.ibs import srgg_service as storage
from ibme.ibs import srgg_structured_service as service
from ibme.ibs.srgg import structured as public_api
from experiments.research.gaussian_reference import SamplingAbort
from experiments.research.candidates.srgg import structured_backend as api
from experiments.research.candidates.srgg.formal_candidates import conditional_candidate
from experiments.research.candidates.srgg.structured_execution import ExecutionParams


class NoRead:
    def read(self, _size):
        raise AssertionError("cached/rejected issuance consumed entropy")


def _params():
    return ExecutionParams.from_candidate(conditional_candidate(degree=8, rank=1, digits=3))


def _canonical(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


@pytest.fixture(scope="module")
def issued(tmp_path_factory):
    root = tmp_path_factory.mktemp("srgg-structured-real")
    issuer = service.FixedIssuer(root/"issuer", api.Backend(rng=DeterministicRandom(b"structured-service-real")))
    public = issuer.initialize(_params(), max_users=3)
    key = issuer.key_extract(b"Alice")
    assert key.public_key == public
    return issuer, public, key


def _clone(issued, tmp_path, name="clone"):
    issuer = issued[0]
    path = tmp_path/name
    path.mkdir()
    shutil.copyfile(issuer.path/storage.STATE_FILE, path/storage.STATE_FILE)
    return service.FixedIssuer(path, api.Backend(rng=DeterministicRandom(b"structured-service-clone")))


def _read_master(path):
    outer = json.loads((path/storage.STATE_FILE).read_bytes())
    return outer, json.loads(bytes.fromhex(outer["master"]))


def _store_master(path, outer, master):
    outer["master"] = _canonical(master).hex()
    (path/storage.STATE_FILE).write_bytes(_canonical(outer))


def test_namespace_and_restart_reuse_fixed_key_without_entropy(issued):
    issuer, public, key = issued
    assert public_api.FixedIssuer is service.FixedIssuer
    assert public_api.IssuerStateError is service.IssuerStateError
    reopened = service.FixedIssuer(issuer.path, api.Backend(rng=NoRead()),
        expected_public=public, expected_params=public.params)
    assert reopened.public_key() == public
    assert reopened.key_extract(b"Alice").to_bytes() == key.to_bytes()
    restored = reopened.key_extract(b"Alice")
    backend = api.Backend(rng=DeterministicRandom(b"structured-service-after-restart"))
    signature = backend.sign(restored, b"after restart")
    assert backend.verify(public, b"Alice", b"after restart", signature) is True


def test_preflight_rejects_bad_capacity_before_entropy_or_filesystem(tmp_path):
    params = _params()
    assert 0 < service._preflight(params, 64) <= service.MAX_STATE_BYTES
    for count in (0, 65, True, 1.0):
        issuer = service.FixedIssuer(tmp_path/str(count), api.Backend(rng=NoRead()))
        with pytest.raises(ValueError):
            issuer.initialize(params, max_users=count)
        assert not issuer.path.exists()
    with pytest.raises(TypeError):
        service._preflight(None, 1)


def test_preflight_large_valid_shape_has_capacity_error_and_no_mutation(tmp_path):
    params = ExecutionParams.from_candidate(conditional_candidate(degree=512, rank=4, digits=8))
    issuer = service.FixedIssuer(tmp_path/"too-large", api.Backend(rng=NoRead()))
    with pytest.raises(service.IssuerCapacityError):
        issuer.initialize(params, max_users=64)
    assert not issuer.path.exists()


def test_preflight_exact_byte_boundary_and_existing_directory(tmp_path, monkeypatch):
    params = _params()
    bound = service._preflight(params, 1)
    monkeypatch.setattr(service, "MAX_STATE_BYTES", bound)
    assert service._preflight(params, 1) == bound
    monkeypatch.setattr(service, "MAX_STATE_BYTES", bound-1)
    issuer = service.FixedIssuer(tmp_path/"boundary", api.Backend(rng=NoRead()))
    with pytest.raises(service.IssuerCapacityError):
        issuer.initialize(params, max_users=1)
    assert not issuer.path.exists()


def test_invalid_identity_and_expected_parameters_reject_before_writes(tmp_path):
    issuer = service.FixedIssuer(tmp_path/"absent", api.Backend(rng=NoRead()))
    for identity in (b"", "Alice", b"x"*4097):
        with pytest.raises(EncodingError):
            issuer.key_extract(identity)
    assert not issuer.path.exists()
    changed = replace(_params(), sign_max_attempts=1)
    issuer = service.FixedIssuer(tmp_path/"mismatch", api.Backend(rng=NoRead()), expected_params=changed)
    with pytest.raises(service.IssuerStateError):
        issuer.initialize(_params(), max_users=1)
    assert not issuer.path.exists()


def test_wrong_public_and_parameters_block_reopen_without_replacement(issued, tmp_path):
    clone = _clone(issued, tmp_path)
    public = issued[1]
    alternative, _ = api.Backend(rng=DeterministicRandom(b"different-structured-root")).setup(_params())
    snapshot = (clone.path/storage.STATE_FILE).read_bytes()
    for options in ({"expected_public": alternative},
                    {"expected_params": replace(public.params, sign_max_attempts=1)}):
        reopened = service.FixedIssuer(clone.path, api.Backend(rng=NoRead()), **options)
        with pytest.raises(service.IssuerStateError):
            reopened.public_key()
        assert (clone.path/storage.STATE_FILE).read_bytes() == snapshot
        assert not (clone.path/storage.PENDING_FILE).exists()


def test_initialization_failures_and_existing_nonempty_directory_are_blocked(tmp_path):
    class FailedSetup:
        def setup(self, _params):
            raise RuntimeError("injected setup failure")
    path = tmp_path/"private"
    path.mkdir()
    issuer = service.FixedIssuer(path, FailedSetup())
    with pytest.raises(RuntimeError, match="injected setup"):
        issuer.initialize(_params(), max_users=1)
    assert (path/storage.PENDING_FILE).exists()
    with pytest.raises(service.IssuerPendingError):
        service.FixedIssuer(path, api.Backend(rng=NoRead())).initialize(_params(), max_users=1)
    other = tmp_path/"nonempty"
    other.mkdir()
    (other/"keep.txt").write_text("preserve", encoding="utf-8")
    with pytest.raises(FileExistsError):
        service.FixedIssuer(other, api.Backend(rng=NoRead())).initialize(_params(), max_users=1)
    assert (other/"keep.txt").read_text(encoding="utf-8") == "preserve"


def test_new_issuer_directory_is_private_on_posix(tmp_path):
    class FailedSetup:
        def setup(self, _params):
            raise RuntimeError("stop after directory")
    issuer = service.FixedIssuer(tmp_path/"private", FailedSetup())
    with pytest.raises(RuntimeError, match="stop after"):
        issuer.initialize(_params(), max_users=1)
    if os.name != "nt":
        assert stat.S_IMODE(issuer.path.stat().st_mode) == 0o700


@pytest.mark.parametrize("failure", [SamplingAbort("injected sampler abort"), RuntimeError("injected issuance failure")])
def test_failed_extraction_persists_tombstone_and_never_retries(issued, tmp_path, failure):
    clone = _clone(issued, tmp_path)
    calls = []
    class FailedBackend:
        def key_extract(self, _master, _identity):
            calls.append(1)
            raise failure
    clone.backend = FailedBackend()
    with pytest.raises(type(failure)):
        clone.key_extract(b"Bob")
    assert calls == [1]
    assert (clone.path/storage.PENDING_FILE).exists()
    outer, master = _read_master(clone.path)
    assert outer["status"] == "failed"
    assert [b"Bob".hex(), "failed", None] in master["entries"]
    blocked = service.FixedIssuer(clone.path, api.Backend(rng=NoRead()))
    with pytest.raises(service.IssuerPendingError):
        blocked.key_extract(b"Bob")
    (clone.path/storage.PENDING_FILE).unlink()
    with pytest.raises(service.IssuerPendingError):
        blocked.public_key()
    assert calls == [1]


@pytest.mark.parametrize("save_number", [1, 2])
def test_pending_and_final_write_failures_are_fail_closed(issued, tmp_path, monkeypatch, save_number):
    clone = _clone(issued, tmp_path)
    real_write = clone._atomic_write
    writes = []
    def fail_once(data):
        writes.append(1)
        if len(writes) == save_number:
            raise OSError("injected write failure")
        return real_write(data)
    monkeypatch.setattr(clone, "_atomic_write", fail_once)
    with pytest.raises(OSError, match="injected write"):
        clone.key_extract(b"Bob")
    assert (clone.path/storage.PENDING_FILE).exists()
    outer, master = _read_master(clone.path)
    assert outer["status"] == "failed"
    assert [b"Bob".hex(), "failed", None] in master["entries"]
    with pytest.raises(service.IssuerPendingError):
        service.FixedIssuer(clone.path, api.Backend(rng=NoRead())).key_extract(b"Bob")


def test_inconsistent_backend_key_is_blocked(issued, tmp_path):
    clone = _clone(issued, tmp_path)
    class WrongBackend:
        def key_extract(self, _master, _identity):
            return issued[2]
    clone.backend = WrongBackend()
    with pytest.raises(service.IssuerStateError):
        clone.key_extract(b"Bob")
    assert (clone.path/storage.PENDING_FILE).exists()


def test_failure_after_commit_marker_removal_reblocks_issuer(issued, tmp_path, monkeypatch):
    clone = _clone(issued, tmp_path)
    finish = clone._finish
    def fail_after_removal():
        finish()
        raise OSError("injected failure after marker removal")
    monkeypatch.setattr(clone, "_finish", fail_after_removal)
    with pytest.raises(OSError, match="after marker removal"):
        clone.key_extract(b"Bob")
    assert (clone.path/storage.PENDING_FILE).exists()
    outer, master = _read_master(clone.path)
    assert outer["status"] == "failed"
    assert [b"Bob".hex(), "failed", None] in master["entries"]
    with pytest.raises(service.IssuerPendingError):
        service.FixedIssuer(clone.path, api.Backend(rng=NoRead())).key_extract(b"Bob")


def test_inconsistent_setup_output_is_blocked_before_any_key_delivery(tmp_path):
    class WrongSetup:
        def setup(self, _params):
            return None, None
    issuer = service.FixedIssuer(tmp_path/"bad-setup", WrongSetup())
    with pytest.raises(service.IssuerStateError):
        issuer.initialize(_params(), max_users=1)
    assert (issuer.path/storage.PENDING_FILE).exists()
    assert not (issuer.path/storage.STATE_FILE).exists()


@pytest.mark.parametrize("change", ["truncated", "trailing", "unknown", "duplicate", "capacity", "witness", "cache-identity", "cache-duplicate"])
def test_corrupt_snapshots_are_rejected_without_replacement(issued, tmp_path, change):
    clone = _clone(issued, tmp_path)
    path = clone.path/storage.STATE_FILE
    raw = path.read_bytes()
    outer, master = _read_master(clone.path)
    if change == "truncated":
        raw = raw[:-1]
    elif change == "trailing":
        raw += b" "
    elif change == "unknown":
        raw = _canonical(dict(outer, unexpected=1))
    elif change == "duplicate":
        raw = b'{"schema":"x",'+raw[1:]
    elif change == "capacity":
        outer["max_users"] = True
        raw = _canonical(outer)
    else:
        if change == "witness":
            master["witness"][0][0][0] = 2
        elif change == "cache-identity":
            master["entries"][0][0] = ""
        elif change == "cache-duplicate":
            master["entries"].append(master["entries"][0])
        outer["master"] = _canonical(master).hex()
        raw = _canonical(outer)
    path.write_bytes(raw)
    with pytest.raises(service.IssuerStateError):
        service.FixedIssuer(clone.path, api.Backend(rng=NoRead())).public_key()
    assert path.read_bytes() == raw
    assert not (clone.path/storage.PENDING_FILE).exists()


def test_capacity_failure_preserves_committed_key_and_state(issued, tmp_path):
    clone = _clone(issued, tmp_path)
    outer, master = _read_master(clone.path)
    outer["max_users"] = 1
    _store_master(clone.path, outer, master)
    raw = (clone.path/storage.STATE_FILE).read_bytes()
    clone.backend = api.Backend(rng=NoRead())
    with pytest.raises(service.IssuerCapacityError):
        clone.key_extract(b"Bob")
    assert clone.key_extract(b"Alice").to_bytes() == issued[2].to_bytes()
    assert (clone.path/storage.STATE_FILE).read_bytes() == raw
    assert not (clone.path/storage.PENDING_FILE).exists()


def test_hard_process_exit_after_reservation_blocks_recovery(issued, tmp_path):
    clone = _clone(issued, tmp_path)
    code = "\n".join([
        "import os,sys",
        "from ibme.ibs.srgg_structured_service import FixedIssuer",
        "class Crash:",
        "    def key_extract(self,*args): os._exit(23)",
        "FixedIssuer(sys.argv[1],Crash()).key_extract(b'Crash')",
    ])
    child = subprocess.run([sys.executable, "-c", code, str(clone.path)],
        env=os.environ.copy(), capture_output=True, text=True, timeout=60)
    assert child.returncode == 23, child.stderr
    assert (clone.path/storage.PENDING_FILE).exists()
    outer, master = _read_master(clone.path)
    assert outer["status"] == "ready"
    assert [b"Crash".hex(), "pending", None] in master["entries"]
    with pytest.raises(service.IssuerPendingError):
        service.FixedIssuer(clone.path, api.Backend(rng=NoRead())).key_extract(b"Crash")
    (clone.path/storage.PENDING_FILE).unlink()
    with pytest.raises(service.IssuerPendingError):
        service.FixedIssuer(clone.path, api.Backend(rng=NoRead())).public_key()


def test_independent_process_restart_has_identical_key_digest(issued):
    issuer, _, key = issued
    code = "\n".join([
        "import hashlib,sys",
        "from ibme.ibs.srgg_structured_service import FixedIssuer",
        "class NoRead:",
        "    def read(self,n): raise AssertionError('unexpected entropy')",
        "from experiments.research.candidates.srgg.structured_backend import Backend",
        "key=FixedIssuer(sys.argv[1],Backend(rng=NoRead())).key_extract(b'Alice')",
        "print(hashlib.sha256(key.to_bytes()).hexdigest())",
    ])
    child = subprocess.run([sys.executable, "-c", code, str(issuer.path)],
        env=os.environ.copy(), capture_output=True, text=True, timeout=60)
    assert child.returncode == 0, child.stderr
    assert child.stdout.strip() == sha256(key.to_bytes()).hexdigest()


@pytest.mark.parametrize("identities", [("Bob", "Bob"), ("Bob", "Carol")])
def test_two_concurrent_processes_preserve_one_key_per_identity(issued, tmp_path, identities):
    clone = _clone(issued, tmp_path)
    barrier = tmp_path/"barrier"
    barrier.mkdir()
    code = "\n".join([
        "import hashlib,os,sys",
        "from pathlib import Path",
        "from time import monotonic,sleep",
        "from ibme.ibs.srgg_structured_service import FixedIssuer",
        "barrier=Path(sys.argv[3])",
        "(barrier/str(os.getpid())).write_text('ready')",
        "deadline=monotonic()+45",
        "while not (barrier/'go').exists():",
        "    if monotonic()>deadline: raise RuntimeError('start barrier timed out')",
        "    sleep(0.01)",
        "key=FixedIssuer(sys.argv[1]).key_extract(sys.argv[2].encode('ascii'))",
        "print(hashlib.sha256(key.to_bytes()).hexdigest())",
    ])
    processes = [subprocess.Popen([sys.executable, "-c", code, str(clone.path), identity, str(barrier)],
        env=os.environ.copy(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for identity in identities]
    try:
        deadline = monotonic()+45
        while not all((barrier/str(process.pid)).exists() for process in processes):
            assert all(process.poll() is None for process in processes), "worker failed before simultaneous start"
            assert monotonic() < deadline, "workers did not reach simultaneous start barrier"
            sleep(0.01)
        (barrier/"go").write_text("release", encoding="ascii")
        outputs = [process.communicate(timeout=90) for process in processes]
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)
    assert all(process.returncode == 0 for process in processes), outputs
    restarted = service.FixedIssuer(clone.path, api.Backend(rng=NoRead()))
    for identity, (stdout, _stderr) in zip(identities, outputs):
        key = restarted.key_extract(identity.encode("ascii"))
        assert stdout.strip() == sha256(key.to_bytes()).hexdigest()
    _, master = _read_master(clone.path)
    assert len(master["entries"]) == 1+len(set(identities))
    assert not (clone.path/storage.PENDING_FILE).exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX link boundary checked in prescribed WSL")
@pytest.mark.parametrize("target_kind", ["directory-symlink", "snapshot-symlink", "snapshot-hardlink"])
def test_nonordinary_state_paths_are_rejected(issued, tmp_path, target_kind):
    clone = _clone(issued, tmp_path)
    if target_kind == "directory-symlink":
        link = tmp_path/"linked-dir"
        link.symlink_to(clone.path, target_is_directory=True)
        reopened = service.FixedIssuer(link, api.Backend(rng=NoRead()))
    else:
        target = clone.path/storage.STATE_FILE
        original = tmp_path/"original-snapshot"
        target.replace(original)
        if target_kind == "snapshot-symlink":
            target.symlink_to(original)
        else:
            os.link(original, target)
        reopened = service.FixedIssuer(clone.path, api.Backend(rng=NoRead()))
    with pytest.raises(service.IssuerStateError):
        reopened.public_key()
