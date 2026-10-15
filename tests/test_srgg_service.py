"""Persistence, concurrency, and fail-closed recovery for SRGG issuance."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

import pytest

from ibme.core.errors import EncodingError
from ibme.core.randomness import DeterministicRandom
from ibme.ibs.srgg_service import (
    FixedIssuer,
    IssuerCapacityError,
    IssuerPendingError,
    IssuerStateError,
    STATE_FILE,
    _preflight,
)
from experiments.research.candidates.srgg.backend import Backend
from experiments.research.candidates.srgg.config import Config


class NoRead:
    def read(self, _size):
        raise AssertionError("cached SRGG extraction consumed entropy")


class FailingBackend:
    def key_extract(self, _master, _identity):
        raise RuntimeError("deliberate SRGG extraction failure")


class WrongKeyBackend:
    def __init__(self, key):
        self.key = key

    def key_extract(self, _master, _identity):
        return self.key


class SetupFailBackend:
    def setup(self, _params):
        raise AssertionError("setup reached after directory admission")


def _copy_snapshot(source: FixedIssuer, root: Path, name: str) -> FixedIssuer:
    target = root / name
    target.mkdir()
    shutil.copy2(source.path / STATE_FILE, target / STATE_FILE)
    return FixedIssuer(target)


def test_preflight_bounds_whole_ledger_before_entropy():
    assert _preflight(Config(), 16) < 2**21
    with pytest.raises(IssuerCapacityError):
        _preflight(Config(identity_max_bytes=4096, max_users=64), 64)
    with pytest.raises(TypeError):
        _preflight(None, 16)
    with pytest.raises(ValueError):
        _preflight(Config(), 65)
    with pytest.raises(ValueError):
        _preflight(Config(max_users=1), 2)


def test_invalid_identity_is_rejected_before_filesystem_or_entropy(tmp_path):
    backend = Backend(rng=NoRead())
    issuer = FixedIssuer(tmp_path / "uncreated", backend)
    with pytest.raises(EncodingError):
        issuer.key_extract(b"")
    assert not issuer.path.exists()


def test_initialize_reuses_an_existing_empty_directory(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    # No setup is reached because this Windows-level check runs before Sage.
    issuer = FixedIssuer(empty, SetupFailBackend())
    with pytest.raises(AssertionError):
        issuer.initialize(Config())
    assert empty.is_dir()


def test_new_issuer_directory_is_private_on_posix(tmp_path):
    target = tmp_path / "private"
    issuer = FixedIssuer(target, SetupFailBackend())
    with pytest.raises(AssertionError):
        issuer.initialize(Config())
    if os.name != "nt":
        assert stat.S_IMODE(target.stat().st_mode) == 0o700


@pytest.fixture(scope="module")
def issued_issuer(tmp_path_factory):
    pytest.importorskip("sage.all", reason="SRGG extraction requires the prescribed Sage runtime")
    parent = tmp_path_factory.mktemp("srgg-service")
    issuer = FixedIssuer(parent / "issuer", Backend(rng=DeterministicRandom(b"srgg-service-root")))
    public = issuer.initialize(Config(), max_users=3)
    key = issuer.key_extract(b"Alice")
    assert public.to_bytes() == key.public_key.to_bytes()
    return issuer, key


def test_restart_reuses_same_key_without_entropy(issued_issuer):
    issuer, key = issued_issuer
    restarted = FixedIssuer(issuer.path, Backend(rng=NoRead()))
    assert restarted.public_key().to_bytes() == key.public_key.to_bytes()
    assert restarted.key_extract(b"Alice").to_bytes() == key.to_bytes()


def test_restored_key_can_sign_and_verify(issued_issuer):
    issuer, key = issued_issuer
    restarted = FixedIssuer(issuer.path, Backend(rng=NoRead()))
    restored = restarted.key_extract(b"Alice")
    signer = Backend(rng=DeterministicRandom(b"srgg-service-sign"))
    signature = signer.sign(restored, b"after-restart")
    assert signer.verify(restored.public_key, b"Alice", b"after-restart", signature)


def test_failed_extraction_leaves_blocking_marker_and_tombstone(issued_issuer, tmp_path):
    issuer, _ = issued_issuer
    clone = _copy_snapshot(issuer, tmp_path, "failed")
    clone.backend = FailingBackend()
    with pytest.raises(RuntimeError, match="deliberate SRGG"):
        clone.key_extract(b"Bob")
    assert (clone.path / "master.bin.pending").exists()
    blocked = FixedIssuer(clone.path, Backend(rng=NoRead()))
    with pytest.raises(IssuerPendingError):
        blocked.public_key()
    raw = (clone.path / STATE_FILE).read_bytes()
    assert b'"status":"failed"' in raw


def test_final_save_failure_is_fail_closed(issued_issuer, tmp_path, monkeypatch):
    issuer, _ = issued_issuer
    clone = _copy_snapshot(issuer, tmp_path, "save-failure")
    real_write = clone._atomic_write
    calls = []

    def fail_after_pending(raw):
        calls.append(1)
        if len(calls) == 2:
            raise OSError("deliberate final save failure")
        return real_write(raw)

    monkeypatch.setattr(clone, "_atomic_write", fail_after_pending)
    with pytest.raises(OSError, match="deliberate final save"):
        clone.key_extract(b"Bob")
    assert (clone.path / "master.bin.pending").exists()
    with pytest.raises(IssuerPendingError):
        FixedIssuer(clone.path, Backend(rng=NoRead())).public_key()


def test_hard_exit_after_pending_reservation_blocks_recovery(issued_issuer, tmp_path):
    issuer, _ = issued_issuer
    clone = _copy_snapshot(issuer, tmp_path, "hard-exit")
    code = (
        "import os,sys; "
        "from ibme.ibs.srgg_service import FixedIssuer; "
        "from experiments.research.candidates.srgg.backend import Backend; "
        "b=Backend(); b.key_extract=lambda *_: os._exit(23); "
        "FixedIssuer(sys.argv[1], b).key_extract(b'Crash')"
    )
    child = subprocess.run([sys.executable, "-c", code, str(clone.path)],
                           env=os.environ.copy(), capture_output=True, text=True, timeout=60)
    assert child.returncode == 23
    assert (clone.path / "master.bin.pending").exists()
    raw = (clone.path / STATE_FILE).read_bytes()
    record = json.loads(raw.split(b"\0", 1)[1])
    crash_row = next(row for row in record["entries"] if bytes.fromhex(row["identity"]) == b"Crash")
    assert crash_row["status"] == "pending" and crash_row["key"] is None
    with pytest.raises(IssuerPendingError):
        FixedIssuer(clone.path, Backend(rng=NoRead())).public_key()


def test_inconsistent_key_output_is_blocked(issued_issuer, tmp_path):
    issuer, key = issued_issuer
    clone = _copy_snapshot(issuer, tmp_path, "wrong-key")
    clone.backend = WrongKeyBackend(key)
    with pytest.raises(IssuerStateError):
        clone.key_extract(b"Bob")
    assert (clone.path / "master.bin.pending").exists()


def test_corrupt_state_is_rejected_without_replacement(issued_issuer, tmp_path):
    issuer, _ = issued_issuer
    clone = _copy_snapshot(issuer, tmp_path, "corrupt")
    state = clone.path / STATE_FILE
    raw = state.read_bytes() + b"x"
    state.write_bytes(raw)
    with pytest.raises(IssuerStateError):
        FixedIssuer(clone.path, Backend(rng=NoRead())).public_key()
    assert state.read_bytes() == raw


def test_two_processes_same_identity_observe_one_persisted_key(issued_issuer, tmp_path):
    issuer, _ = issued_issuer
    code = (
        "import hashlib,sys; "
        "from ibme.ibs.srgg_service import FixedIssuer; "
        "from experiments.research.candidates.srgg.backend import Backend; "
        "key=FixedIssuer(sys.argv[1], Backend()).key_extract(b'Bob'); "
        "print(hashlib.sha256(key.to_bytes()).hexdigest())"
    )
    env = os.environ.copy()
    processes = [
        subprocess.Popen([sys.executable, "-c", code, str(issuer.path)],
                         env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(2)
    ]
    results = [process.communicate(timeout=180) for process in processes]
    assert all(process.returncode == 0 for process in processes), results
    digests = [stdout.strip() for _, (stdout, _stderr) in zip(processes, results)]
    assert len(set(digests)) == 1
    assert len(digests[0]) == 64
