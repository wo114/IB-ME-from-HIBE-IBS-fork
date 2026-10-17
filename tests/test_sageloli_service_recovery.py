"""Independent-process and fault recovery for real Sageloli issuers.

Only teaching profiles are exercised.  Successful lifecycle, locking, and
failure checks establish implementation behavior, not SIS/RSIS security.
Child processes return only booleans and digests; secret objects never enter
their output.  A single real issued snapshot per route limits sampler work.
"""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from ibme.core.errors import SerializationError
from ibme.core.randomness import DeterministicRandom
from experiments.research.candidates.sageloli import (
    FixedIssuer, IssuerPendingError, IssuerStateError,
    SISBackend, SISParams, RSISBackend, RSISParams,
)
from experiments.research.candidates.sageloli import codec
from experiments.research.candidates.sageloli import service as service_module
from experiments.research.candidates.sageloli.objects import MasterSecret
from experiments.research.candidates.sageloli.service import PENDING_FILE, STATE_FILE


_ROOT = Path(__file__).resolve().parents[1]
_CHILD_TIMEOUT = 240
_CRASH_EXIT = 73
_ROUTES = [("sis", SISParams, SISBackend), ("rsis", RSISParams, RSISBackend)]


class NoEntropy:
    def __init__(self):
        self.calls = 0

    def read(self, _size):
        self.calls += 1
        raise AssertionError("cached recovery consumed fresh entropy")


def _digest(raw):
    return sha256(raw).hexdigest()


@pytest.fixture(scope="module", params=_ROUTES, ids=["sis", "rsis"])
def issued_snapshot(request, tmp_path_factory):
    route, params_type, backend_type = request.param
    params = params_type()
    backend = backend_type(rng=DeterministicRandom(f"{route}-process-fixture".encode()))
    directory = tmp_path_factory.mktemp(f"{route}-issued")
    issuer = FixedIssuer(directory, backend)
    public = issuer.initialize(params)
    key = issuer.key_extract(b"alice")
    signature = issuer.sign(key, b"recovery-contract")
    assert issuer.verify(public, b"alice", b"recovery-contract", signature) is True
    return {
        "route": route, "params": params, "backend_type": backend_type,
        "raw": (directory / STATE_FILE).read_bytes(), "public": public,
        "key": key, "signature": signature,
        "key_digest": _digest(key.to_bytes()),
    }


@pytest.fixture
def issuer_path(issued_snapshot, tmp_path):
    path = tmp_path / "issuer"
    path.mkdir(mode=0o700)
    (path / STATE_FILE).write_bytes(issued_snapshot["raw"])
    return path


def _environment():
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join((str(_ROOT / "src"), str(_ROOT)))
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


# This standalone worker imports the implementation from disk: it inherits
# neither a Python object nor an in-memory identity cache from the test process.
_WORKER = r'''
from hashlib import sha256
import json, os, sys, time
from pathlib import Path
from ibme.core.randomness import DeterministicRandom
from experiments.research.candidates.sageloli import (
    FixedIssuer, SISBackend, RSISBackend,
)

action, route, directory, label = sys.argv[1:]
directory = Path(directory)
base = SISBackend if route == "sis" else RSISBackend

class NoEntropy:
    def read(self, size):
        raise AssertionError("cached recovery consumed fresh entropy")

class ObservedBackend(base):
    def key_extract(self, master, identity):
        with (directory / "sampler.calls").open("ab") as handle:
            handle.write(b"entered\n")
            handle.flush()
            os.fsync(handle.fileno())
        key = super().key_extract(master, identity)
        if action == "crash":
            os._exit(73)
        return key

def digest(raw):
    return sha256(raw).hexdigest()

if action == "recover":
    # First prove restore/extract itself needs no entropy, then provide fresh
    # test randomness solely for the post-restart signature.
    cached = FixedIssuer(directory, base(rng=NoEntropy()))
    public = cached.public_key()
    key = cached.key_extract(b"alice")
    signer = base(rng=DeterministicRandom((route + "-restarted-sign").encode()))
    signature = signer.sign(key, b"restarted-message")
    loaded = signer.load_signature(public, signature.to_bytes())
    print(json.dumps({"public_digest": digest(public.to_bytes()),
        "key_digest": digest(key.to_bytes()),
        "verified": signer.verify(public, b"alice", b"restarted-message", loaded),
        "wrong_identity": signer.verify(public, b"mallory", b"restarted-message", loaded)}))
elif action in ("race", "crash"):
    if action == "race":
        (directory / ("ready-" + label)).touch()
        deadline = time.monotonic() + 60
        while not (directory / "start-gate").exists():
            if time.monotonic() > deadline:
                raise RuntimeError("test start gate timed out")
            time.sleep(0.01)
    issuer = FixedIssuer(directory, ObservedBackend(
        rng=DeterministicRandom((route + "-" + action + "-" + label).encode())))
    key = issuer.key_extract(b"bob")
    print(json.dumps({"key_digest": digest(key.to_bytes())}))
else:
    raise RuntimeError("unknown child action")
'''


def _child(action, snapshot, path, label="single"):
    return subprocess.run(
        [sys.executable, "-c", _WORKER, action, snapshot["route"], str(path), label],
        cwd=_ROOT, env=_environment(), capture_output=True, text=True,
        timeout=_CHILD_TIMEOUT, check=False,
    )


def _safe_result(completed):
    # The worker deliberately emits no secret coefficients.  On errors, avoid
    # propagating arbitrary backend tracebacks or object representations.
    assert completed.returncode == 0, "Sageloli child process failed"
    result = json.loads(completed.stdout)
    assert isinstance(result, dict)
    return result


def _assert_blocked(path, snapshot):
    before = _digest((path / STATE_FILE).read_bytes())
    entropy = NoEntropy()
    issuer = FixedIssuer(path, snapshot["backend_type"](rng=entropy))
    with pytest.raises(IssuerPendingError):
        issuer.public_key()
    for identity in (b"alice", b"bob", b"unseen"):
        with pytest.raises(IssuerPendingError):
            issuer.key_extract(identity)
    assert entropy.calls == 0
    assert _digest((path / STATE_FILE).read_bytes()) == before
    assert (path / PENDING_FILE).is_file()


def test_independent_process_restart_signs_with_same_issued_key(issued_snapshot, issuer_path):
    before = _digest((issuer_path / STATE_FILE).read_bytes())
    result = _safe_result(_child("recover", issued_snapshot, issuer_path))
    assert result["public_digest"] == _digest(issued_snapshot["public"].to_bytes())
    assert result["key_digest"] == issued_snapshot["key_digest"]
    assert result["verified"] is True
    assert result["wrong_identity"] is False
    assert _digest((issuer_path / STATE_FILE).read_bytes()) == before
    assert not (issuer_path / PENDING_FILE).exists()


def test_two_processes_issue_one_fixed_key_for_new_identity(issued_snapshot, issuer_path):
    workers = []
    try:
        for label in ("one", "two"):
            workers.append(subprocess.Popen(
                [sys.executable, "-c", _WORKER, "race", issued_snapshot["route"],
                 str(issuer_path), label],
                cwd=_ROOT, env=_environment(), stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True,
            ))
        deadline = time.monotonic() + 60
        while not all((issuer_path / f"ready-{label}").exists() for label in ("one", "two")):
            assert time.monotonic() < deadline, "child startup timed out"
            assert all(process.poll() is None for process in workers), "child exited before gate"
            time.sleep(0.01)
        (issuer_path / "start-gate").touch()
        results = []
        for process in workers:
            stdout, _stderr = process.communicate(timeout=_CHILD_TIMEOUT)
            assert process.returncode == 0, "concurrent issuer process failed"
            results.append(json.loads(stdout))
    finally:
        for process in workers:
            if process.poll() is None:
                process.kill()
            process.communicate()
    assert results[0]["key_digest"] == results[1]["key_digest"]
    assert (issuer_path / "sampler.calls").read_text().splitlines() == ["entered"]
    entropy = NoEntropy()
    restarted = FixedIssuer(issuer_path, issued_snapshot["backend_type"](rng=entropy))
    key = restarted.key_extract(b"bob")
    assert _digest(key.to_bytes()) == results[0]["key_digest"]
    assert entropy.calls == 0
    master = MasterSecret.from_bytes((issuer_path / STATE_FILE).read_bytes())
    assert len(master.states) == 2
    assert all(status == "issued" for status, _key in master.states.values())
    assert not (issuer_path / PENDING_FILE).exists()


def test_hard_exit_after_real_sampling_leaves_durable_pending(issued_snapshot, issuer_path):
    completed = _child("crash", issued_snapshot, issuer_path)
    assert completed.returncode == _CRASH_EXIT, "crash hook did not execute"
    assert completed.stdout == ""
    assert (issuer_path / "sampler.calls").read_text().splitlines() == ["entered"]
    master = MasterSecret.from_bytes((issuer_path / STATE_FILE).read_bytes())
    assert master.states[b"bob"][0] == "pending"
    assert master.states[b"bob"][1] is None
    _assert_blocked(issuer_path, issued_snapshot)


@pytest.mark.parametrize("stage", ["reservation-save", "issued-save", "finish"])
def test_persistence_failure_blocks_without_silent_reissue(
        issued_snapshot, issuer_path, monkeypatch, stage):
    backend_type = issued_snapshot["backend_type"]
    calls = []

    class ObservedBackend(backend_type):
        def key_extract(self, master, identity):
            calls.append(True)
            return super().key_extract(master, identity)

    issuer = FixedIssuer(issuer_path, ObservedBackend(
        rng=DeterministicRandom(f"{issued_snapshot['route']}-{stage}".encode())))
    original_replace = service_module.os.replace
    writes = []

    def fail_save(source, target):
        if Path(target) == issuer_path / STATE_FILE:
            writes.append(True)
            if stage == "reservation-save" or len(writes) >= 2:
                raise OSError("injected state publication failure")
        return original_replace(source, target)

    original_sync = service_module._sync_directory

    def fail_completion_sync(directory):
        # Exercise the real _finish path after unlink has succeeded.  It must
        # re-arm the marker when the completion directory-fsync fails.
        if not (directory / PENDING_FILE).exists():
            raise OSError("injected completion directory-sync failure")
        return original_sync(directory)

    if stage == "finish":
        monkeypatch.setattr(service_module, "_sync_directory", fail_completion_sync)
    else:
        monkeypatch.setattr(service_module.os, "replace", fail_save)
    with pytest.raises(OSError, match="injected"):
        issuer.key_extract(b"bob")
    assert len(calls) == (0 if stage == "reservation-save" else 1)
    assert not list(issuer_path.glob(".sageloli-*.tmp"))
    master = MasterSecret.from_bytes((issuer_path / STATE_FILE).read_bytes())
    if stage == "reservation-save":
        assert b"bob" not in master.states
        assert _digest((issuer_path / STATE_FILE).read_bytes()) == _digest(issued_snapshot["raw"])
    else:
        assert master.states[b"bob"][0] == ("pending" if stage == "issued-save" else "failed")
        assert master.states[b"bob"][1] is None
    _assert_blocked(issuer_path, issued_snapshot)


@pytest.mark.parametrize("pin", ["public", "params"])
def test_wrong_expected_context_rejects_without_entropy_or_state_change(
        issued_snapshot, issuer_path, pin):
    params = issued_snapshot["params"]
    alternate = replace(params, identity_max_bytes=params.identity_max_bytes + 1)
    kwargs = {"expected_params": alternate}
    if pin == "public":
        other_public, _ = issued_snapshot["backend_type"](
            rng=DeterministicRandom(f"{issued_snapshot['route']}-other-context".encode())
        ).setup(params)
        kwargs = {"expected_public": other_public}
    before = _digest((issuer_path / STATE_FILE).read_bytes())
    entropy = NoEntropy()
    with pytest.raises(IssuerStateError):
        issuer = FixedIssuer(issuer_path, issued_snapshot["backend_type"](rng=entropy), **kwargs)
        issuer.public_key()
    assert entropy.calls == 0
    assert _digest((issuer_path / STATE_FILE).read_bytes()) == before
    assert not (issuer_path / PENDING_FILE).exists()


def test_correct_expected_context_recovers_same_key(issued_snapshot, issuer_path):
    entropy = NoEntropy()
    issuer = FixedIssuer(
        issuer_path, issued_snapshot["backend_type"](rng=entropy),
        expected_public=issued_snapshot["public"], expected_params=issued_snapshot["params"],
    )
    assert _digest(issuer.key_extract(b"alice").to_bytes()) == issued_snapshot["key_digest"]
    assert entropy.calls == 0


@pytest.mark.parametrize("damage", ["empty", "truncated", "appended", "duplicated-field", "duplicated-identity"])
def test_damaged_snapshot_is_preserved_and_never_resampled(issued_snapshot, issuer_path, damage):
    raw = issued_snapshot["raw"]
    kind = b"SIS-MSK" if issued_snapshot["route"] == "sis" else b"RSIS-MSK"
    fields = codec.decode(raw, kind, 3)
    if damage == "empty":
        damaged = b""
    elif damage == "truncated":
        damaged = raw[:-1]
    elif damage == "appended":
        damaged = raw + b"\x00"
    elif damage == "duplicated-field":
        damaged = codec.encode(kind, *fields, fields[-1])
    else:
        count, position = codec.read_u32(fields[2])
        assert count == 1
        record = fields[2][position:]
        damaged = codec.encode(kind, fields[0], fields[1], codec.u32(2) + record + record)
    (issuer_path / STATE_FILE).write_bytes(damaged)
    before = _digest(damaged)
    entropy = NoEntropy()
    issuer = FixedIssuer(issuer_path, issued_snapshot["backend_type"](rng=entropy))
    with pytest.raises(IssuerStateError):
        issuer.public_key()
    with pytest.raises(IssuerStateError):
        issuer.key_extract(b"alice")
    assert entropy.calls == 0
    assert _digest((issuer_path / STATE_FILE).read_bytes()) == before
    assert not (issuer_path / PENDING_FILE).exists()


@pytest.mark.parametrize("object_name", ["public", "master", "key", "signature"])
def test_object_decoders_reject_duplicate_fields(issued_snapshot, object_name):
    route = issued_snapshot["route"].upper().encode()
    if object_name == "master":
        obj = MasterSecret.from_bytes(issued_snapshot["raw"])
        kind, count = route + b"-MSK", 3
        parser = MasterSecret.from_bytes
    elif object_name == "signature":
        obj = issued_snapshot["signature"]
        kind, count = b"SIG", 4
        backend = issued_snapshot["backend_type"](rng=NoEntropy())
        parser = lambda raw: backend.load_signature(issued_snapshot["public"], raw)
    else:
        obj = issued_snapshot[object_name]
        kind, count = route + (b"-PK" if object_name == "public" else b"-SK"), (2 if object_name == "public" else 4)
        parser = type(obj).from_bytes
    fields = codec.decode(obj.to_bytes(), kind, count)
    duplicated = codec.encode(kind, *fields, fields[-1])
    with pytest.raises(SerializationError):
        parser(duplicated)
