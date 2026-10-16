"""Real Table 4 PARAM-I issuance plus explicit storage-failure injections.

No toy parameters or mock signatures are used. Faults are injected only after
a real root/key. Private state stays under pytest's temporary directory.
"""
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from threading import Timer
from time import monotonic, sleep

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

from ibme.core.randomness import DeterministicRandom
from ibme.ibs import srgg_service as storage
from ibme.ibs import srgg_paper_service as service
from experiments.research.candidates.srgg import paper_backend as api
from experiments.research.candidates.srgg.paper_parameters import PaperParams


class NoRead:
    def read(self, _count):
        raise AssertionError("cached/rejected request consumed entropy")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


@pytest.fixture(scope="module")
def issued(tmp_path_factory):
    path = tmp_path_factory.mktemp("srgg-paper-real")/"issuer"
    backend = api.Backend(rng=DeterministicRandom(b"paper-service-real-PARAM-I"))
    issuer = service.FixedIssuer(path, backend)
    public = issuer.initialize(PaperParams("PARAM-I"), max_users=3)
    key = issuer.key_extract(b"Alice")
    return issuer, public, key


def _clone(issued, tmp_path):
    path = tmp_path/"clone"
    path.mkdir()
    shutil.copyfile(issued[0].path/storage.STATE_FILE, path/storage.STATE_FILE)
    return service.FixedIssuer(path, api.Backend(rng=NoRead()))


def _records(path):
    outer = json.loads((path/storage.STATE_FILE).read_bytes())
    return outer, json.loads(bytes.fromhex(outer["master"]))


def test_three_literal_profile_capacity_bounds_are_entropy_free(tmp_path):
    for name in ("PARAM-I", "PARAM-II", "PARAM-III"):
        bound = service._preflight(PaperParams(name), 1)
        assert 0 < bound <= service.MAX_STATE_BYTES
    for count in (0, 65, True, 1.0):
        issuer = service.FixedIssuer(tmp_path/str(count), api.Backend(rng=NoRead()))
        with pytest.raises(ValueError):
            issuer.initialize(PaperParams(), max_users=count)
        assert not issuer.path.exists()
    with pytest.raises(TypeError):
        service._preflight(None, 1)
    issuer = service.FixedIssuer(tmp_path/"oversize", api.Backend(rng=NoRead()))
    with pytest.raises(service.IssuerCapacityError):
        issuer.initialize(PaperParams("PARAM-III"), max_users=64)
    assert not issuer.path.exists()


def test_capacity_boundary_and_existing_files_are_preserved(tmp_path, monkeypatch):
    bound = service._preflight(PaperParams(), 1)
    monkeypatch.setattr(service, "MAX_STATE_BYTES", bound)
    assert service._preflight(PaperParams(), 1) == bound
    monkeypatch.setattr(service, "MAX_STATE_BYTES", bound-1)
    path = tmp_path/"boundary"
    with pytest.raises(service.IssuerCapacityError):
        service.FixedIssuer(path, api.Backend(rng=NoRead())).initialize(PaperParams())
    assert not path.exists()
    monkeypatch.undo()
    path.mkdir()
    (path/"keep.txt").write_text("preserve", encoding="ascii")
    with pytest.raises(FileExistsError):
        service.FixedIssuer(path, api.Backend(rng=NoRead())).initialize(PaperParams())
    assert (path/"keep.txt").read_text() == "preserve"


@pytest.mark.parametrize("budget", [True, -1, 3601, float("nan"), float("inf"), "300"])
def test_invalid_lock_budgets_do_not_mutate_or_use_entropy(tmp_path, budget):
    path = tmp_path/"invalid-lock"
    with pytest.raises(ValueError):
        service.FixedIssuer(path, api.Backend(rng=NoRead()), lock_timeout=budget)
    assert not path.exists()


def test_lock_reentry_and_body_errors_are_never_retried(tmp_path):
    issuer = service.FixedIssuer(tmp_path, api.Backend(rng=NoRead()), lock_timeout=300)
    with issuer._locked():
        with pytest.raises(service.StateBusyError) as caught:
            with issuer._locked():
                pytest.fail("writer reentry was accepted")
        assert caught.value.__cause__ is None
    error = service.StateBusyError("injected body failure")
    calls = []
    with pytest.raises(service.StateBusyError) as caught:
        with issuer._locked():
            calls.append(1)
            raise error
    assert caught.value is error
    assert calls == [1]
    assert not (tmp_path/storage.PENDING_FILE).exists()


def test_os_lock_timeout_and_acquisition_retries_do_not_use_entropy(tmp_path, monkeypatch):
    ready, release = tmp_path/"ready", tmp_path/"release"
    code = "\n".join([
        "import sys,time",
        "from pathlib import Path",
        "from ibme.cli_state import key_issuance_lock",
        "root=Path(sys.argv[1])",
        "with key_issuance_lock(root):",
        "    (root/'ready').write_text('locked')",
        "    deadline=time.monotonic()+20",
        "    while not (root/'release').exists():",
        "        if time.monotonic()>deadline: raise RuntimeError('release timeout')",
        "        time.sleep(0.01)",
    ])
    child = subprocess.Popen([sys.executable, "-c", code, str(tmp_path)],
        env=os.environ.copy(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = monotonic()+15
        while not ready.exists():
            assert child.poll() is None
            assert monotonic() < deadline
            sleep(0.01)
        issuer = service.FixedIssuer(tmp_path, api.Backend(rng=NoRead()), lock_timeout=0.03)
        with pytest.raises(service.StateBusyError) as caught:
            with issuer._locked():
                pytest.fail("second process acquired a held lock")
        assert isinstance(caught.value.__cause__, OSError)
        assert not (tmp_path/storage.PENDING_FILE).exists()
        # Fault injection shortens each audited OS acquisition slice so the
        # extended waiting path is exercised without a 30-second test delay.
        original, attempts = storage.key_issuance_lock, []
        def short_slice(path, *, timeout):
            attempts.append(timeout)
            return original(path, timeout=min(0.02, timeout))
        monkeypatch.setattr(storage, "key_issuance_lock", short_slice)
        release_timer = Timer(0.12, release.write_text, args=("release",), kwargs={"encoding": "ascii"})
        release_timer.start()
        try:
            with service.FixedIssuer(tmp_path, api.Backend(rng=NoRead()), lock_timeout=2)._locked():
                pass
        finally:
            release_timer.join(timeout=5)
        assert len(attempts) > 1
        output = child.communicate(timeout=20)
        assert child.returncode == 0, output
        with issuer._locked():
            pass
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=10)


def test_repeated_and_restarted_identity_reuses_real_key_without_entropy(issued):
    issuer, public, key = issued
    reopened = service.FixedIssuer(issuer.path, api.Backend(rng=NoRead()),
        expected_public=public, expected_params=public.params)
    before = (issuer.path/storage.STATE_FILE).read_bytes()
    assert len(before) <= service._preflight(public.params, 3)
    assert reopened.public_key().to_bytes() == public.to_bytes()
    assert reopened.key_extract(b"Alice").to_bytes() == key.to_bytes()
    assert reopened.key_extract(b"Alice").to_bytes() == key.to_bytes()
    assert (issuer.path/storage.STATE_FILE).read_bytes() == before


def test_independent_process_restart_reuses_real_key_without_entropy(issued):
    code = "\n".join([
        "import hashlib,sys",
        "from ibme.ibs.srgg_paper_service import FixedIssuer",
        "from experiments.research.candidates.srgg.paper_backend import Backend",
        "class NoRead:",
        "    def read(self,n): raise AssertionError('unexpected entropy')",
        "key=FixedIssuer(sys.argv[1],Backend(rng=NoRead())).key_extract(b'Alice')",
        "print(hashlib.sha256(key.to_bytes()).hexdigest())",
    ])
    child = subprocess.run([sys.executable, "-c", code, str(issued[0].path)],
        env=os.environ.copy(), capture_output=True, text=True, timeout=90)
    assert child.returncode == 0, child.stderr
    assert child.stdout.strip() == sha256(issued[2].to_bytes()).hexdigest()


def test_wrong_public_and_parameters_reject_recovery_without_replacement(issued, tmp_path):
    issuer = _clone(issued, tmp_path)
    public = issued[1]
    rows = [[list(poly) for poly in row] for row in public.b]
    rows[0][0][0] = (rows[0][0][0]+1) % public.params.modulus
    wrong_public = replace(public, b=rows)
    before = (issuer.path/storage.STATE_FILE).read_bytes()
    for kwargs in ({"expected_public": wrong_public},
                   {"expected_params": PaperParams("PARAM-II")},
                   {"expected_params": PaperParams("PARAM-I", "literal-density-width")}):
        with pytest.raises(service.IssuerStateError):
            service.FixedIssuer(issuer.path, api.Backend(rng=NoRead()), **kwargs).public_key()
    assert (issuer.path/storage.STATE_FILE).read_bytes() == before


@pytest.mark.parametrize("fault", ["extract", "pending-write", "final-write", "finish"])
def test_explicit_failures_block_reissue_and_keep_failed_state(issued, tmp_path, monkeypatch, fault):
    issuer = _clone(issued, tmp_path)
    calls = []
    if fault in ("extract", "pending-write"):
        class InjectedFailure:
            def key_extract(self, _master, _identity):
                calls.append(1)
                raise RuntimeError("injected extraction failure")
        issuer.backend = InjectedFailure()
    else:
        issuer.backend = api.Backend(rng=DeterministicRandom(b"paper-service-write-fault"))
    if fault in ("pending-write", "final-write"):
        write, writes = issuer._atomic_write, []
        def fail_write(data):
            writes.append(1)
            if len(writes) == (1 if fault == "pending-write" else 2):
                raise OSError("injected write failure")
            return write(data)
        monkeypatch.setattr(issuer, "_atomic_write", fail_write)
    if fault == "finish":
        finish = issuer._finish
        def fail_finish():
            finish()
            raise OSError("injected failure after marker removal")
        monkeypatch.setattr(issuer, "_finish", fail_finish)
    with pytest.raises((RuntimeError, OSError), match="injected"):
        issuer.key_extract(b"Bob")
    assert calls == ([1] if fault == "extract" else [])
    assert (issuer.path/storage.PENDING_FILE).exists()
    outer, master = _records(issuer.path)
    assert outer["status"] == "failed"
    assert [b"Bob".hex(), "failed", None] in master["entries"]
    reopened = service.FixedIssuer(issuer.path, api.Backend(rng=NoRead()))
    with pytest.raises(service.IssuerPendingError):
        reopened.key_extract(b"Bob")
    (issuer.path/storage.PENDING_FILE).unlink()
    with pytest.raises(service.IssuerPendingError):
        reopened.public_key()


@pytest.mark.parametrize("fault", ["truncated", "trailing", "schema", "duplicate", "capacity", "witness", "identity"])
def test_corrupt_snapshot_is_rejected_and_preserved(issued, tmp_path, fault):
    issuer = _clone(issued, tmp_path)
    path = issuer.path/storage.STATE_FILE
    raw = path.read_bytes()
    outer, master = _records(issuer.path)
    if fault == "truncated":
        raw = raw[:-1]
    elif fault == "trailing":
        raw += b" "
    elif fault == "duplicate":
        raw = b'{"schema":"duplicate",'+raw[1:]
    elif fault == "schema":
        raw = _canonical(dict(outer, schema="IBME/SRGG-STRUCTURED-OBJECT/1"))
    elif fault == "capacity":
        raw = _canonical(dict(outer, max_users=True))
    else:
        if fault == "witness":
            master["witness"][0][0][0] = 2
        else:
            master["entries"][0][0] = ""
        outer["master"] = _canonical(master).hex()
        raw = _canonical(outer)
    path.write_bytes(raw)
    with pytest.raises(service.IssuerStateError):
        issuer.public_key()
    assert path.read_bytes() == raw
    assert not (issuer.path/storage.PENDING_FILE).exists()


def test_process_exit_after_pending_commit_blocks_recovery(issued, tmp_path):
    issuer = _clone(issued, tmp_path)
    code = "\n".join([
        "import os,sys",
        "from ibme.ibs.srgg_paper_service import FixedIssuer",
        "class Crash:",
        "    def key_extract(self,*args): os._exit(23)",
        "FixedIssuer(sys.argv[1],Crash()).key_extract(b'Crash')",
    ])
    child = subprocess.run([sys.executable, "-c", code, str(issuer.path)],
        env=os.environ.copy(), capture_output=True, text=True, timeout=90)
    assert child.returncode == 23, child.stderr
    assert (issuer.path/storage.PENDING_FILE).exists()
    outer, master = _records(issuer.path)
    assert outer["status"] == "ready"
    assert [b"Crash".hex(), "pending", None] in master["entries"]
    with pytest.raises(service.IssuerPendingError):
        issuer.public_key()
    (issuer.path/storage.PENDING_FILE).unlink()
    with pytest.raises(service.IssuerPendingError):
        issuer.public_key()


def test_two_processes_requesting_new_identity_receive_one_real_key(issued, tmp_path):
    issuer = _clone(issued, tmp_path)
    barrier = tmp_path/"barrier"
    barrier.mkdir()
    code = "\n".join([
        "import hashlib,os,sys",
        "from pathlib import Path",
        "from time import monotonic,sleep",
        "from ibme.ibs.srgg_paper_service import FixedIssuer",
        "barrier=Path(sys.argv[2])",
        "(barrier/str(os.getpid())).write_text('ready')",
        "deadline=monotonic()+60",
        "while not (barrier/'go').exists():",
        "    if monotonic()>deadline: raise RuntimeError('barrier timeout')",
        "    sleep(0.01)",
        "key=FixedIssuer(sys.argv[1]).key_extract(b'Bob')",
        "print(hashlib.sha256(key.to_bytes()).hexdigest())",
    ])
    workers = [subprocess.Popen([sys.executable, "-c", code, str(issuer.path), str(barrier)],
        env=os.environ.copy(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(2)]
    try:
        deadline = monotonic()+60
        while not all((barrier/str(worker.pid)).exists() for worker in workers):
            assert all(worker.poll() is None for worker in workers)
            assert monotonic() < deadline
            sleep(0.01)
        (barrier/"go").write_text("release", encoding="ascii")
        outputs = [worker.communicate(timeout=180) for worker in workers]
    finally:
        for worker in workers:
            if worker.poll() is None:
                worker.kill()
                worker.communicate(timeout=10)
    assert all(worker.returncode == 0 for worker in workers), outputs
    key = issuer.key_extract(b"Bob")
    assert [stdout.strip() for stdout, _ in outputs] == [sha256(key.to_bytes()).hexdigest()]*2
    _, master = _records(issuer.path)
    assert len(master["entries"]) == 2
    assert not (issuer.path/storage.PENDING_FILE).exists()
