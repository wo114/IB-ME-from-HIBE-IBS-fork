"""Fast runner controls with synthetic objects; no cryptographic operations.

The fakes test bookkeeping and object routing only. They do not establish
cryptographic correctness, secure restoration, or a security parameter level.
"""
import csv
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


@pytest.fixture
def runner():
    path = Path(__file__).resolve().parents[1] / "experiments/research/luo_lifecycle_benchmark.py"
    spec = importlib.util.spec_from_file_location("lifecycle_runner_controls", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_csv(path):
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(7), RuntimeError("test failure")])
def test_timed_reserves_event_and_preserves_base_exception(runner, monkeypatch, error):
    rows = []
    clock = iter((1_000_000_000, 1_250_000_000))
    monkeypatch.setattr(runner, "time", SimpleNamespace(perf_counter_ns=lambda: next(clock)))
    backend = SimpleNamespace(last_sign_attempts=0)

    def fail():
        assert len(rows) == 1 and rows[0]["status"] == "error"
        backend.last_sign_attempts = 3
        raise error

    with pytest.raises(type(error)) as caught:
        runner.timed(rows, (0, 5, 256, 0), "sign", fail, backend=backend)
    assert caught.value is error
    assert len(rows) == 1
    assert rows[0]["error_type"] == type(error).__name__
    assert rows[0]["status"] == "error"
    assert rows[0]["sign_attempts"] == 3
    assert rows[0]["seconds"] == .25


def test_timed_returns_value_and_records_success(runner):
    rows, value = [], object()
    returned, row = runner.timed(rows, (0, 1, 0, 0), "decode", lambda: value, "reference")
    assert returned is value and rows == [row]
    assert row["status"] == "ok" and row["error_type"] == ""
    assert row["seconds"] >= 0


def test_timed_pre_attempt_interrupt_keeps_counter_unknown(runner):
    rows = []

    def interrupt():
        raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        runner.timed(rows, (0, 1, 0, 0), "sign", interrupt,
                     backend=SimpleNamespace(last_sign_attempts=0))
    assert rows[0]["sign_attempts"] == ""


def test_validate_failure_marks_existing_event_invalid(runner):
    rows = []
    _, row = runner.timed(rows, (0, 1, 0, 0), "verify", lambda: False)
    with pytest.raises(ValueError):
        runner.validate(row, False)
    assert rows[0]["status"] == "invalid"
    assert rows[0]["error_type"] == "EvidenceValidationError"
    assert rows[0]["seconds"] >= 0


def test_validate_success_does_not_change_event(runner):
    row = dict(status="ok", error_type="", seconds=.125)
    before = row.copy()
    runner.validate(row, True)
    assert row == before


@pytest.fixture
def synthetic_main(runner, monkeypatch):
    """Replace every algorithm/codec entry point before invoking main."""
    trace = SimpleNamespace(setup_error=None, sign_error=None, sign_keys=[],
                            restored_cache_reads=0, restored_cache_keys=[],
                            audit_calls=0, audit_error=None)

    class Public:
        def to_bytes(self):
            return b"synthetic-public"

        @classmethod
        def from_bytes(cls, raw):
            assert raw == b"synthetic-public"
            return cls()

    class Key:
        def __init__(self, identity, restored=False):
            self.identity, self.restored = identity, restored

        def to_bytes(self):
            return self.identity

        @classmethod
        def from_bytes(cls, raw):
            return cls(raw, restored=True)

    class Master:
        def __init__(self, identities=(), restored=False):
            self.keys = {identity: Key(identity, restored) for identity in identities}
            self.restored = restored

        @property
        def cached_identities(self):
            return tuple(sorted(self.keys))

        def to_bytes(self):
            return b"/".join(self.cached_identities)

        @classmethod
        def from_bytes(cls, raw):
            return cls(raw.split(b"/") if raw else (), restored=True)

    class Signature:
        params, context, z, c, w1, h = "synthetic", b"public", (1,), (1,), (1,), (0,)

        def to_bytes(self):
            return b"synthetic-reference"

    class Compact:
        def __init__(self, signature):
            self.signature = signature

        def to_bytes(self):
            return b"synthetic-compact"

    class Backend:
        def __init__(self, rng=None):
            self.rng = rng
            self.last_extract_attempts = self.last_sign_attempts = 0

        def setup(self, params):
            if trace.setup_error is not None:
                raise trace.setup_error
            return Public(), Master()

        def key_extract(self, master, identity):
            if identity in master.keys:
                self.last_extract_attempts = 0
                if master.restored:
                    trace.restored_cache_reads += 1
                    trace.restored_cache_keys.append(master.keys[identity])
                return master.keys[identity]
            if self.rng is not None:
                self.rng.read(1)  # NoEntropy is live if routing misses the cache.
            self.last_extract_attempts = 1
            master.keys[identity] = Key(identity)
            return master.keys[identity]

        def sign(self, key, message):
            trace.sign_keys.append(key)
            self.last_sign_attempts = 2
            if trace.sign_error is not None:
                raise trace.sign_error
            return Signature()

        def load_signature(self, public, raw):
            assert raw == b"synthetic-reference"
            return Signature()

        def verify(self, public, identity, message, signature):
            return True

    class CompactBackend(Backend):
        def load_signature(self, public, raw):
            assert raw == b"synthetic-compact"
            return Compact(Signature())

    def audit(output, run_id):
        trace.audit_calls += 1
        if trace.audit_error is not None:
            raise trace.audit_error
        return {"normal_calls": len(read_csv(output / f"luo-sign-calls-{run_id}.csv"))}

    monkeypatch.setattr(runner, "LuoModuleParams", lambda: object())
    monkeypatch.setattr(runner, "LuoModulePublicKey", Public)
    monkeypatch.setattr(runner, "LuoModuleMasterSecret", Master)
    monkeypatch.setattr(runner, "LuoModuleSigningKey", Key)
    monkeypatch.setattr(runner, "LuoModuleIBSBackend", Backend)
    monkeypatch.setattr(runner, "LuoModuleCompactIBSBackend", CompactBackend)
    monkeypatch.setattr(runner, "LuoModuleCompactSignature", Compact)
    monkeypatch.setattr(runner, "make_backend", lambda *args, **kwargs: Backend())
    monkeypatch.setattr(runner, "metadata", lambda run_id: dict(
        run_id=run_id, completed=False, interrupted=False, failure_type=None,
        source_sha256={}))
    monkeypatch.setattr(runner, "peak_memory", lambda: dict(bytes=None, method="test-unavailable"))
    monkeypatch.setitem(sys.modules, "audit_luo_lifecycle", SimpleNamespace(audit=audit))
    return trace


@pytest.mark.parametrize("stage", ["setup", "sign"])
@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(9)])
def test_main_interruption_saves_incomplete_records(runner, synthetic_main, tmp_path, stage, error):
    setattr(synthetic_main, stage + "_error", error)
    output = tmp_path / "interrupted"
    with pytest.raises(type(error)) as caught:
        runner.main(output, "control")
    assert caught.value is error
    meta = json.loads((output / "run-metadata-control.json").read_text(encoding="utf-8"))
    assert meta["completed"] is False and meta["interrupted"] is True
    assert meta["failure_type"] == type(error).__name__
    assert meta["memory"]["bytes"] is None
    events = read_csv(output / "luo-single-call-ledger-control.csv")
    assert events[-1]["stage"] == stage and events[-1]["status"] == "error"
    assert events[-1]["error_type"] == type(error).__name__
    assert float(events[-1]["seconds"]) >= 0
    calls = read_csv(output / "luo-sign-calls-control.csv")
    assert len(calls) == int(stage == "sign")
    assert meta["attempted_sign_calls"] == len(calls)
    if calls:
        assert calls[0]["status"] == "error"
        assert calls[0]["failure_type"] == type(error).__name__
    assert not (output / "summary.json").exists()
    assert synthetic_main.audit_calls == 0


def test_main_routes_original_and_restored_keys(runner, synthetic_main, tmp_path):
    output = tmp_path / "complete"
    runner.main(output, "control")
    calls = read_csv(output / "luo-sign-calls-control.csv")
    assert len(calls) == len(synthetic_main.sign_keys) == 54
    assert synthetic_main.restored_cache_reads >= 9
    assert all(key.restored is bool(int(row["repetition"]))
               for row, key in zip(calls, synthetic_main.sign_keys))
    assert all(key in synthetic_main.restored_cache_keys
               for row, key in zip(calls, synthetic_main.sign_keys) if int(row["repetition"]) == 1)
    assert all(row["status"] == "ok" for row in calls)
    assert synthetic_main.audit_calls == 1
    assert json.loads((output / "summary.json").read_text(encoding="utf-8"))["normal_calls"] == 54


def test_main_sampling_aborts_keep_all_54_calls_and_timers(runner, synthetic_main, tmp_path):
    synthetic_main.sign_error = runner.LuoModuleSamplingAbort("synthetic abort")
    output = tmp_path / "aborted"
    with pytest.raises(ValueError):
        runner.main(output, "control")
    calls = read_csv(output / "luo-sign-calls-control.csv")
    events = read_csv(output / "luo-single-call-ledger-control.csv")
    signs = [row for row in events if row["stage"] == "sign"]
    assert len(calls) == len(signs) == 54
    assert all(row["status"] == "error" and row["failure_type"] == "LuoModuleSamplingAbort" for row in calls)
    meta = json.loads((output / "run-metadata-control.json").read_text(encoding="utf-8"))
    assert meta["completed"] is False and meta["normal_call_failures"] == 54
    assert meta["attempted_sign_calls"] == 54
    assert not (output / "summary.json").exists() and synthetic_main.audit_calls == 0
    for call, event in zip(calls, signs):
        assert call["sign_seconds"] != "", "a failed Sign still has an observed duration"
        assert float(call["sign_seconds"]) == float(event["seconds"])
        assert int(call["sign_attempts"]) == int(event["sign_attempts"]) == 2


def test_main_audit_rejection_does_not_leave_completed_true(runner, synthetic_main, tmp_path):
    synthetic_main.audit_error = ValueError("synthetic audit rejection")
    output = tmp_path / "audit-rejected"
    with pytest.raises(ValueError, match="synthetic audit rejection"):
        runner.main(output, "control")
    assert synthetic_main.audit_calls == 1
    meta = json.loads((output / "run-metadata-control.json").read_text(encoding="utf-8"))
    assert meta["completed"] is False, "audit failure must invalidate the published completion marker"
    assert not (output / "summary.json").exists()


def test_main_refuses_existing_output_before_work(runner, monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        pytest.fail("existing output must be rejected before metadata or algorithms")

    monkeypatch.setattr(runner, "metadata", forbidden)
    monkeypatch.setattr(runner, "make_backend", forbidden)
    marker = tmp_path / "run-metadata-control.json"
    marker.write_text("keep-existing-evidence", encoding="utf-8")
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    with pytest.raises(FileExistsError):
        runner.main(tmp_path, "control")
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


@pytest.mark.parametrize("run_id", ["../escape", "", "中文"])
def test_invalid_run_id_does_not_create_output(runner, tmp_path, run_id):
    output = tmp_path / "never-created"
    with pytest.raises(ValueError):
        runner.main(output, run_id)
    assert not output.exists()


def test_unknown_memory_on_other_platform_is_json_null(runner, monkeypatch):
    monkeypatch.setattr(runner, "os", SimpleNamespace(name="posix"))
    result = json.loads(json.dumps(runner.peak_memory()))
    assert result["bytes"] is None


@pytest.mark.parametrize("error", [OSError("probe unavailable"), AttributeError("probe unavailable")])
def test_memory_probe_error_is_json_null(runner, monkeypatch, error):
    monkeypatch.setattr(runner, "os", SimpleNamespace(name="nt"))

    def unavailable(*args, **kwargs):
        raise error

    monkeypatch.setattr(runner.ctypes, "WinDLL", unavailable, raising=False)
    result = json.loads(json.dumps(runner.peak_memory()))
    assert result["bytes"] is None and result["error_type"] == type(error).__name__
