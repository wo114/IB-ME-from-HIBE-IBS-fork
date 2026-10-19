"""Guard preparation failures, compatibility and recovery boundaries.

Injected failures test service policy only. Real successful controls use the
unchanged original PARAM-I row and do not establish cryptographic security.
"""
from __future__ import annotations

import pytest

from ibme.core.randomness import DeterministicRandom
from ibme.ibs.srgg_paper.guarded import GuardedSourceSchurBackend
from ibme.ibs.srgg_paper import guarded
from experiments.research.candidates.srgg import paper_distribution_guard as guard
from experiments.research.candidates.srgg import paper_schur_backend as implementation
from experiments.research.candidates.srgg.paper_parameters import PaperParams
from experiments.research.candidates.srgg.paper_objects import MasterSecret
from experiments.research.candidates.srgg.paper_samplef import WitnessGeometryError
from experiments.research.candidates.srgg.paper_schur_backend import SourceSchurBackend
from experiments.research.gaussian_reference import SamplingAbort


class ZeroWitnessSource:
    """Deterministic fixture: zero seed/witness, with explicit read accounting."""

    def __init__(self):
        self.reads = []

    def read(self, count):
        self.reads.append(count)
        return bytes(count)


class NoRead:
    def read(self, _count):
        raise AssertionError("failed plan consumed sampling entropy")


@pytest.fixture(scope="module")
def real_key():
    params = PaperParams("PARAM-I")
    backend = SourceSchurBackend(rng=DeterministicRandom(b"guard-failure-semantics-key"))
    public, master = backend.setup(params)
    key = backend.key_extract(master, b"Alice")
    return params, public, master, key


def test_compatibility_backend_and_exception_names_are_identical():
    assert GuardedSourceSchurBackend is SourceSchurBackend
    assert guarded.RootGateRejection is guard.RootGateRejection
    assert guarded.SigningKeyGateRejection is guard.SigningKeyGateRejection


@pytest.mark.parametrize("failure", [ValueError, WitnessGeometryError, ArithmeticError])
def test_setup_retries_preparation_failure_before_any_sample(monkeypatch, failure):
    params = PaperParams("PARAM-I")
    source = ZeroWitnessSource()
    backend = SourceSchurBackend(rng=source, setup_max_attempts=2)
    original = implementation.PaperSchurSampleF
    calls = 0

    def fail_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise failure("injected deterministic preparation failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(implementation, "PaperSchurSampleF", fail_once)
    public, master = backend.setup(params)
    witness_bytes = 2 * params.rank**2 * params.digits * params.degree
    assert source.reads == [32, witness_bytes, witness_bytes]
    assert calls == backend.setup_attempts == 2
    assert backend.gate_rejections == 1
    assert backend.last_master_gate_audit is not None
    assert master.public_key == public


def test_setup_exhaustion_counts_gate_failures_without_sampler_entropy(monkeypatch):
    params = PaperParams("PARAM-I")
    source = ZeroWitnessSource()
    backend = SourceSchurBackend(rng=source, setup_max_attempts=2)

    def fail(*_args, **_kwargs):
        raise guard.GateFailure("injected audit failure")

    monkeypatch.setattr(guard, "require_gates", fail)
    with pytest.raises(SamplingAbort):
        backend.setup(params)
    witness_bytes = 2 * params.rank**2 * params.digits * params.degree
    assert source.reads == [32, witness_bytes, witness_bytes]
    assert backend.gate_rejections == backend.setup_attempts == 2
    assert backend.last_master_gate_audit is None


@pytest.mark.parametrize("failure", [ValueError, WitnessGeometryError, ArithmeticError])
def test_sign_preparation_failure_aborts_fixed_key_without_entropy(monkeypatch, failure, real_key):
    _params, _public, _master, key = real_key
    before = key.to_bytes()
    backend = SourceSchurBackend(rng=NoRead())

    def fail(*_args, **_kwargs):
        raise failure("injected signing preparation failure")

    monkeypatch.setattr(implementation, "PaperSchurSampleF", fail)
    with pytest.raises(guard.SigningKeyGateRejection) as caught:
        backend.sign(key, b"unchanged fixed key")
    assert isinstance(caught.value.__cause__, failure)
    assert backend.sign_attempts == 0
    assert backend.last_sign_gate_audit is None
    assert key.to_bytes() == before


def test_sign_audit_failure_aborts_before_entropy(monkeypatch, real_key):
    _params, _public, _master, key = real_key
    backend = SourceSchurBackend(rng=NoRead())

    def fail(*_args, **_kwargs):
        raise guard.GateFailure("injected stored-factor audit failure")

    monkeypatch.setattr(guard, "require_gates", fail)
    with pytest.raises(guard.SigningKeyGateRejection):
        backend.sign(key, b"gate rejection")
    assert backend.sign_attempts == 0


def test_new_issuance_gate_failure_blocks_reissue_and_preserves_cached_key(monkeypatch, real_key):
    _params, _public, original_master, key = real_key
    master = MasterSecret.from_bytes(original_master.to_bytes())
    backend = SourceSchurBackend(rng=NoRead())

    def fail(*_args, **_kwargs):
        raise guard.GateFailure("injected restored-root gate failure")

    monkeypatch.setattr(guard, "require_gates", fail)
    with pytest.raises(guard.RootGateRejection):
        backend.key_extract(master, b"Bob")
    assert master.states[b"Bob"] == ("failed", None)
    assert master.states[b"Alice"][1].to_bytes() == key.to_bytes()
    with pytest.raises(SamplingAbort, match="pending/failed"):
        backend.key_extract(master, b"Bob")
    assert backend.extract_calls == 1


@pytest.mark.parametrize("failure", [OSError, MemoryError])
def test_external_preparation_fault_is_not_retried(monkeypatch, failure):
    params = PaperParams("PARAM-I")
    source = ZeroWitnessSource()
    backend = SourceSchurBackend(rng=source, setup_max_attempts=2)

    def fail(*_args, **_kwargs):
        raise failure("injected external fault")

    monkeypatch.setattr(implementation, "PaperSchurSampleF", fail)
    with pytest.raises(failure):
        backend.setup(params)
    assert backend.setup_attempts == 1
    assert backend.gate_rejections == 0


def test_historical_unguarded_probe_is_explicitly_not_run(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("disabled probe ran the guarded backend")

    monkeypatch.setattr(guard, "SourceSchurBackend", forbidden)
    result = guard.probe_unguarded_gate_gap("PARAM-I", "table-standard-deviation", 6)
    assert result["status"] == "not_run_after_guard_unification"
    assert result["enabled"] is False
    assert result["witness_found"] is None
    assert result["seeds_tried"] == 0
    assert result["requested_seeds"] == 6


def test_signature_probe_records_every_stage_failure(monkeypatch):
    cases = iter(("setup", "issuance", "sign_plan", "reject", "accept"))

    class FixtureBackend:
        def __init__(self, **_kwargs):
            self.case = next(cases)

        def setup(self, _params):
            if self.case == "setup":
                raise SamplingAbort("private setup details")
            return object(), object()

        def key_extract(self, _master, _identity):
            if self.case == "issuance":
                raise OSError("private storage details")
            return object()

        def _sign_plan(self, _key):
            if self.case == "sign_plan":
                raise RuntimeError("private plan details")
            if self.case == "reject":
                raise guard.SigningKeyGateRejection("private rejected-key details")

    monkeypatch.setattr(guard, "SourceSchurBackend", FixtureBackend)
    result = guard.probe_sign_gate_mass("PARAM-I", "table-standard-deviation", 5)
    assert result["sign_gate_accepts"] == result["sign_gate_rejections"] == 1
    assert result["stage_failures"] == {"setup": 1, "issuance": 1, "sign_plan": 1}
    assert result["all_attempted_fixtures_accounted_for"] is True
    assert [item["stage"] for item in result["failure_types"]] == ["setup", "issuance", "sign_plan"]
    assert "private" not in str(result)
