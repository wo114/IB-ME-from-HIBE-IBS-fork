"""The public chain report must retain failures, not silently retry them."""

import pytest

pytest.importorskip("sage.all", reason="Use prescribed WSL Sage")
from sage.all import QQ

from experiments.research import chkp_t2_audit as audit
from experiments.research.gaussian_reference import SamplingAbort


def test_actual_declared_chain_records_second_level_resource_limit():
    result = audit.run_attempt(audit.SEEDS[0])
    assert result["outcome"] == "admission_rejected"
    assert result["stopped_at"] == "level_2_SampleD_admission"
    assert len(result["stages"]) == 3
    root, first, second = result["stages"]
    assert root["kernel_equation_exact"]
    assert first["all_syndromes_equations_exact"] == [True, True]
    assert first["raw_vectors_consumed"] == 20
    assert first["randomized_basis"]["absolute_determinant"] == "2"
    assert QQ(second["maximum_required_scalar_squared_width"]) > 10**12
    assert "sampleD_certificate" not in second


def test_setup_abort_not_counted_as_chain_success_or_retried(monkeypatch):
    calls = []
    def abort(*a, **kw):
        calls.append(1)
        raise SamplingAbort("forced setup abort")
    monkeypatch.setattr(audit, "gen_basis", abort)
    result = audit.run_attempt("declared-abort-test")
    assert result["outcome"] == "explicit_abort"
    assert result["stopped_at"] == "GenBasis"
    assert result["stages"] == [] and len(calls) == 1


def test_internal_math_error_is_not_relabelled_as_resource_rejection(monkeypatch):
    def defect(*a, **kw):
        raise ArithmeticError("injected equation defect")
    monkeypatch.setattr(audit, "gen_basis", defect)
    with pytest.raises(ArithmeticError, match="equation defect"):
        audit.run_attempt("declared-error-test")
