import pytest
pytest.importorskip("sage.all", reason="Use prescribed WSL Sage")
from sage.all import QQ
from experiments.research import chkp_width_audit as audit
from experiments.research.gaussian_reference import SamplingAbort
from experiments.research.chkp_basis import KernelBasis, ModMatrixReference


def test_old_fixed_basis_has_no_width_even_without_smoothing():
    result = audit.run_attempt(audit.SEEDS[0])
    assert result["outcome"] == "admission_rejected"
    interval = result["stages"][1]["width_interval"]
    assert QQ(interval["scalar_only_lower"]) > QQ(interval["upper"])
    assert not interval["C1_exec_nonempty"]


def test_same_widths_resolve_sampleD_but_preserve_randbasis_tape_gate():
    result = audit.run_attempt(audit.SEEDS[0], postprocess=True)
    assert result["outcome"] == "admission_rejected"
    assert result["stopped_at"] == "level_2_RandBasis"
    assert "tape exceeds" in result["reason"]
    assert [s["width_squared"] for s in result["stages"]] == ["9064", "15952640"]
    for stage in result["stages"]:
        assert stage["all_syndromes_exact"] == [True, True]
        assert stage["SampleD"]["C1_exec_verified"]
    assert result["stages"][0]["LLL"]["after"]["absolute_determinant"] == "2"
    second = result["stages"][1]
    assert second["RandBasis_required_tape_bytes"] > second["RandBasis_tape_cap_bytes"]
    assert "before_postprocess" not in second  # no invented second RandBasis output


def test_postprocess_abort_is_retained_without_retry(monkeypatch):
    calls = []
    def abort(*a, **kw):
        calls.append(1)
        raise SamplingAbort("forced LLL exhaustion")
    monkeypatch.setattr(audit, "reduce_basis", abort)
    result = audit.run_attempt(audit.SEEDS[0], postprocess=True)
    assert result["outcome"] == "explicit_abort" and len(calls) == 1
    assert result["stopped_at"] == "level_1_LLL"


def test_math_defect_is_not_hidden(monkeypatch):
    def fail(*a, **kw):
        raise ArithmeticError("forced math defect")
    monkeypatch.setattr(audit, "gen_basis", fail)
    with pytest.raises(ArithmeticError, match="math defect"):
        audit.run_attempt(audit.SEEDS[0])


def test_false_public_gs_bound_rejected_instead_of_misleading_interval():
    # Exact counterexample supplied by independent read-only review.
    basis = KernelBasis(ModMatrixReference([[1, 0]], 2), [[100000, 2], [1, 0]])
    assert not audit.width_interval(basis)["scalar_only_nonempty"]
    with pytest.raises(ValueError, match="underestimates"):
        audit.width_interval(basis, 1)


def test_cli_does_not_equate_audit_completion_with_T2_completion(monkeypatch, capsys):
    monkeypatch.setattr(audit, "build_report", lambda: {"counts": {}, "T2_complete": False})
    monkeypatch.setattr("sys.argv", ["chkp_width_audit"])
    assert audit.main() == 2
    assert '"T2_complete": false' in capsys.readouterr().out
