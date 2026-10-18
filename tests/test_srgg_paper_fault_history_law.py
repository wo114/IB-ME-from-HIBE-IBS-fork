"""Exact composition counterexamples and original-parameter object witness."""
from fractions import Fraction

import pytest

from experiments.research.candidates.srgg import paper_fault_history_law as law


@pytest.mark.parametrize("size", (2, 8, 37))
def test_fixture_signing_is_insufficient_even_with_identical_issuance(size):
    record = law.fixture_key_counterexample(size)
    assert record["issuance_tv_exact"] == "0"
    assert record["fixture_key_0_signing_tv_exact"] == "0"
    assert Fraction(record["complete_issue_then_sign_tv_exact"]) == Fraction(size-1, size)
    assert not record["is_srgg_attack"]


@pytest.mark.parametrize("rate", (Fraction(0), Fraction(1, 3), Fraction(1)))
def test_unmodeled_fault_probability_is_exactly_visible(rate):
    record = law.external_fault_counterexample(rate)
    assert record["fault_free_issue_and_sign_tv_exact"] == "0"
    assert Fraction(record["complete_history_tv_exact"]) == rate
    assert record["fault_label_retained"] and not record["is_srgg_attack"]


def test_complete_microstep_formula_requires_all_inputs_and_counts_bad_keys_once():
    rows = [
        {"kind": "first issue", "count": 3, "uniform_tv": Fraction(1, 100)},
        {"kind": "sign", "count": 2, "uniform_tv": Fraction(1, 200)},
        {"kind": "fault", "count": 4, "uniform_tv": Fraction(1, 1000)},
    ]
    result = law.conditional_microstep_bound(
        initial_complete_state_tv=Fraction(1, 1000),
        bad_signing_key_history_mass=Fraction(1, 50), microsteps=rows)
    assert Fraction(result["conditional_complete_history_tv_upper"]) == Fraction(65, 1000)
    assert not result["all_conditional_premises_verified_here"]
    assert law.conditional_microstep_bound(
        initial_complete_state_tv=0, bad_signing_key_history_mass=None,
        microsteps=rows)["conditional_complete_history_tv_upper"] is None
    rows[2]["uniform_tv"] = None
    assert law.conditional_microstep_bound(
        initial_complete_state_tv=0, bad_signing_key_history_mass=0,
        microsteps=rows)["conditional_complete_history_tv_upper"] is None


@pytest.mark.parametrize("bad", (
    {"kind": "sign", "count": True, "uniform_tv": 0},
    {"kind": "sign", "count": -1, "uniform_tv": 0},
    {"kind": "sign", "count": 1, "uniform_tv": Fraction(3, 2)},
    {"kind": "sign", "count": 1, "uniform_tv": 0, "extra": 0},
))
def test_arithmetic_rejects_invalid_premises(bad):
    with pytest.raises(ValueError):
        law.conditional_microstep_bound(
            initial_complete_state_tv=0, bad_signing_key_history_mass=0,
            microsteps=(bad,))
    with pytest.raises(ValueError):
        law.exact_tv({"ok": Fraction(1, 2)}, {"ok": 1})


def test_original_table4_wire_object_does_not_imply_sign_schur_positive():
    pytest.importorskip("sage.all", reason="specified WSL Sage required")
    witness = law.wire_valid_bad_sign_plan_witness()
    assert witness["profile"] == "PARAM-I"
    assert witness["interpretation"] == "table-standard-deviation"
    assert witness["key_wire_round_trip"] and witness["public_zero_witness_relation"]
    assert Fraction(witness["negative_shifted_schur_rayleigh_exact"]) < 0
    assert witness["shows_all_wire_valid_keys_have_signing_certificate"] is False
    assert witness["key_output_by_random_extract_claimed"] is False


def test_report_binds_real_source_and_keeps_full_history_null():
    pytest.importorskip("sage.all", reason="specified WSL Sage required")
    result = law.build_report()
    assert result["schema"] == law.SCHEMA
    assert len(result["six_rows"]) == 6
    assert result["full_history_bound"] is None
    assert result["conditional_hybrid"]["conditional_complete_history_tv_upper"] is None
    assert all(row["full_issuance_signature_fault_history_tv"] is None
               for row in result["six_rows"])
    assert result["source_map"]["src/ibme/ibs/srgg_paper_service.py"]["anchors"]
    assert result["security_claim"] == "none"
    assert result["backend_admitted"] is False
    assert result["parameters_are_formal"] is False
    assert result["nist_security_category"] is None
