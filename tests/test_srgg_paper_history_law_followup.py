"""Independent scope checks for SRGG fixed-root adaptive history follow-up."""
from fractions import Fraction
import json
from pathlib import Path

import pytest

from experiments.research.candidates.srgg import paper_history_law_followup as history


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "docs/research/team-b-delivery/2026-10-18-srgg-history-law-followup/history-law.json"


def test_adaptive_coupling_toy_with_abort_and_adaptive_second_step():
    # Real transcript is always (0,0).  Reference flips at step 1 with 1/4;
    # on the matching branch the next conditional kernel flips with 1/5.
    # Diverged histories may behave arbitrarily; only matching-history kernels
    # enter the proof.  Exact TV is 1-(3/4)(4/5)=2/5 <= 1/4+1/5.
    exact_tv = 1 - (1 - Fraction(1, 4)) * (1 - Fraction(1, 5))
    assert exact_tv == Fraction(2, 5)
    assert exact_tv <= history.union_bound(Fraction(1, 4) + Fraction(1, 5), 1)
    assert history.union_bound(Fraction(1, 4), 4) == 1
    assert history.union_bound(Fraction(1, 4), 0) == 0


@pytest.mark.parametrize("bad,count", [
    (None, 1), (-1, 1), (Fraction(3, 2), 1), (True, 1),
    (0, True), (0, -1), (0, 1025),
])
def test_history_bound_rejects_unproved_or_unbounded_inputs(bad, count):
    with pytest.raises(ValueError):
        history.union_bound(bad, count)


@pytest.mark.parametrize("value,expected", [
    (Fraction(0), "0"), (Fraction(1), "1"),
    (Fraction(1, 4), "2^-2"), (Fraction(1, 5), "2^-2"),
    (Fraction(3, 4), "1"), (Fraction(1, 2**128), "2^-128"),
])
def test_dyadic_is_an_outward_upper(value, expected):
    label = history.dyadic_upper(value)
    assert label == expected
    upper = Fraction(1) if label == "1" else (
        Fraction(0) if label == "0" else Fraction(1, 2**int(label[3:])))
    assert value <= upper


def test_authentic_predecessor_chain_and_one_replayed_signing_key():
    source, finite, joint, binding = history.authenticated_inputs()
    assert len(source["rows"]) == len(finite["rows"]) == len(joint["rows"]) == 6
    assert set(binding) == {
        "source_issuance_sha256", "finite_sha256", "joint_sha256",
        "source_package_manifest_sha256",
    }
    fresh = history.certificate("PARAM-I", "table-standard-deviation")
    frozen = next(row for row in json.loads(REPORT.read_text(encoding="utf-8"))["rows"]
                  if row["profile"] == "PARAM-I" and
                  row["interpretation"] == "table-standard-deviation")
    assert fresh == frozen
    assert fresh["same_fixture_key_signature_plan_replayed"] is True
    assert fresh["fixed_service_worst_case_capacity_users"] == 3
    assert fresh["issuance_only_history_at_capacity_tv_upper"] == "2^-24"
    assert fresh["same_fixture_key_two_adaptive_sign_calls_tv_upper"] == "2^-18"
    assert fresh["random_issued_key_then_sign_history_tv"] is None


def test_six_row_report_never_promotes_missing_full_history_or_literal_issue():
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    assert report["schema"] == history.SCHEMA + "/REPORT"
    assert len(report["rows"]) == 6
    assert report["full_random_issuance_signature_fault_history_tv"] is None
    expected_capacity = {"PARAM-I": 3, "PARAM-II": 2, "PARAM-III": 1}
    for row in report["rows"]:
        assert row["fixed_service_worst_case_capacity_users"] == expected_capacity[row["profile"]]
        assert row["all_accepted_setup_roots_tv"] is None
        assert row["faulty_storage_history_tv"] is None
        assert row["uniform_all_reachable_signing_keys_schur_bound"] is None
        assert row["bad_issued_key_sign_plan_probability"] is None
        assert row["native_strong_security_proven"] is False
        assert row["security_claim"] == "none"
        assert row["backend_admitted"] is False
        assert row["parameters_are_formal"] is False
        assert row["nist_security_category"] is None
        if row["interpretation"] == "literal-density-width":
            assert row["one_fresh_issuance_tv_upper"] is None
            assert row["issuance_only_history_at_capacity_tv_upper"] is None
            assert row["same_fixture_key_one_sign_call_tv_upper"] == "1"
        else:
            assert row["one_fresh_issuance_tv_upper"].startswith("2^-")
            assert row["issuance_only_history_at_capacity_tv_upper"].startswith("2^-")
            assert row["same_fixture_key_two_adaptive_sign_calls_bound_nontrivial"] is True


@pytest.mark.parametrize("profile,interpretation", [
    ("PARAM-0", "table-standard-deviation"),
    ("PARAM-I", "default"),
])
def test_unknown_original_parameter_route_rejected(profile, interpretation):
    with pytest.raises(ValueError):
        history.certificate(profile, interpretation)
