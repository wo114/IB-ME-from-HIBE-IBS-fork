"""Live original-row cross-checks for the fixed SRGG service entropy ledger."""
import json
from pathlib import Path

import pytest

from ibme.ibs.srgg_paper_service import _preflight, IssuerCapacityError
from experiments.research.candidates.srgg.paper_parameters import PaperParams
from experiments.research.candidates.srgg.paper_service_resource_envelope import (
    ROOT, bounded_single_root, report, row_envelope,
)


RECEIPTS = Path("docs/research/team-b-delivery/2026-10-18-srgg-source-schur")


@pytest.fixture(scope="module")
def live():
    return report()


def _receipt_name(row):
    name = row["profile"].lower()
    suffix = "-literal" if row["interpretation"] == "literal-density-width" else ""
    return f"{name}{suffix}-bounded-final-lifecycle.json"


def test_all_six_live_caps_match_successful_source_schur_receipts(live):
    assert len(live["rows"]) == 6
    for row in live["rows"]:
        receipt = json.loads((ROOT/RECEIPTS/_receipt_name(row)).read_text(encoding="utf-8"))
        assert receipt["status"] == "functional-pass"
        assert receipt["profile"] == row["parameter_record"]
        assert receipt["master_sampler"]["whole_entropy_cap_bytes"] == row[
            "first_issuance"]["master_samplef_hard_cap_bytes"]
        assert receipt["signature_sampler"]["whole_entropy_cap_bytes"] == row[
            "signing"]["sign_samplef_hard_cap_bytes"]
        assert receipt["signature_attempt_entropy"]["selected_cap_bytes"] == row[
            "signing"]["one_attempt_hard_entropy_cap_bytes"]
        assert receipt["signature_call_entropy"]["one_sign_call_hard_cap_bytes"] == row[
            "signing"]["one_call_hard_entropy_cap_bytes"]
        assert row["signing"]["whole_attempt_extra_cap_charged_once"] is True
        assert row["setup"]["actual_setup_retry_failure_upper"] is None
        assert row["first_issuance"]["complete_issuance_failure_upper"] is None
        assert row["signing"]["complete_signature_failure_upper"] is None


def test_fixed_issuer_capacity_is_actual_preflight_boundary(live):
    for row in live["rows"]:
        params = PaperParams(row["profile"], row["interpretation"])
        maximum = row["fixed_issuer"]["maximum_admitted_new_identities"]
        assert _preflight(params, maximum) == row["fixed_issuer"]["state_bytes_upper_at_maximum"]
        assert row["fixed_issuer"]["state_bytes_upper_at_maximum"] <= 2*1024*1024
        with pytest.raises(IssuerCapacityError):
            _preflight(params, maximum+1)


def test_bounded_lifetime_formula_and_unbounded_signing_gap(live):
    for row in live["rows"]:
        maximum = row["fixed_issuer"]["maximum_admitted_new_identities"]
        ledger = bounded_single_root(row, new_identities=maximum, sign_calls=2)
        expected = (row["setup"]["one_setup_hard_entropy_cap_bytes"]
                    + maximum*row["first_issuance"]["one_new_identity_hard_entropy_cap_bytes"]
                    + 2*row["signing"]["one_call_hard_entropy_cap_bytes"])
        assert ledger["single_root_hard_entropy_cap_bytes"] == expected
        assert bounded_single_root(row, new_identities=0, sign_calls=3)[
            "single_root_hard_entropy_cap_bytes"] > bounded_single_root(
                row, new_identities=0, sign_calls=2)["single_root_hard_entropy_cap_bytes"]
        assert row["formula"]["global_service_lifetime_entropy_cap_bytes"] is None
        assert row["formula"]["global_service_lifetime_failure_upper"] is None
        assert row["fixed_issuer"]["external_fault_probability_upper"] is None
    assert live["peak_ram_upper_bytes"] is None
    assert live["author_C_ANS_or_1000_run_performance_reproduced"] is False


def test_lifetime_counts_and_original_retry_options_are_bounded(live):
    row = live["rows"][0]
    assert row["setup"]["seed_bytes"] == 32
    assert row["setup"]["max_attempts"] == 64
    assert row["signing"]["max_attempts_per_call"] == 64
    assert row["fixed_issuer"]["default_max_users"] == 1
    for bad in (-1, True, 1.0):
        with pytest.raises(ValueError):
            bounded_single_root(row, new_identities=bad, sign_calls=0)
        with pytest.raises(ValueError):
            bounded_single_root(row, new_identities=0, sign_calls=bad)
    with pytest.raises(ValueError):
        bounded_single_root(row, new_identities=1+row["fixed_issuer"][
            "maximum_admitted_new_identities"], sign_calls=0)
    with pytest.raises(ValueError):
        row_envelope("PARAM-IV")
