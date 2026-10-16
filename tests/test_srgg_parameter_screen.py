"""Public-boundary tests for the HIBE-independent SRGG parameter screen."""

import json

import pytest

from experiments.research.candidates.srgg.config import Config
from experiments.research.candidates.srgg.parameter_screen import (
    KYBER_NIST_REFERENCE,
    SCHEMA,
    screen,
)


def test_screen_has_complete_snapshot_and_explicit_nonadmission_flags():
    report = screen()
    assert report["schema"] == SCHEMA
    assert report["hibe_independent"] is True
    assert report["security_claim"] == "none"
    assert report["backend_admitted"] is False
    assert report["parameters_are_formal"] is False
    assert set(report["parameters"]) == set(Config().record())
    assert report["correctness"]["all_component_gates_pass"] is True
    assert report["hardness"]["hardness_estimate_ready"] is False


def test_wire_and_capacity_are_shape_bounded_without_secret_material():
    report = screen(identity_bytes=64, message_bytes=1024, issuer_users=4)
    wire = report["wire"]
    assert wire["all_reference_objects_within_wire_limit"] is True
    assert wire["object_wire_limit_bytes"] == 2**21
    assert report["capacity"]["identity_max_bytes"] == 64
    assert report["capacity"]["message_max_bytes"] == 1024
    assert report["capacity"]["issuer_identity_slots"] == 4
    encoded = json.dumps(report, sort_keys=True)
    for forbidden in ("private_covariance", "raw_vector", "seed_material"):
        assert forbidden not in encoded


def test_sampling_budget_keeps_unknown_terms_unknown():
    sampling = screen()["sampling"]
    assert sampling["modeled_total_tv_upper"] is None
    assert sampling["modeled_total_tv_certified"] is False
    assert sampling["abort_terms"]["sign_entropy_abort_upper"] is None
    assert sampling["draw_counts"]["sign_total_scalar_draws"] > 0
    assert sampling["operation_budgets"]["identity_issuance_retry_policy"] == (
        "none after pending/failed; fixed service blocks reselection")


def test_kyber_nist_comparison_is_reference_only_and_type_safe():
    reference = screen()["kyber_nist_reference"]
    assert reference == KYBER_NIST_REFERENCE
    assert reference["standard"] == "NIST FIPS 203"
    assert reference["primitive_type"] == "KEM"
    assert reference["comparison_status"] == "reference-only"
    assert reference["security_categories"] == [1, 3, 5]
    assert any("not an SRGG security level" in item for item in reference["non_equivalence"])


@pytest.mark.parametrize("kwargs", [
    {"identity_bytes": 0}, {"identity_bytes": Config().identity_max_bytes + 1},
    {"message_bytes": 0}, {"issuer_users": Config().max_users + 1},
])
def test_capacity_overrides_are_bounded(kwargs):
    with pytest.raises(ValueError):
        screen(**kwargs)


def test_candidate_snapshot_changes_with_component_config_only():
    candidate = Config(degree=8, rank=1, p=257, base=31, digits=3,
                       master_first_squared=2**31, master_second_squared=2**31,
                       signature_first_squared=2**38, signature_second_squared=2**38,
                       user_norm_squared=2**31)
    report = screen(candidate)
    assert report["parameters"]["degree"] == 8
    assert report["derived_layout"]["Q"] == 257 * 31**3
    assert report["capacity"]["hibe_capacity_unselected"] is True
    assert report["security_claim"] == "none"
