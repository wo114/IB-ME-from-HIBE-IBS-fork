"""Public-boundary tests for the HIBE-independent SRGG parameter screen."""

import json

import pytest

from experiments.research.candidates.srgg.config import Config
from experiments.research.candidates.srgg.backend import message
from experiments.research.candidates.srgg.objects import PublicKey, Signature
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


def test_quantization_and_continuous_errors_have_no_invented_bit_bound():
    sampling = screen()["sampling"]
    for section in ("scalar_sampler", "gadget_sampler"):
        certificate = sampling[section]
        assert certificate["certified"] is False
        assert certificate["tail_target_bits"] > 0
        assert certificate["mass_quantization_tv_upper"] is None
        assert certificate["tail_upper"] is None
        assert certificate["open_obligations"]
        assert not any("upper_model" in key for key in certificate)
    assert sampling["scalar_sampler"]["continuous_stage_tv_upper"] is None
    assert sampling["scalar_sampler"]["real_precision_error_upper"] is None
    assert sampling["gadget_sampler"]["partition_bias_tv_upper"] is None


def test_sampling_counts_distinguish_u_gaussian_and_continuous_tickets():
    sampling = screen()["sampling"]
    counts = sampling["draw_counts"]
    # Default Alg3: extraction has 2d upper + wd lower polynomials;
    # signing has (2+w)d upper + one lower, followed by the Gaussian u.
    assert counts["key_extraction_geometry_scalar_draws"] == 40
    assert counts["key_extraction_gadget_scalar_draws"] == 24
    assert counts["key_extraction_continuous_normal_tickets"] == 16
    assert counts["sign_geometry_scalar_draws"] == 48
    assert counts["sign_u_gaussian_scalar_draws"] == 8
    assert counts["sign_total_scalar_draws"] == 56
    assert counts["sign_continuous_normal_tickets"] == 40
    assert counts["sign_max_total_scalar_draws"] == Config().sign_max_attempts * 56
    assert counts["sign_max_continuous_normal_tickets"] == Config().sign_max_attempts * 40
    assert "sign_uniform_scalar_draws" not in counts
    assert sampling["abort_terms"]["setup_norm_rejection_upper"] == 0
    assert sampling["operation_budgets"]["setup_actual_root_draw_attempts_max"] == 1
    assert sampling["operation_budgets"]["setup_norm_rejection_implemented"] is False


def test_wire_fixtures_match_real_encoders_without_inventing_packed_lower_bounds():
    config = Config()
    p = config.algebra
    public = PublicKey(config, b"\0" * 32, tuple(
        tuple((0,) * p.degree for _ in range(p.rank * p.digits)) for _ in range(p.rank)))
    signature = Signature(b"\0" * 32, tuple(
        (0,) * p.degree for _ in range(p.columns + 1)), (0,) * p.degree)
    report = screen(config)
    wire = report["wire"]
    assert wire["public_key_reference_bytes"] == len(public.to_bytes())
    assert wire["signature_reference_bytes"] == len(signature.to_bytes())
    assert wire["packed_encoding_bytes"] is None
    assert wire["all_admitted_objects_within_wire_limit"] is None
    assert "packed_lower_bounds_bytes" not in wire
    inventory = wire["coefficient_inventory"]
    assert inventory["public_key"]["b_coefficients"] == sum(
        len(poly) for row in public.b for poly in row)
    assert inventory["signature"]["response_coefficients"] == sum(map(len, signature.z))
    assert inventory["signing_key"]["stored_tail_coefficients"] == 32
    assert inventory["signing_key"]["reconstructed_vector_coefficients"] == 40
    assert inventory["master_secret_empty"]["coefficient_support"] == [-1, 0, 1]


def test_exact_modulus_gate_accepts_integer_square_boundary():
    candidate = Config(signature_first_squared=305305888679,
                       signature_second_squared=305305888679)
    report = screen(candidate)["correctness"]
    q = candidate.algebra.modulus
    # Here ceil(sqrt(B)) would wrongly reject Q > 2*sqrt(B).
    assert q*q - 4*candidate.signature_bound_squared == 1
    assert q <= 2*report["derived"]["gamma_bound_ceiling"]
    assert report["gates"]["exact_Q_gt_2_gamma_bound"] is True
    assert report["all_component_gates_pass"] is True


def test_empty_message_capacity_matches_backend_acceptance():
    config = Config()
    assert message(config, b"") == b""
    assert screen(config, message_bytes=0)["capacity"]["message_max_bytes"] == 0


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
    {"message_bytes": -1}, {"message_bytes": Config().message_max_bytes + 1},
    {"message_bytes": False}, {"issuer_users": Config().max_users + 1},
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
