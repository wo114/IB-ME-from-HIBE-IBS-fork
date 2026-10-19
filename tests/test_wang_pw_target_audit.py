"""Numerical screens must not promote one sample or a budget into admission."""

import json
import math

import pytest

from ibme.ibs.wang_pw_target.parameter_audit import GIB, audit
from ibme.ibs.wang_pw_target.params import TARGET_PROFILE, small_params


def test_default_target_bounds_and_sis_dimension_are_not_sample_estimates():
    result = audit(TARGET_PROFILE)
    assert result["dimensions"]["m"] == 32768 and result["dimensions"]["M"] == 49152
    assert result["dimensions"]["q"] == 4294967291
    assert not result["dimensions"]["q_is_2_to_32"]
    assert math.isclose(result["gaussian_widths"]["root_sigma"], 4/math.sqrt(2*math.pi))
    assert result["paper_sis"]["instance_m"] == 32768
    assert result["paper_sis"]["beta"] is None
    envelope = result["paper_sis"]["configured_reference_envelope"]
    assert envelope["optimistic_beta"] >= TARGET_PROFILE.q
    assert envelope["trivial_q_multiple"] is True
    assert result["paper_sis"]["formal_status"] == "rejected_configured_reference_envelope"
    assert result["signature_public_bound"]["bound_less_than_q"] is True
    assert result["security_claim"] == "none" and result["parameters_are_formal"] is False
    json.dumps(result, allow_nan=False)


def test_measurements_cannot_substitute_for_uniform_bounds_or_certification():
    result = audit(TARGET_PROFILE, {"sign_norm": 130978.66, "quantum_bits": 153.70, "peak_rss_bytes": 96*GIB})
    assert result["paper_sis"]["beta"] is None
    assert result["observations"]["sign_norm"] == 130978.66
    assert result["archived_sample_costs_not_used_as_admission"]["quantum_bits"] == 153.70
    assert result["parameters_are_formal"] is False
    assert result["nist_security_category"] is None
    assert result["resources"]["target_memory_acceptance"] is True
    assert result["finite_sampler_diagnostics"]["total_tv_bound"] is None
    assert result["finite_sampler_diagnostics"]["gs_bound_certified"] is False


def test_uniform_bound_mapping_is_exact_and_trivial_sis_is_reported():
    p = small_params()
    result = audit(p, {"uniform_bounds": {"reference_norm_bound": 1, "simulation_spectral_bound": 1, "source": "test fixture bounds, not certified"}})
    mapping = result["paper_sis"]["provided_bound_mapping"]
    expected = (p.verify_bound_ceil + 1)**2 * 2
    assert mapping["length_bound"]**2 >= expected
    assert (mapping["length_bound"]-1)**2 < expected
    assert mapping["trivial_q_multiple"] is True
    assert result["paper_sis"]["formal_status"] == "rejected_trivial_sis"
    assert mapping["bound_source_verified_by_audit"] is False
    incomplete = audit(p, {"uniform_bounds": {"reference_norm_bound": 1}})
    assert incomplete["paper_sis"]["beta"] is None
    tight_debug = small_params(q=4294967291, user_gs_limit=16)
    finite = audit(tight_debug, {"uniform_bounds": {"reference_norm_bound": 1, "simulation_spectral_bound": 1, "source": "synthetic bounds for mapping test"}})
    assert finite["paper_sis"]["beta"] < tight_debug.q
    assert finite["paper_sis"]["formal_status"] == "unadmitted_caller_bounds_require_review"
    assert finite["parameters_are_formal"] is False


def test_wire_memory_planning_does_not_count_as_peak_measurement():
    p = TARGET_PROFILE
    result = audit(p)
    resource = result["resources"]
    assert resource["wire_bytes"]["signature"] == 393320
    assert resource["dense_user_basis_bytes"] == 18*GIB
    assert resource["dense_root_basis_bytes"] == 8*GIB
    assert resource["planning_five_user_square_arrays_bytes"] == 90*GIB
    assert resource["planning_is_a_measured_peak"] is False
    assert resource["measured_peak_rss_bytes"] is None
    assert resource["target_memory_acceptance"] is False
    assert audit(p, {"peak_rss_bytes": 128*GIB})["resources"]["measured_under_128gib"] is False
    assert audit(p, {"peak_rss_bytes": 128*GIB-1})["resources"]["measured_under_128gib"] is True
    assert audit(small_params(), {"peak_rss_bytes": GIB})["resources"]["target_memory_acceptance"] is False


def test_finite_diagnostics_are_scaled_and_explicitly_not_total_tv():
    result = audit(TARGET_PROFILE)
    dg = result["finite_sampler_diagnostics"]
    p = TARGET_PROFILE
    assert dg["one_attempt_lifecycle_coordinate_count"] == p.m_bar*p.w+p.m*p.w+p.dimension
    assert 0 < dg["continuous_normal_two_sided_tail_reference"] < 2**-290
    assert 0 < dg["sum_floor_weight_loss_envelope_diagnostic"] < 2**-149
    assert dg["total_tv_bound"] is None and dg["abort_probability_bound"] is None
    assert dg["continuous_tail_is_discrete_or_gpv_tv_bound"] is False
    assert result["estimator"]["executed"] is False
    assert result["estimator"]["automatic_download"] is False


@pytest.mark.parametrize("measured", [
    [], {"peak_rss_bytes": 0}, {"peak_rss_bytes": True}, {"sign_norm": float("nan")},
    {"uniform_bounds": {"reference_norm_bound": 0}},
    {"uniform_bounds": {"simulation_spectral_bound": True}},
    {"uniform_bounds": {"source": ""}}, {"uniform_bounds": {"sign_norm": 123}},
])
def test_bad_measurement_and_uniform_bound_inputs_are_rejected(measured):
    with pytest.raises((ValueError, TypeError)):
        audit(TARGET_PROFILE, measured)
