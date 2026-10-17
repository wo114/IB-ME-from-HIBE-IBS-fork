"""Conditional large-dimension arithmetic, separate from backend admission."""

from dataclasses import replace
from fractions import Fraction

import pytest

from experiments.research.candidates.srgg.algebra import Params
from experiments.research.candidates.srgg.formal_candidates import (
    Candidate, build_report, conditional_candidate, geometry_bounds,
    resource_model, screen_candidate, search_gadget_digits, smoothing_certificate,
)
from experiments.research.candidates.srgg.geometry import (
    Widths, master_geometry, signature_geometry,
)


def test_large_candidates_are_calculated_without_relaxing_runtime_config():
    report = build_report()
    assert [c["parameters"]["rank"] for c in report["conditional_candidates"]] == [2, 3, 4]
    for candidate in report["conditional_candidates"]:
        assert candidate["parameters"]["degree"] == 512
        assert candidate["conditional_arithmetic_candidate"] is True
        assert candidate["security_claim"] == "none"
        assert candidate["parameters_are_formal"] is False
        assert candidate["backend_admitted"] is False
        assert candidate["nist_security_category"] is None
        assert candidate["generic_recovery_projection"]["classical_attack_bits"] is None
        assert candidate["generic_recovery_projection"]["estimator_validated"] is False
        resources = candidate["resources"]
        assert resources["runtime_observations"]["within_dense_geometry_dimension_limit"] is False
        assert resources["runtime_observations"]["current_backend_executable"] is False
        assert resources["peak_memory_measurement"] is None
        assert resources["timing_measurement"] is None
    assert report["kyber_nist_comparison"]["nist_category_inferred"] is False


def test_original_table_rows_do_not_gain_admission_from_new_candidates():
    rows = build_report()["source_rows"]
    assert [row["rank"] for row in rows] == [2, 3, 4]
    for row in rows:
        assert row["Q"] == 15744063
        assert row["digits"] == 2
        assert row["literal_Q_gt_2_gamma"] is False
        assert row["literal_even_2Q_gt_2_gamma"] is False
        assert row["normalization_verified"] is False
        assert row["strong_signature_premise_verified"] is False
        assert row["parameters_are_formal"] is False


def test_finite_gadget_search_reports_failures_without_claiming_security_optimum():
    search = search_gadget_digits(rank=2, maximum_digits=8)
    assert search["first_passing_digits"] == 7
    for trial in search["trials"]:
        if trial["digits"] < 7:
            assert trial["arithmetic_passes"] is False
            assert "conditional_Q_gt_2_gamma_exact" in trial["failed_gates"]
    assert search_gadget_digits(rank=2, maximum_digits=6)["first_passing_digits"] is None


def test_insufficient_modulus_and_smoothing_are_rejected_as_study_candidates():
    candidate = conditional_candidate()
    too_small_modulus = replace(candidate, digits=2)
    assert geometry_bounds(too_small_modulus)["gates"]["conditional_Q_gt_2_gamma_exact"] is False
    assert screen_candidate(too_small_modulus)["conditional_arithmetic_candidate"] is False
    weak_rounding = replace(candidate, r_squared=1)
    assert screen_candidate(weak_rounding)["rounding_lattice_smoothing"][
        "sufficient_smoothing_condition_passes"] is False
    assert screen_candidate(weak_rounding)["conditional_arithmetic_candidate"] is False


def test_smoothing_rational_bound_covers_finite_theta_polynomial():
    dimension, squared = 7, 3
    certificate = smoothing_certificate(dimension, squared, 1)
    a = Fraction(1, 2**(2*squared))
    # Independent finite lower approximation to theta(a)^D-1. The function's
    # bound covers the infinite geometric majorant, rather than a float estimate.
    finite_mass = (1+2*sum(a**(k*k) for k in range(1, 9)))**dimension-1
    assert finite_mass <= Fraction(certificate["dual_gaussian_mass_upper"])
    assert certificate["sufficient_smoothing_condition_passes"] is True
    assert smoothing_certificate(10240, 1, 80)["dual_gaussian_mass_upper"] is None


def _small_candidate():
    # Conservative support bound for n=2,d=1,w=1 is ||[M(R);I]||^2 <= 9.
    # U=66 also covers raw cap=1 plus the unsigned p=5 HNF error bound.
    return Candidate("exact-small-check", 2, 1, 5, 3, 1, 4,
                     329, 329, 1069, 1069, 1, 66, 8*1069)


def test_sufficient_geometry_matches_actual_exact_shape_construction():
    candidate = _small_candidate()
    p = Params(degree=2, rank=1, p=5, base=3, digits=1)
    r = (((1, 1),), ((1, -1),))
    master = master_geometry(p, r, Widths(329, 329, 4))
    user = ((1, 1), (1, -1), (0, 1))
    signing = signature_geometry(p, user, Widths(1069, 1069, 4), noise_factor=2)
    assert all(pivot > 0 for pivot in master.shifted_pivots)
    assert all(pivot > 0 for pivot in signing.shifted_pivots)
    gates = geometry_bounds(candidate)["gates"]
    assert gates["master_residual_strictly_positive_sufficient"] is True
    assert gates["signature_residual_strictly_positive_sufficient"] is True
    assert gates["hnf_user_cap_covers_assumed_raw_cap"] is True
    resources = resource_model(candidate)
    for name, geometry in (("master_geometry", master), ("signature_geometry", signing)):
        modeled = resources[name]
        dimension = len(geometry.target)
        lower = len(geometry.center_operator[0])
        assert modeled["coefficient_dimension"] == dimension
        assert modeled["initial_stacked_gram_scalar_multiplications"] == dimension**2*lower
        assert modeled["full_shape_ldl_rational_updates"] == sum(
            sum(1 for _ in range(k, dimension))
            for i in range(dimension) for k in range(i+1, dimension))


def test_geometry_minimum_is_strict_and_unsigned_hnf_error_is_counted():
    candidate = _small_candidate()
    geometry = geometry_bounds(candidate)
    root_edge = replace(candidate, master_first_squared=geometry["master_minimum_width_squared_exclusive"])
    assert geometry_bounds(root_edge)["gates"]["master_residual_strictly_positive_sufficient"] is False
    signature_edge = replace(candidate, signature_second_squared=geometry[
        "signing_minimum_width_squared_exclusive"])
    assert geometry_bounds(signature_edge)["gates"]["signature_residual_strictly_positive_sufficient"] is False
    insufficient_hnf = replace(candidate, user_norm_squared_cap=65)
    assert geometry_bounds(insufficient_hnf)["gates"]["hnf_user_cap_covers_assumed_raw_cap"] is False


def test_resource_memory_scenarios_are_not_peak_estimates_or_wire_claims():
    resources = resource_model(conditional_candidate())
    signing = resources["signature_geometry"]
    assert signing["coefficient_dimension"] == 10752
    assert signing["single_dense_square_entries"] == 115605504
    assert signing["single_dense_matrix_payload_scenarios_bytes"]["64"] == 7398752256
    assert signing["module_square_coefficient_count"] == 225792
    assert signing["single_dense_square_entries"] // signing["module_square_coefficient_count"] == 512
    assert resources["runtime_observations"]["within_current_scalar_width_limit"] is False
    assert resources["hypothetical_fixed_width_component_payload_bytes"]["encoding_status"].startswith(
        "counting model only")


@pytest.mark.parametrize("overrides", [
    {"degree": 3}, {"degree": True}, {"rank": 0}, {"r_squared": 4097},
    {"p": 2**32}, {"master_first_squared": 1 << 4096},
])
def test_inputs_have_explicit_arithmetic_resource_bounds(overrides):
    with pytest.raises(ValueError):
        replace(_small_candidate(), **overrides)


def test_screen_requires_candidate_and_remains_json_serializable():
    import json

    with pytest.raises(TypeError):
        screen_candidate({})
    assert json.loads(json.dumps(build_report()))["security_claim"] == "none"


def test_response_count_matches_actual_schoolbook_calls_including_relation_check(monkeypatch):
    from experiments.research.candidates.srgg import algebra
    candidate = _small_candidate()
    p = Params(degree=2, rank=1, p=5, base=3, digits=1)
    zero = (0, 0)
    public = algebra.build_public(p, ((zero,),), ((zero,), (zero,)))
    original, calls = algebra.multiply, []
    def counted(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)
    monkeypatch.setattr(algebra, "multiply", counted)
    algebra.response_from_values(public, (zero,), (zero,)*p.columns,
                                 (zero,)*(p.columns+1), zero, zero)
    modeled = resource_model(candidate)["schoolbook_ring_arithmetic"]
    assert len(calls) == modeled["response_total_ring_products"]
