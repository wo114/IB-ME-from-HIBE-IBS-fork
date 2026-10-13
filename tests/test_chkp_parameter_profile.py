"""Public CHKP profile admission rejects changed or dishonest declarations."""

from copy import deepcopy
from fractions import Fraction

import pytest

from experiments.research.chkp_parameter_profile import (
    check_profile, root_parameters, selected_profile,
)
from experiments.research.ibme_joint_parameters import evaluate_noise


def test_profile_matches_independent_noise_checker():
    p = selected_profile()
    checked = check_profile(p)
    independent = evaluate_noise(q=p["q"], dimension=p["leaf_dimension"],
        width_squared=p["leaf_width_squared"],
        alpha=Fraction(p["alpha_numerator"], p["alpha_denominator"]),
        error_bits=p["error_bits"], seed_bits=p["seed_bits"],
        encapsulations=p["encapsulation_budget"])
    assert independent["conditional_noise_sufficient"]
    assert independent["conditional_lifetime_failure_upper"] == checked["conditional_lifetime_error_upper"]
    assert independent["continuous_margin"] == checked["conditional_continuous_margin"]
    assert independent["continuous_squared_upper"] == str(checked["conditional_continuous_squared_upper"])
    assert checked["worst_entropy_bytes"]["chain"] <= p["chain_entropy_budget"]
    assert checked["actual_geometry_or_sampling_checked"] is False


@pytest.mark.parametrize("field,value", [
    ("n", True), ("q", 1099511627790), ("m_bar", 44),
    ("r_width_squared", 1), ("root_radius", 170),
    ("root_gs_squared_bound", 1), ("parent_width_squared", 1),
    ("parent_gs_squared_bound", 1), ("leaf_width_squared", 1),
    ("root_mass_lower", "32"), ("regularity_bits", 128),
    ("parent_max_vectors", 254), ("alpha_numerator", 0),
    ("alpha_denominator", 1), ("seed_bits", 32),
    ("chain_entropy_budget", 2**20), ("max_dimension", 128),
    ("security_claim", "128 bits"), ("backend_admitted", True),
    ("parameters_are_formal", True), ("geometry_and_sampling_executed", True),
])
def test_profile_mutations_are_rejected(field, value):
    p = selected_profile()
    p[field] = value
    with pytest.raises(ValueError):
        check_profile(p)


def test_options_copy_and_constructor_field_boundary():
    p = selected_profile()
    p["finite_options"]["max_gaussian_trials"] = 1
    assert selected_profile()["finite_options"]["max_gaussian_trials"] == 2048
    with pytest.raises(ValueError):
        root_parameters(p)
    kwargs = root_parameters()
    assert "security_claim" not in kwargs
    assert "backend_admitted" not in kwargs
    assert kwargs["max_entropy_bytes"] == 2**34


def test_schema_does_not_accept_extra_fields():
    p = deepcopy(selected_profile())
    p["actual_security_bits"] = 128
    with pytest.raises(ValueError):
        check_profile(p)


def test_finite_root_mass_and_width_preflight_without_entropy():
    pytest.importorskip("sage.all")
    from experiments.research.chkp_parameter_profile import check_finite_profile
    report = check_finite_profile()
    assert report["root_mass_floor_pass"]
    assert report["random_bytes_consumed"] == 0
    assert report["root_generated"] is False
    assert report["actual_geometry_or_sampling_checked"] is False
    assert len(report["scalar_profiles"]) == 7
