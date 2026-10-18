"""Convolution identity, all-center tilt, and original Table 4 branches."""
from fractions import Fraction

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")
from sage.all import QQ, matrix, vector

from experiments.research.candidates.srgg.paper_parameters import PaperParams
from experiments.research.candidates.srgg.paper_schur_convolution import (
    chain_convolution_certificate, convolution_tilt_tv_upper,
)


def test_likelihood_ratio_bound_on_independent_finite_probability_models():
    # Algebraic two-point models test the reweighting step independently of
    # Sage's theta implementation. Marginalization can only decrease TV.
    for epsilon in (Fraction(0), Fraction(1, 100), Fraction(1, 4)):
        lower, upper = 1-epsilon, 1+epsilon
        for mass in (Fraction(1, 10), Fraction(1, 2), Fraction(9, 10)):
            mean = mass*lower+(1-mass)*upper
            tilted = mass*lower/mean
            tv = abs(mass-tilted)
            assert tv <= convolution_tilt_tv_upper(epsilon)


def test_exact_anisotropic_gaussian_completion_underlying_convolution():
    # The Schur pivot need not be diagonal. Verify the identity used before
    # normalization with exact rational arithmetic in a two-coordinate case.
    pivot = matrix(QQ, [[5, 1], [1, 4]])
    rounding = matrix.identity(QQ, 2)
    continuous = pivot-rounding
    center = vector(QQ, [QQ(1)/3, -QQ(1)/4])
    integer = vector(QQ, [2, -1])
    real = vector(QQ, [QQ(1)/7, QQ(2)/5])
    precision = continuous.inverse()+rounding.inverse()
    posterior_center = precision.inverse()*(continuous.inverse()*center+rounding.inverse()*integer)
    original_exponent = ((real-center)*continuous.inverse()*(real-center)
                         +(integer-real)*rounding.inverse()*(integer-real))
    factored_exponent = ((integer-center)*pivot.inverse()*(integer-center)
                         +(real-posterior_center)*precision*(real-posterior_center))
    assert original_exponent == factored_exponent
    assert 1/(continuous.det()*precision.det()) == rounding.det()/pivot.det()


@pytest.mark.parametrize("name", ("PARAM-I", "PARAM-II", "PARAM-III"))
def test_original_table4_standard_deviation_interpretation_closes_local_bridge(name):
    params = PaperParams(name)
    before = params.record(), params.r_squared
    for leaves in (2*params.rank, params.columns):
        result = chain_convolution_certificate(
            degree=params.degree,
            upper_polynomials=leaves,
            rounding_squared=params.r_squared,
            ideal_pivot_lower=Fraction(64),
        )
        assert result["positive_continuous_covariance"]
        assert result["theta_certificate"]["all_centers"]
        assert result["theta_certificate"]["density_shape_lower_exact"] == str(params.r_squared)
        assert 0 < Fraction(result["mathematical_single_leaf_tv_upper_exact"]) < Fraction(1, 2**20)
        assert 0 < Fraction(result["mathematical_algorithm34_to_ideal_sequential_discrete_tv_upper_exact"]) < Fraction(1, 2**16)
        assert result["finite_to_mathematical_algorithm34_tv_upper"] is None
        assert result["ideal_sequential_vs_joint_integer_tv_upper"] is None
        assert not result["all_accepted_setup_roots_covered"]
        assert result["security_claim"] == "none" and not result["parameters_are_formal"]
    assert (params.record(), params.r_squared) == before


@pytest.mark.parametrize("name", ("PARAM-I", "PARAM-II", "PARAM-III"))
def test_literal_density_width_keeps_actual_tv_unknown(name):
    params = PaperParams(name, "literal-density-width")
    result = chain_convolution_certificate(
        degree=params.degree,
        upper_polynomials=params.columns,
        rounding_squared=params.r_squared,
        ideal_pivot_lower=Fraction(64),
    )
    assert result["theta_certificate"]["relative_normalizer_error_upper_exact"] is None
    assert result["mathematical_single_leaf_tv_upper_exact"] is None
    assert result["mathematical_algorithm34_to_ideal_sequential_discrete_tv_upper_exact"] is None
    assert "inconclusive" in result["blocker"]


def test_pivot_floor_and_input_gates_do_not_invent_a_certificate():
    row = chain_convolution_certificate(
        degree=4, upper_polynomials=2, rounding_squared=Fraction(9),
        ideal_pivot_lower=Fraction(9))
    assert not row["positive_continuous_covariance"]
    assert row["theta_certificate"] is None
    assert row["mathematical_algorithm34_to_ideal_sequential_discrete_tv_upper_exact"] is None
    for invalid in (Fraction(-1), Fraction(1), 1, 0.5, True):
        with pytest.raises(ValueError):
            convolution_tilt_tv_upper(invalid)
    with pytest.raises(ValueError):
        chain_convolution_certificate(degree=True, upper_polynomials=2,
                                      rounding_squared=Fraction(9), ideal_pivot_lower=Fraction(64))


def test_adaptive_chain_bound_caps_at_one_without_claiming_joint_reference():
    row = chain_convolution_certificate(
        degree=1, upper_polynomials=16, rounding_squared=Fraction(1),
        ideal_pivot_lower=Fraction(64))
    assert row["relative_all_center_normalizer_error_upper_exact"] is not None
    assert row["mathematical_algorithm34_to_ideal_sequential_discrete_tv_upper_exact"] == "1"
    assert row["ideal_sequential_vs_joint_integer_tv_upper"] is None
