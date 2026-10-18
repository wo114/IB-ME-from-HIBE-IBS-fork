"""One bounded product-normalizer alternative for SRGG literal width."""

from fractions import Fraction

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

from experiments.research.candidates.srgg.paper_parameters import PaperParams
from experiments.research.candidates.srgg.paper_schur_literal_fallback import (
    coordinate_product_tilt_bound, literal_product_certificate,
)


def test_product_tilt_bound_rounds_up_without_losing_the_exact_inequality():
    t = Fraction(1, 16)
    complement, tv = coordinate_product_tilt_bound(
        dimension=3, scalar_theta_upper=t, dyadic_bits=64)
    exact_complement = Fraction(15, 17)**3
    assert 0 <= complement <= exact_complement
    assert exact_complement-complement < Fraction(1, 2**64)
    assert tv == 1-complement
    assert tv >= 1-exact_complement
    assert coordinate_product_tilt_bound(
        dimension=512, scalar_theta_upper=Fraction(0)) == (Fraction(1), Fraction(0))


def test_likelihood_ratio_step_on_exact_two_point_tilts():
    for t in (Fraction(1, 64), Fraction(1, 8)):
        for dimension in (1, 3, 8):
            lower, upper = (1-t)**dimension, (1+t)**dimension
            certified_complement, certified_tv = coordinate_product_tilt_bound(
                dimension=dimension, scalar_theta_upper=t)
            for mass in (Fraction(1, 10), Fraction(1, 2), Fraction(9, 10)):
                mean = mass*lower+(1-mass)*upper
                tilted_first_mass = mass*lower/mean
                actual_tv = abs(mass-tilted_first_mass)
                assert actual_tv <= certified_tv
                assert certified_complement <= lower/upper


@pytest.mark.parametrize("name,rank", (("PARAM-I", 2), ("PARAM-II", 3), ("PARAM-III", 4)))
def test_original_literal_table4_rows_leave_no_nontrivial_chain_tv(name, rank):
    params = PaperParams(name, "literal-density-width")
    assert params.degree == 512
    assert params.r_squared == Fraction(841, 625)
    for leaves in (2*rank, params.columns):
        result = literal_product_certificate(
            degree=params.degree, upper_polynomials=leaves,
            rounding_squared=params.r_squared)
        t = Fraction(result["scalar_theta_upper_exact"])
        leaf = Fraction(result["mathematical_single_leaf_tv_upper_dyadic_exact"])
        assert 0 < t < 1
        assert Fraction(1, 4) < leaf < 1
        assert result["mathematical_algorithm34_to_ideal_sequential_discrete_tv_upper_exact"] == "1"
        assert not result["whole_chain_bound_nontrivial"]
        assert "actual TV remains unknown" in result["blocker"]
        assert result["finite_to_mathematical_algorithm34_tv_upper"] is None
        assert result["full_ibs_tv_upper"] is None
        assert result["security_claim"] == "none"
        assert result["nist_security_category"] is None


def test_small_dimension_bound_is_not_hardcoded_to_one():
    result = literal_product_certificate(
        degree=2, upper_polynomials=4, rounding_squared=Fraction(9))
    assert result["whole_chain_bound_nontrivial"]
    assert Fraction(result["mathematical_algorithm34_to_ideal_sequential_discrete_tv_upper_exact"]) < 1


def test_all_adaptive_chain_lengths_four_through_sixteen_are_trivial():
    shape = PaperParams("PARAM-I", "literal-density-width").r_squared
    for leaves in range(4, 17):
        result = literal_product_certificate(
            degree=512, upper_polynomials=leaves, rounding_squared=shape)
        assert result["mathematical_algorithm34_to_ideal_sequential_discrete_tv_upper_exact"] == "1"
        assert not result["whole_chain_bound_nontrivial"]


@pytest.mark.parametrize("input", (
    {"dimension": True, "scalar_theta_upper": Fraction(1, 2)},
    {"dimension": 513, "scalar_theta_upper": Fraction(1, 2)},
    {"dimension": 1, "scalar_theta_upper": 0.1},
    {"dimension": 1, "scalar_theta_upper": Fraction(1)},
    {"dimension": 1, "scalar_theta_upper": Fraction(-1, 2)},
    {"dimension": 1, "scalar_theta_upper": Fraction(1, 2), "dyadic_bits": 63},
))
def test_resource_and_type_gates(input):
    with pytest.raises(ValueError):
        coordinate_product_tilt_bound(**input)
