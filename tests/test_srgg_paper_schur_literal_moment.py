"""Directed Fourier-moment certificate for the literal SRGG Schur branch."""

from fractions import Fraction

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

from experiments.research.candidates.srgg.paper_parameters import PaperParams
from experiments.research.candidates.srgg.paper_schur_literal_moment import (
    moment_chain_certificate,
)


@pytest.mark.parametrize("name,leaves", (
    ("PARAM-I", 4), ("PARAM-I", 8),
    ("PARAM-II", 6), ("PARAM-II", 12),
    ("PARAM-III", 8), ("PARAM-III", 16),
))
def test_original_literal_table4_fixed_root_premise_gives_rational_nontrivial_chain(name, leaves):
    params = PaperParams(name, "literal-density-width")
    assert params.degree == 512 and params.r_squared == Fraction(841, 625)
    row = moment_chain_certificate(
        degree=params.degree, upper_polynomials=leaves,
        rounding_squared=params.r_squared, ideal_pivot_lower=Fraction(64))
    leaf = Fraction(row["mathematical_single_leaf_tv_upper_exact"])
    chain = Fraction(row["mathematical_algorithm34_to_ideal_sequential_discrete_tv_upper_exact"])
    assert 0 < leaf < Fraction(1, 4)
    assert chain == 1-(1-leaf)**leaves < 1
    assert row["single_leaf_strictly_below_one_quarter"]
    assert row["whole_chain_bound_nontrivial"]
    assert row["positive_continuous_covariance"]
    assert row["fixed_root_pivot_floor_authenticated_here"] is False
    assert not row["all_accepted_setup_roots_covered"]
    assert row["finite_to_mathematical_algorithm34_tv_upper"] is None
    assert row["full_ibs_tv_upper"] is None
    assert row["security_claim"] == "none"
    assert row["nist_security_category"] is None


def test_directed_endpoints_dominate_the_exact_moment_formula():
    row = moment_chain_certificate(
        degree=512, upper_polynomials=4,
        rounding_squared=Fraction(841, 625), ideal_pivot_lower=Fraction(64))
    t1 = Fraction(row["scalar_theta_rounding_upper_exact"])
    t2 = Fraction(row["scalar_theta_squared_rounding_upper_exact"])
    tf = Fraction(row["scalar_theta_pivot_floor_upper_exact"])
    a_cont = Fraction(row["exp_minus_pi_continuous_floor_upper_exact"])
    delta = Fraction(row["mean_offset_upper_exact"])
    moment = Fraction(row["moment_second_upper_exact"])
    leaf = Fraction(row["mathematical_single_leaf_tv_upper_exact"])
    assert delta >= (1+tf)**512-1
    assert moment >= (1+t2)**512-1+a_cont*((1+t1)**512-1)**2
    assert 0 <= delta < 1 and 0 <= moment < Fraction(1, 4)
    assert (2*leaf*(1-delta))**2 >= moment


def test_finite_two_point_tilts_obey_the_likelihood_ratio_moment_step():
    # The Cauchy-Schwarz step itself is checked independently of Gaussian
    # evaluation: a positive reweighting W changes a two-point distribution.
    for p in (Fraction(1, 10), Fraction(1, 2), Fraction(9, 10)):
        for low, high in ((Fraction(1, 2), Fraction(3, 2)),
                          (Fraction(9, 10), Fraction(11, 10))):
            mean = p*low+(1-p)*high
            second = p*(low-1)**2+(1-p)*(high-1)**2
            tv = abs(p-p*low/mean)
            assert tv**2 <= second/(4*mean**2)


def test_pivot_premise_and_input_gates_are_explicit():
    blocked = moment_chain_certificate(
        degree=512, upper_polynomials=4,
        rounding_squared=Fraction(841, 625), ideal_pivot_lower=Fraction(1))
    assert blocked["mathematical_single_leaf_tv_upper_exact"] is None
    assert not blocked["positive_continuous_covariance"]
    assert "pivot floor" in blocked["blocker"]
    for kwargs in (
        {"degree": True, "upper_polynomials": 4, "rounding_squared": Fraction(841, 625), "ideal_pivot_lower": Fraction(64)},
        {"degree": 513, "upper_polynomials": 4, "rounding_squared": Fraction(841, 625), "ideal_pivot_lower": Fraction(64)},
        {"degree": 512, "upper_polynomials": 17, "rounding_squared": Fraction(841, 625), "ideal_pivot_lower": Fraction(64)},
        {"degree": 512, "upper_polynomials": 4, "rounding_squared": 1.3456, "ideal_pivot_lower": Fraction(64)},
        {"degree": 512, "upper_polynomials": 4, "rounding_squared": Fraction(841, 625), "ideal_pivot_lower": Fraction(64), "precision_bits": 128},
    ):
        with pytest.raises(ValueError):
            moment_chain_certificate(**kwargs)
