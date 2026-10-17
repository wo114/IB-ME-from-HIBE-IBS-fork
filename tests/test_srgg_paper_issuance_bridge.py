"""Independent dense algebra and exact two-point checks for issuance bridge."""
from fractions import Fraction

import pytest

sage = pytest.importorskip("sage.all")
from sage.all import QQ, identity_matrix, matrix

from experiments.research.candidates.srgg.paper_issuance_bridge import (
    combine_issuance_tv, fixed_root_c_gate, issuance_certificate,
)
from experiments.research.candidates.srgg.structured_geometry import StructuredGeometry


def geometry():
    return StructuredGeometry(2, (((1, -1),),), (64,), 48, 9, 1)


def test_fourier_c_gate_matches_independent_exact_dense_matrix():
    # Multiplication by 1-X modulo X^2+1, independently expanded by hand.
    r = matrix(QQ, [[1, 1], [-1, 1]])
    t = r.stack(identity_matrix(QQ, 2))
    sigma_inverse = matrix.diagonal(QQ, [QQ(1)/64]*2+[QQ(1)/48]*2)
    c = 9*identity_matrix(QQ, 2)-81*t.transpose()*sigma_inverse*t
    assert c == (QQ(153)/32)*identity_matrix(QQ, 2)
    assert (c-4*identity_matrix(QQ, 2)).is_positive_definite()
    assert not (c-5*identity_matrix(QQ, 2)).is_positive_definite()
    passing = fixed_root_c_gate(geometry(), lower_bound=4)
    failing = fixed_root_c_gate(geometry(), lower_bound=5)
    assert passing["certified"] and passing["all_fourier_blocks_checked"]
    assert not failing["certified"]
    assert passing["root_redraws"] == failing["root_redraws"] == 0
    assert not passing["private_spectra_and_witness_exported"]


def test_completed_square_and_center_equal_independent_dense_formula():
    r = matrix(QQ, [[1, 1], [-1, 1]])
    t = r.stack(identity_matrix(QQ, 2))
    sigma = matrix.diagonal(QQ, [64, 64, 48, 48])
    sp = sigma-9*t*t.transpose()
    c = ((QQ(1)/9)*identity_matrix(QQ, 2)+t.transpose()*sp.inverse()*t).inverse()
    assert c == 9*identity_matrix(QQ, 2)-81*t.transpose()*sigma.inverse()*t
    assert c*t.transpose()*sp.inverse() == 9*t.transpose()*sigma.inverse()
    u, x = matrix(QQ, 4, 1, [1, 2, -3, 5]), matrix(QQ, 2, 1, [2, -1])
    mu = 9*t.transpose()*sigma.inverse()*u
    assert not mu.is_zero()
    left = ((u-t*x).transpose()*sp.inverse()*(u-t*x)+x.transpose()*x/9)[0, 0]
    right = (u.transpose()*sigma.inverse()*u+(x-mu).transpose()*c.inverse()*(x-mu))[0, 0]
    assert left == right


def test_one_denominator_cost_attains_exact_two_point_tv():
    x = Fraction(1, 8)
    low, high = 1-x, 1/(1-x)
    p_high = (1-low)/(high-low)
    # Probability measure tilted by the product normalizer; mean weight=1.
    assert p_high*high+(1-p_high)*low == 1
    actual_tv = p_high*(high-1)
    result = combine_issuance_tv(perturbation_tv=0, gadget_scalar_tv=0,
                               digit_relative_sum=x, center_relative_error=0)
    assert actual_tv == Fraction(result["denominator_removal_tv_upper"]) == x/(2-x)
    assert Fraction(result["complete_law_tv_upper_including_abort"]) == actual_tv


def test_triangle_composition_preserves_abort_and_never_conditions_it_away():
    result = combine_issuance_tv(perturbation_tv=Fraction(1, 128),
        gadget_scalar_tv=Fraction(1, 256), digit_relative_sum=Fraction(1, 32),
        center_relative_error=Fraction(1, 64))
    expected = Fraction(1, 128)+Fraction(1, 256)+Fraction(1, 63)+Fraction(1, 63)
    assert Fraction(result["complete_law_tv_upper_including_abort"]) == expected
    assert combine_issuance_tv(perturbation_tv=1, gadget_scalar_tv=1,
        digit_relative_sum=0, center_relative_error=0)["complete_law_tv_upper_including_abort"] == "1"


@pytest.mark.parametrize("x,epsilon", [(1, 0), (2, 0), (0, 1), (0, 2), (0, None)])
def test_inconclusive_gate_keeps_bound_absent(x, epsilon):
    result = combine_issuance_tv(perturbation_tv=0, gadget_scalar_tv=0,
                               digit_relative_sum=x, center_relative_error=epsilon)
    assert not result["certified"] and result["complete_law_tv_upper_including_abort"] is None


@pytest.mark.parametrize("arguments", [
    {"perturbation_tv": True}, {"gadget_scalar_tv": 1.0}, {"perturbation_tv": -1},
    {"gadget_scalar_tv": 2}, {"digit_relative_sum": -1}, {"center_relative_error": -1},
    {"digit_relative_sum": "1/8"}, {"center_relative_error": Fraction(1, 2**32769)},
])
def test_composition_type_and_resource_rejection(arguments):
    kwargs = dict(perturbation_tv=0, gadget_scalar_tv=0, digit_relative_sum=0,
                  center_relative_error=0)
    kwargs.update(arguments)
    with pytest.raises(ValueError):
        combine_issuance_tv(**kwargs)


@pytest.mark.parametrize("arguments", [{"lower_bound": True}, {"lower_bound": 0},
    {"lower_bound": 1025}, {"lower_bound": 1.0}, {"precision_bits": True},
    {"precision_bits": 127}, {"precision_bits": 2049}])
def test_c_gate_type_and_resource_rejection(arguments):
    with pytest.raises(ValueError):
        fixed_root_c_gate(geometry(), **arguments)


def test_bound_above_noise_is_not_a_root_rejection():
    result = fixed_root_c_gate(geometry(), lower_bound=10)
    assert not result["certified"] and not result["all_fourier_blocks_checked"]
    assert result["root_redraws"] == result["sampler_draws"] == 0
    with pytest.raises(ValueError):
        fixed_root_c_gate(object())
    with pytest.raises(ValueError):
        issuance_certificate(None, None, None)
