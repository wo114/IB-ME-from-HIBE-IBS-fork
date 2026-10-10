"""Exact positivity, Schur geometry and ring-adjoint boundary controls."""

from fractions import Fraction as F
import pytest

from experiments.research.candidates.srgg.algebra import Params, constant, zeta
from experiments.research.candidates.srgg.geometry import (
    Widths, combine, diagonal, master_geometry, module_operator, polynomial_operator,
    positive_pivots, product, rational, signature_geometry, transpose,
)


def simple_r(p):
    return tuple(tuple(constant(p, int(i == j)) for j in range(p.rank * p.digits)) for i in range(2 * p.rank))


def test_exact_ldl_boundary_and_nonsymmetric_controls():
    assert positive_pivots(((2, 1), (1, 2))) == (F(2), F(3, 2))
    for matrix in (((0, 0), (0, 1)), ((1, 1), (1, 1)), ((1, 2), (2, 1)), ((1, 2), (0, 1))):
        with pytest.raises(ValueError): positive_pivots(matrix)


@pytest.mark.parametrize("value", [True, 0.5, "NaN", F(0), -1])
def test_widths_reject_float_and_nonpositive_inputs(value):
    with pytest.raises(ValueError): Widths(value, 16, 1)


def test_rational_resources_are_bounded():
    with pytest.raises(ValueError): rational(1 << 8193)
    with pytest.raises(ValueError): positive_pivots(((1,),) * 129)
    with pytest.raises(ValueError): rational("1e999999999")
    with pytest.raises(ValueError): rational("1" * 8193)
    assert rational("0.25") == F(1, 4)


@pytest.mark.parametrize("factor", [True, 1.0, "1", 0, 3])
def test_noise_factor_is_an_explicit_integer_interpretation(factor):
    p = Params()
    y = (constant(p, 0),) * p.columns
    with pytest.raises(ValueError): signature_geometry(p, y, Widths(1024, 256, 1), noise_factor=factor)


def test_ring_transpose_requires_coefficient_adjoint():
    p = Params()
    f = (1, 2, -1, 0)
    conjugate = (1, 0, 1, -2)
    op = polynomial_operator(p, f)
    assert transpose(op) == polynomial_operator(p, conjugate)
    assert transpose(op) != op
    gram = product(op, transpose(op))
    assert gram == transpose(gram)
    assert product(op, op) != gram


@pytest.mark.parametrize("degree", [2, 4, 8])
def test_zeta_multiplication_shape_scale_is_two(degree):
    p = Params(degree=degree)
    op = polynomial_operator(p, zeta(p))
    assert product(op, transpose(op)) == diagonal((2,) * degree)


def test_master_conditional_geometry_uses_gadget_sigma_squared():
    p = Params(degree=2, digits=1)
    r = ((constant(p, 1),), (constant(p, 0),))
    result = master_geometry(p, r, Widths(25, 16, 1))
    assert result.noise_squared == 9 and result.lower_scalar == 7
    assert result.center_operator == ((F(-9, 7), F(0)), (F(0), F(-9, 7)), (F(0), F(0)), (F(0), F(0)))
    assert result.conditional_shape[0][0] == F(31, 7)
    assert result.shifted_schur[0][0] == F(3, 2)
    assert result.conditioned_center((1, -1)) == (F(-9, 7), F(9, 7), F(0), F(0))
    assert all(x > 0 for x in result.shifted_pivots + result.schur_pivots)
    assert "redacted" in repr(result)


def test_positive_shape_does_not_imply_required_smoothing_margin():
    p = Params(degree=2, digits=1)
    r = ((constant(p, 0),),) * 2
    # Literal perturbation diag(2,2,1,1) is SPD; subtract r^2 I is singular.
    assert positive_pivots(diagonal((2, 2, 1, 1))) == (F(2), F(2), F(1), F(1))
    with pytest.raises(ValueError): master_geometry(p, r, Widths(2, 10, 1))


def test_master_width_too_small_is_rejected():
    p = Params(degree=2, digits=1)
    r = ((constant(p, 1),), (constant(p, 1),))
    with pytest.raises(ValueError): master_geometry(p, r, Widths(10, 16, 1))


def test_signature_geometry_checks_both_declared_noise_interpretations():
    p = Params(degree=2, digits=1)
    y = (constant(p, 1), constant(p, 0), constant(p, 0))
    one = signature_geometry(p, y, Widths(4, 4, 1), noise_factor=1)
    assert all(x > 0 for x in one.shifted_pivots)
    with pytest.raises(ValueError): signature_geometry(p, y, Widths(4, 4, 1), noise_factor=2)
    # This diagnoses a width/scale difference; no sampler interpretation is approved.


def test_valid_signature_shapes_and_conditioned_center_dimensions():
    p = Params()
    y = tuple(constant(p, i - 1) for i in range(p.columns))
    result = signature_geometry(p, y, Widths(1024, 256, 1))
    assert len(result.target) == (p.columns + 1) * p.degree
    assert len(result.conditional_shape) == p.columns * p.degree
    assert len(result.conditioned_center((1,) * p.degree)) == p.columns * p.degree
    with pytest.raises(ValueError): result.conditioned_center((1,))


def test_module_operator_shape_and_product_match_scalar_constant_case():
    p = Params(degree=2, digits=1)
    r = simple_r(p)
    op = module_operator(p, r)
    assert len(op) == 4 and len(op[0]) == 2
    assert op == ((F(1), F(0)), (F(0), F(1)), (F(0), F(0)), (F(0), F(0)))
