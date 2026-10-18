"""Exact basis comparison against the existing coefficient-dense geometry."""

from fractions import Fraction

import pytest

pytest.importorskip("sage.all")

from experiments.research.candidates.srgg.algebra import Params
from experiments.research.candidates.srgg.geometry import (
    Widths, master_geometry, module_operator, signature_geometry, transpose,
)
from experiments.research.candidates.srgg.structured_geometry import (
    MAX_DEGREE, StructuredGeometry, master_operator, signature_operator,
)


def _vector(flat, degree):
    return tuple(tuple(flat[i:i+degree]) for i in range(0, len(flat), degree))


def _flatten(polynomials, degree):
    # Python 3.13 Fraction expects numerator/denominator attributes; Sage QQ
    # exposes methods, so normalize explicitly instead of constructing a broken
    # Fraction whose stored numerator/denominator are bound methods.
    return tuple(Fraction(int(poly[i].numerator()), int(poly[i].denominator()))
                 for poly in polynomials for i in range(degree))


def _matvec(matrix, vector):
    return tuple(sum((x*y for x, y in zip(row, vector) if y), Fraction(0)) for row in matrix)


def _basis_and_integer(dimension):
    for column in range(dimension):
        yield tuple(int(i == column) for i in range(dimension))
    yield tuple((3*i+1) % 7-3 for i in range(dimension))


@pytest.mark.parametrize("degree,rank,digits", [(2, 1, 1), (4, 1, 2), (8, 2, 1)])
@pytest.mark.parametrize("kind", ["master", "signature"])
def test_all_basis_and_integer_inputs_match_the_original_anisotropic_geometry(degree, rank, digits, kind):
    p = Params(degree=degree, rank=rank, p=5, base=3, digits=digits)
    witness = tuple(tuple(tuple((i+2*j+k) % 3-1 for k in range(degree))
                          for j in range(digits*rank)) for i in range(2*rank))
    user = tuple(tuple((2*i+k) % 3-1 for k in range(degree)) for i in range(p.columns))
    if kind == "master":
        widths = Widths(2**23, 2**22, 4)
        dense = master_geometry(p, witness, widths)
        operator = master_operator(degree=degree, rank=rank, digits=digits, base=3,
            witness=witness, first_squared=2**23, second_squared=2**22, r_squared=4)
        v = module_operator(p, witness)
    else:
        widths = Widths(2**25, 2**24, 4)
        dense = signature_geometry(p, user, widths, noise_factor=2)
        operator = signature_operator(degree=degree, rank=rank, digits=digits,
            user_vector=user, first_squared=2**25, second_squared=2**24, r_squared=4, noise_factor=2)
        v = module_operator(p, tuple((poly,) for poly in user))
        assert operator.top_squared == (2**25,)*(2*rank)+(2**24,)*(digits*rank)
        assert operator.noise_squared == 8
    upper, lower = len(v), len(v[0])
    factor = v+tuple(tuple(int(i == j) for j in range(lower)) for i in range(lower))
    assert Fraction(int(operator.lower_scalar.numerator()), int(operator.lower_scalar.denominator())) == dense.lower_scalar
    for flat in _basis_and_integer(lower):
        argument = _vector(flat, degree)
        assert _flatten(operator.v_apply(argument), degree) == _matvec(v, flat)
        assert _flatten(operator.factor_apply(argument), degree) == _matvec(factor, flat)
        assert _flatten(operator.conditioned_center(argument), degree) == _matvec(dense.center_operator, flat)
    for flat in _basis_and_integer(upper):
        argument = _vector(flat, degree)
        assert _flatten(operator.v_adjoint_apply(argument), degree) == _matvec(transpose(v), flat)
        assert _flatten(operator.conditional_apply(argument), degree) == _matvec(dense.conditional_shape, flat)
        assert _flatten(operator.shifted_schur_apply(argument), degree) == _matvec(dense.shifted_schur, flat)
    for flat in _basis_and_integer(upper+lower):
        argument = _vector(flat, degree)
        assert _flatten(operator.factor_adjoint_apply(argument), degree) == _matvec(transpose(factor), flat)
        assert _flatten(operator.perturbation_apply(argument), degree) == _matvec(dense.perturbation, flat)


def test_conjugate_adjoint_preserves_the_coefficient_inner_product():
    operator = StructuredGeometry(4, ((((1, -2, 3, 1)),),), (1000,), 500, 4, 4)
    lower, upper = ((1, 2, -1, 3),), ((-3, 1, 2, 5),)
    applied = _flatten(operator.v_apply(lower), 4)
    adjoint = _flatten(operator.v_adjoint_apply(upper), 4)
    assert sum(x*y for x, y in zip(applied, upper[0])) == sum(x*y for x, y in zip(lower[0], adjoint))


def test_factor2_changes_the_shape_without_changing_the_declared_witness():
    user = ((1, 1), (1, 0), (0, -1))
    kwargs = dict(degree=2, rank=1, digits=1, user_vector=user,
                  first_squared=1000, second_squared=500, r_squared=4)
    left, right = signature_operator(**kwargs, noise_factor=1), signature_operator(**kwargs, noise_factor=2)
    full = user+((1, -1),)
    assert left.witness == right.witness
    assert left.perturbation_apply(full) != right.perturbation_apply(full)


def test_rational_coefficients_remain_exact_and_repr_redacts_witness():
    operator = StructuredGeometry(2, (((Fraction(1, 3), Fraction(-2, 5)),),),
                                  (Fraction(100, 3),), 30, 2, 1)
    result = _flatten(operator.v_apply(((3, 5),)), 2)
    assert result == (Fraction(3), Fraction(7, 15))
    assert "redacted" in repr(operator)
    assert "1/3" not in repr(operator)
    metadata = operator.public_metadata()
    assert metadata["coefficient_matrices_materialized"] is False
    assert metadata["full_positive_definiteness_checked"] is False
    assert metadata["sampler_implemented"] is False


@pytest.mark.parametrize("kwargs", [
    {"degree": 3}, {"degree": MAX_DEGREE+1}, {"degree": True},
    {"lower_squared": 8}, {"witness": (((True, 0),),)},
    {"witness": (((1 << 4096, 0),),)},
])
def test_structured_operand_gates_are_explicit(kwargs):
    values = dict(degree=2, witness=(((1, 0),),), top_squared=(100,),
                  lower_squared=50, noise_squared=4, rounding_squared=4)
    values.update(kwargs)
    with pytest.raises(ValueError):
        StructuredGeometry(**values)


def test_master_factory_retains_cbd1_and_vector_dimension_contracts():
    with pytest.raises(ValueError, match="CBD1"):
        master_operator(degree=2, rank=1, digits=1, base=3,
                        witness=(((2, 0),), ((0, 1),)), first_squared=1000,
                        second_squared=500, r_squared=4)
    operator = StructuredGeometry(2, (((1, 0),),), (100,), 50, 4, 4)
    with pytest.raises(ValueError, match="dimension"):
        operator.v_apply(())


def test_structured_coefficient_slot_gate_precedes_polynomial_materialization():
    poly = (0,)*128
    row = (poly,)*128
    with pytest.raises(ValueError, match="coefficient budget"):
        StructuredGeometry(128, (row,)*128, (100,)*128, 50, 4, 4)
