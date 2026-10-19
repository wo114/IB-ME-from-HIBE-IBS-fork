"""Independent dense coefficient checks of the exact paper ring-Schur plan."""

from fractions import Fraction

import pytest

pytest.importorskip("sage.all")
from sage.all import QQ, block_matrix, diagonal_matrix, matrix, vector

from experiments.research.candidates.srgg.paper_ring_schur import RingSchurPlan
from experiments.research.candidates.srgg.structured_geometry import StructuredGeometry


def _operator(poly, n):
    """Independently expand negacyclic multiplication by signed wraparound."""
    result = matrix(QQ, n, n)
    for col in range(n):
        for coefficient in range(n):
            degree = coefficient+col
            result[degree % n, col] += poly[coefficient]*(1 if degree < n else -1)
    return result


def _flat(polynomials, n):
    return vector(QQ, [poly[i] for poly in polynomials for i in range(n)])


def _fixture(n, scale=Fraction(1)):
    witness = tuple(tuple(tuple(((2*i+3*j+k) % 5)-2 for k in range(n))
                          for j in range(2)) for i in range(3))
    return StructuredGeometry(n, witness, tuple(scale*x for x in (1000, 1100, 1200)),
                              scale*500, scale*4, scale)


@pytest.mark.parametrize("n", [2, 4])
def test_every_pivot_gain_and_center_matches_independent_dense_elimination(n):
    geometry = _fixture(n)
    plan = RingSchurPlan(geometry)
    blocks = [[_operator(poly, n) for poly in row] for row in geometry.witness]
    witness = block_matrix(blocks)
    shape = (diagonal_matrix(QQ, [x for x in geometry.top_squared for _ in range(n)])
             -(geometry.noise_squared*geometry.lower_squared/geometry.lower_scalar)
             *witness*witness.transpose())
    lower = tuple(tuple((3*j+k) % 7-3 for k in range(n)) for j in range(2))
    center = plan.initial_center(lower)
    dense_center = (-geometry.noise_squared/geometry.lower_scalar)*witness*_flat(lower, n)
    assert _flat(center, n) == dense_center
    assert plan.sampling_order == (2, 1, 0)
    assert plan.output_order == (0, 1, 2)
    for stage in plan.stages:
        cut = stage.index*n
        pivot = shape[cut:, cut:]
        assert _operator(stage.pivot, n) == pivot
        if cut:
            gain = shape[:cut, cut:]*pivot.inverse()
            assert block_matrix([[_operator(poly, n)] for poly in stage.gains]) == gain
            # This sample is fixed public algebra evidence, never a Gaussian.
            sampled = tuple((stage.index+2*k) % 5-2 for k in range(n))
            dense_center = dense_center[:cut]+gain*(vector(QQ, sampled)-dense_center[cut:])
            center = plan.update_center(stage, center, sampled)
            assert _flat(center, n) == dense_center
            shape = shape[:cut, :cut]-gain*shape[cut:, :cut]
        else:
            assert stage.gains == ()
            assert plan.update_center(stage, center, (0,)*n) == ()


@pytest.mark.parametrize("n", [2, 4])
def test_common_positive_scale_cancels_in_gains_and_centers_exactly(n):
    scale = Fraction(7, 13)
    left, right = RingSchurPlan(_fixture(n)), RingSchurPlan(_fixture(n, scale))
    exact_scale = QQ(scale.numerator)/scale.denominator
    for a, b in zip(left.stages, right.stages):
        assert b.pivot == exact_scale*a.pivot
        assert b.gains == a.gains
    lower = ((1,)*n, (-1,)*n)
    assert left.initial_center(lower) == right.initial_center(lower)


def test_input_and_inverse_bitgrowth_fail_before_any_sampling():
    with pytest.raises(ValueError, match="rational resource"):
        RingSchurPlan(StructuredGeometry(2, (((1, 0),),), (2**60,), 50, 4, 1),
                      max_rational_bits=32)
    # The normalized polynomial has small input coefficients, but its exact
    # inverse grows beyond the explicit 32-bit preparation budget.
    geometry = StructuredGeometry(4, (((1, 0, 0, 0),), ((1, 1, 0, 0),)),
                                  (2**20+1, 2**20+1), 50, 4, 1)
    with pytest.raises(ValueError, match="rational resource"):
        RingSchurPlan(geometry, max_rational_bits=32)


def test_zero_schur_pivot_rejected_in_preparation():
    geometry = StructuredGeometry(2, (((1, 0),),), (Fraction(100, 23),), 50, 4, 1)
    with pytest.raises(ValueError, match="noninvertible"):
        RingSchurPlan(geometry)


@pytest.mark.parametrize("kwargs", [
    {"max_degree": True}, {"max_degree": 3}, {"max_degree": 1024},
    {"max_degree": 2}, {"max_rational_bits": True},
    {"max_rational_bits": 31}, {"max_rational_bits": 16385},
])
def test_public_option_and_dimension_caps(kwargs):
    with pytest.raises(ValueError):
        RingSchurPlan(_fixture(4), **kwargs)


def test_upper_module_cap_does_not_form_a_large_matrix():
    geometry = StructuredGeometry(2, (((0, 0),),)*17, (100,)*17, 50, 4, 1)
    with pytest.raises(ValueError, match="dimension"):
        RingSchurPlan(geometry)


def test_private_representations_and_center_validation():
    plan = RingSchurPlan(_fixture(2))
    other = RingSchurPlan(_fixture(2))
    assert "redacted" in repr(plan)
    assert "redacted" in repr(plan.stages[0])
    assert "1000" not in repr(plan)
    report = plan.public_metadata()
    assert report["coefficient_matrices_materialized"] is False
    assert report["shape_positive_definiteness_checked"] is False
    assert report["entropy_bytes_consumed"] == 0
    assert report["sampler_implemented"] is False
    with pytest.raises(TypeError):
        RingSchurPlan(object())
    with pytest.raises(ValueError, match="dimension"):
        plan.initial_center(())
    with pytest.raises(ValueError, match="exact rational"):
        plan.initial_center(((True, 0), (0, 0)))
    center = plan.initial_center(((1, 0), (0, 0)))
    with pytest.raises(ValueError, match="belong"):
        plan.update_center(other.stages[0], center, (0, 0))
    with pytest.raises(ValueError, match="dimension"):
        plan.update_center(plan.stages[0], center[:-1], (0, 0))
