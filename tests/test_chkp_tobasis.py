"""Exact independent checks of GS-only ToBasis, not security estimates."""

import pytest

pytest.importorskip("sage.all", reason="Use prescribed WSL Sage, never count skip as pass")
from sage.all import GF, QQ, ZZ, identity_matrix, matrix, vector

from experiments.research.chkp_basis import (
    KernelBasis, ModMatrixReference, complete_kernel_basis,
    gram_schmidt_squared_lengths,
)
from experiments.research.chkp_tobasis import canonical_basis, to_basis


def root(d=3):
    return complete_kernel_basis(ModMatrixReference([[1] + [2] * (d - 1)], 5))


@pytest.mark.parametrize("d", [1, 2, 3, 6])
def test_strict_sublattice_completed_to_original(d):
    basis = root(d)
    b = matrix(ZZ, basis.basis_rows)
    s = 2 * b
    result = to_basis(s, basis)
    t = matrix(ZZ, result.basis_rows)
    assert abs(s.det()) == 2 ** d * 5
    assert abs(t.det()) == 5
    assert t.transpose().hermite_form() == b.transpose().hermite_form()
    before = gram_schmidt_squared_lengths(s)
    after = gram_schmidt_squared_lengths(t)
    assert all(y <= x for x, y in zip(before, after))
    assert result.security_claim == "none"


@pytest.mark.parametrize("seed", range(12))
def test_dense_ordered_vectors_and_independent_gs(seed):
    from random import Random
    rng = Random(seed)
    basis = root(4)
    b = matrix(ZZ, basis.basis_rows)
    u = identity_matrix(ZZ, 4)
    for _ in range(12):
        i, j = rng.sample(range(4), 2)
        u.add_multiple_of_column(i, j, rng.randint(-4, 4))
    r = matrix(ZZ, [[(i + 2 if i == j else rng.randint(-5, 5) if i < j else 0)
                     for j in range(4)] for i in range(4)])
    s = b * u * r
    t = matrix(ZZ, to_basis(s, basis).basis_rows)
    assert t.transpose().hermite_form() == b.transpose().hermite_form()
    original = s.transpose().change_ring(QQ).gram_schmidt()[0]
    produced = t.transpose().change_ring(QQ).gram_schmidt()[0]
    assert all(a.dot_product(a) <= c.dot_product(c)
               for a, c in zip(produced.rows(), original.rows()))


def test_same_lattice_and_ordered_samples_give_same_postprocessing():
    basis = root()
    b = matrix(ZZ, basis.basis_rows)
    u = matrix(ZZ, [[1, 73, -3], [0, -1, 4], [0, 0, 1]])
    changed = KernelBasis(basis.public, b * u)
    s = b * matrix(ZZ, [[2, 5, 3], [0, 3, 7], [0, 0, 4]])
    assert canonical_basis(basis).basis_rows == canonical_basis(changed).basis_rows
    assert to_basis(s, basis).basis_rows == to_basis(s, changed).basis_rows


def test_false_spectral_inference_has_exact_counterexample():
    r = matrix(ZZ, [[1, 1], [0, 1]])
    v = vector(ZZ, [1, -1])
    assert r[1, 0] == 0 and r.det() == 1
    assert (r*v).dot_product(r*v) == 1 < v.dot_product(v) == 2
    assert (r.transpose()*r).charpoly().list() == [1, -3, 1]


@pytest.mark.parametrize("bad", [
    [[1, 2], [3, 4]], [[1, 2, 3]], [[1, 2, 3]] * 3,
    [[True, 0, 0], [0, 1, 0], [0, 0, 1]],
    [[1.0, 0, 0], [0, 1, 0], [0, 0, 1]],
])
def test_invalid_shape_rank_and_types_rejected(bad):
    with pytest.raises(ValueError):
        to_basis(bad, root())


def test_nonmember_vectors_rejected_even_when_full_rank():
    with pytest.raises(ValueError, match="not in"):
        to_basis(identity_matrix(ZZ, 3), root())


def test_modular_entries_are_not_silently_lifted():
    basis = root()
    with pytest.raises(ValueError, match="exact integers"):
        to_basis(matrix(GF(5), basis.basis_rows), basis)


def test_resource_budget_and_basis_type_rejected():
    with pytest.raises(ValueError, match="KernelBasis"):
        to_basis([[1]], object())
    with pytest.raises(ValueError, match="bit budget"):
        to_basis([[5 * 2**8193]], root(1))


def test_infinite_and_oversized_iterators_are_bounded():
    from itertools import repeat
    from experiments.research.chkp_tobasis import _checked_square
    rows_seen, entries_seen = [], []
    def too_many_rows():
        for row in repeat([5]):
            rows_seen.append(1)
            yield row
    with pytest.raises(ValueError, match="dimension"):
        _checked_square(too_many_rows(), 1)
    assert len(rows_seen) == 2
    def too_many_entries():
        for entry in repeat(5):
            entries_seen.append(1)
            yield entry
    with pytest.raises(ValueError, match="dimension"):
        _checked_square([too_many_entries()], 1)
    assert len(entries_seen) == 2
