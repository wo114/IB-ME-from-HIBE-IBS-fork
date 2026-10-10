"""T1 exact algebra: complete kernel lattices and CHKP Lemma 3.2."""

from itertools import product

import pytest

pytest.importorskip("sage.all", reason="Use the prescribed WSL Sage environment")
from sage.all import GF, QQ, ZZ, identity_matrix, matrix

from experiments.research.chkp_basis import (
    CHKPAlgebraParams, KernelBasis, ModMatrixReference, complete_kernel_basis,
    ext_basis, gram_schmidt_squared_lengths, two_level_matrices,
)


def test_root_parent_child_dimensions_and_order():
    params = CHKPAlgebraParams(n=2, m=4, q=17)
    a = [[1, 0, 2, 3], [0, 1, 5, 7]]
    h1 = [[4, 6, 8, 10], [3, 5, 9, 11]]
    h2 = [[2, 4, 6, 8], [1, 3, 7, 9]]
    root, parent, child = two_level_matrices(params, a, h1, h2)
    assert [x.ncols for x in (root, parent, child)] == [4, 8, 12]
    assert parent.rows == tuple(tuple(a[i] + h1[i]) for i in range(2))
    assert child.rows == tuple(tuple(a[i] + h1[i] + h2[i]) for i in range(2))
    s0 = complete_kernel_basis(root)
    s1 = ext_basis(s0, ModMatrixReference(h1, 17))
    s2 = ext_basis(s1, ModMatrixReference(h2, 17))
    for public, basis in zip((root, parent, child), (s0, s1, s2)):
        a_z = matrix(ZZ, public.rows)
        s_z = matrix(ZZ, basis.basis_rows)
        assert a_z.ncols() == s_z.nrows() == s_z.ncols()
        assert all(int(x) % 17 == 0 for x in (a_z * s_z).list())
        assert s_z.rank() == public.ncols
        assert abs(s_z.det()) == 17**2
        assert basis.security_claim == "none"
        assert not basis.is_randomized


@pytest.mark.parametrize("rows,q,pivots", [
    ([[0, 2, 1], [1, 0, 1]], 3, (0, 1)),
    ([[2, 0, 1, 5], [0, 3, 2, 1]], 17, (0, 1)),
    ([[1, 2, 3]], 2, (0,)),
    ([[0, 1, 0], [0, 0, 1]], 5, (1, 2)),
    ([[0, 2, 0, 1], [0, 4, 1, 3]], 5, (1, 2)),
    ([[0, 0, 1, 2], [0, 0, 0, 1]], 3, (2, 3)),
])
def test_pivot_positions_and_complete_index(rows, q, pivots):
    public = ModMatrixReference(rows, q)
    basis = complete_kernel_basis(public)
    a, s = matrix(GF(q), public.rows), matrix(ZZ, basis.basis_rows)
    assert tuple(a.pivots()) == pivots
    assert a.rank() == public.nrows
    assert matrix(GF(q), s).nrows() == public.ncols
    assert a * matrix(GF(q), s) == 0
    assert abs(s.det()) == q**public.nrows
    assert gram_schmidt_squared_lengths(basis.basis_rows) == (
        (q**2,) * public.nrows + (1,) * (public.ncols - public.nrows))


def test_exhaustive_membership_not_just_kernel_containment():
    root = complete_kernel_basis(ModMatrixReference([[1, 2]], 3))
    child = ext_basis(root, ModMatrixReference([[0, 1]], 3))
    a, s = matrix(ZZ, child.public.rows), matrix(QQ, child.basis_rows)
    inverse = s.inverse()
    for values in product(range(3), repeat=4):
        v = matrix(ZZ, 4, 1, values)
        in_kernel = all(int(x) % 3 == 0 for x in (a * v).list())
        coords = inverse * v
        in_basis = all(x.denominator() == 1 for x in coords.list())
        assert in_kernel == in_basis


def test_extbasis_accepts_arbitrary_unimodular_parent_basis():
    root = complete_kernel_basis(ModMatrixReference([[1, 4, 2], [0, 1, 3]], 17))
    u = identity_matrix(ZZ, 3)
    u[0, 1] = -23
    changed = KernelBasis(root.public, matrix(ZZ, root.basis_rows) * u)
    block = ModMatrixReference([[9, 5], [2, 7]], 17)
    extended = ext_basis(changed, block)
    before = gram_schmidt_squared_lengths(changed.basis_rows)
    after = gram_schmidt_squared_lengths(extended.basis_rows)
    assert after == before + (QQ(1), QQ(1))
    independent = matrix(QQ, extended.basis_rows).transpose().gram_schmidt()[0]
    assert after == tuple(row.dot_product(row) for row in independent.rows())
    assert max(after) == max(before)


def test_negative_entries_and_large_modulus_are_not_truncated():
    q = 2**61 - 1
    root = complete_kernel_basis(ModMatrixReference([[-1, q + 5]], q))
    assert root.public.rows == ((q - 1, 5),)
    assert max(abs(int(x)) for row in root.basis_rows for x in row) >= q
    assert abs(matrix(ZZ, root.basis_rows).det()) == q


def test_invalid_basis_cannot_be_extended():
    public = ModMatrixReference([[1, 2]], 3)
    good = complete_kernel_basis(public)
    # All vectors still solve the congruence, but this is a proper sublattice.
    with pytest.raises(ValueError, match="determinant"):
        KernelBasis(public, matrix(ZZ, good.basis_rows) * 2)
    with pytest.raises(ValueError):
        KernelBasis(public, [[1, 0], [0, 1]])
    with pytest.raises(ValueError):
        KernelBasis(public, [[3, 0], [0, 0]])


@pytest.mark.parametrize("rows,q", [([[0, 0]], 3), ([[1, 0], [2, 0]], 3)])
def test_rank_deficient_root_is_rejected(rows, q):
    with pytest.raises(ValueError, match="row rank"):
        complete_kernel_basis(ModMatrixReference(rows, q))


@pytest.mark.parametrize("n,m,q", [(0, 2, 3), (2, 1, 3), (1, 2, 9), (True, 2, 3)])
def test_invalid_algebra_parameters_rejected(n, m, q):
    with pytest.raises(ValueError):
        CHKPAlgebraParams(n=n, m=m, q=q)


def test_shapes_and_moduli_are_checked():
    root = complete_kernel_basis(ModMatrixReference([[1, 2]], 3))
    with pytest.raises(ValueError):
        ext_basis(root, ModMatrixReference([[1], [2]], 3))
    with pytest.raises(ValueError):
        ext_basis(root, ModMatrixReference([[1]], 5))
    with pytest.raises(ValueError):
        ModMatrixReference([[1, 2], [3]], 3)
    with pytest.raises(ValueError):
        ModMatrixReference([[1.0, 2]], 3)
    with pytest.raises(ValueError):
        ModMatrixReference([[True, 2]], 3)
    with pytest.raises(ValueError):
        two_level_matrices(CHKPAlgebraParams(1, 2, 3), [[1, 2]], [[1]], [[1, 2]])


def test_input_mutation_cannot_change_the_basis():
    rows = [[1, 2]]
    public = ModMatrixReference(rows, 3)
    rows[0][0] = 0
    basis_rows = [list(row) for row in complete_kernel_basis(public).basis_rows]
    basis = KernelBasis(public, basis_rows)
    saved = basis.basis_rows
    basis_rows[0][0] = 999
    assert public.rows == ((1, 2),)
    assert basis.basis_rows == saved
