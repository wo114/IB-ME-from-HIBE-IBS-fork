"""Exact completeness certificates and deterministic postprocess equivalence."""

from hashlib import sha256

import pytest

pytest.importorskip("sage.all")
from sage.all import QQ, ZZ, matrix

from ibme.lattice.chkp.basis import KernelBasis, ModMatrixReference, complete_kernel_basis
from ibme.lattice.chkp.basis_reduce import checked_lll
from ibme.lattice.chkp.root_basis import private_root_basis
from ibme.lattice.chkp.tobasis import to_basis


def _public():
    return ModMatrixReference(((1, 0),), 7)


@pytest.mark.parametrize("huge", [3, 2**1024 + 1])
def test_short_product_certifies_large_complete_basis(huge):
    # The product is tiny even when both the basis and factor are large.
    t = matrix(ZZ, [[7, 7*huge], [0, 1]])
    r = matrix(ZZ, [[-2, -3*huge], [0, 3]])
    s = t*r
    result = KernelBasis.from_upper_triangular_product(_public(), t, r, s)
    assert result == KernelBasis(_public(), t)
    assert result.security_claim == "none" and result.is_randomized is False


@pytest.mark.parametrize("t,r,s", [
    ([[7, 0], [0, 1]], [[1, 0], [1, 1]], [[7, 0], [1, 1]]),  # nontriangular
    ([[7, 0], [0, 1]], [[1, 0], [0, 0]], [[7, 0], [0, 0]]),  # singular R
    ([[7, 0], [0, 1]], [[1, 0], [0, 1]], [[7, 1], [0, 1]]),  # false product
    ([[14, 0], [0, 1]], [[1, 0], [0, 1]], [[14, 0], [0, 1]]),  # sublattice
    ([[1, 0], [0, 7]], [[1, 0], [0, 1]], [[1, 0], [0, 7]]),  # wrong kernel
    ([[7, 0], [0, 1]], [[1]], [[7, 0], [0, 1]]),  # wrong dimensions
    ([[7, False], [0, 1]], [[1, 0], [0, 1]], [[7, 0], [0, 1]]),
    ([[7, 0], [0, 1]], [[1.0, 0], [0, 1]], [[7, 0], [0, 1]]),
])
def test_invalid_product_certificate_is_rejected(t, r, s):
    with pytest.raises(ValueError):
        KernelBasis.from_upper_triangular_product(_public(), t, r, s)


def test_product_certificate_requires_surjective_public_matrix():
    with pytest.raises(ValueError, match="full row rank"):
        KernelBasis.from_upper_triangular_product(
            ModMatrixReference(((0, 0),), 7), [[7, 0], [0, 1]],
            [[1, 0], [0, 1]], [[7, 0], [0, 1]])


def test_tobasis_rejects_singular_samples():
    basis = KernelBasis(_public(), [[7, 0], [0, 1]])
    with pytest.raises(ValueError, match="full integer rank"):
        to_basis([[7, 0], [0, 0]], basis)


def _legacy_checked_lll(basis, bound):
    original = matrix(ZZ, basis.basis_rows)
    rows, transform = original.transpose().LLL(
        delta=QQ(999)/1000, eta=QQ(501)/1000, transformation=True)
    reduced, change = rows.transpose(), transform.transpose()
    old_star, _ = reduced.transpose().change_ring(QQ).gram_schmidt()
    old_norms = tuple(row.dot_product(row) for row in old_star.rows())
    for j in range(reduced.ncols()):
        for i in reversed(range(j)):
            mu = reduced.column(j).dot_product(old_star.row(i))/old_norms[i]
            nearest = ZZ((mu+QQ(1)/2).floor())
            if nearest:
                reduced.add_multiple_of_column(j, i, -nearest)
                change.add_multiple_of_column(j, i, -nearest)
    assert original*change == reduced and abs(change.det()) == 1
    new_star, _ = reduced.transpose().change_ring(QQ).gram_schmidt()
    # Independently recomputing the old check verifies the reused geometry.
    assert new_star == old_star
    lengths = tuple(row.dot_product(row) for row in new_star.rows())
    mu = lambda i,j: reduced.column(i).dot_product(new_star.row(j))/lengths[j]
    assert max(lengths) <= bound
    assert all(abs(mu(i,j)) <= QQ(1)/2 for i in range(len(lengths)) for j in range(i))
    assert all(lengths[i]+mu(i,i-1)**2*lengths[i-1] >= QQ(99)/100*lengths[i-1]
               for i in range(1,len(lengths)))
    return KernelBasis(basis.public, reduced)


def _check_reduction_postconditions(basis, bound, lovasz):
    s = matrix(ZZ, basis.basis_rows)
    a = matrix(ZZ, basis.public.rows)
    assert a*s % basis.public.q == 0
    assert abs(s.det()) == basis.public.q**basis.public.nrows
    star, _ = s.transpose().change_ring(QQ).gram_schmidt()
    lengths = tuple(row.dot_product(row) for row in star.rows())
    mu = lambda i,j: s.column(i).dot_product(star.row(j))/lengths[j]
    assert max(lengths) <= bound
    assert all(abs(mu(i,j)) <= QQ(1)/2 for i in range(len(lengths)) for j in range(i))
    assert all(lengths[i]+mu(i,i-1)**2*lengths[i-1] >= lovasz*lengths[i-1]
               for i in range(1,len(lengths)))


@pytest.mark.parametrize("q,n,mbar", [(3, 1, 1), (17, 2, 2), (257, 1, 2)])
def test_old_and_new_lll_profiles_have_their_declared_exact_postconditions(q,n,mbar):
    k = (q-1).bit_length()
    root = private_root_basis(
        [[(2*i+3*j+1) % q for j in range(mbar)] for i in range(n)],
        [[(7*i+2*j) % 5-2 for j in range(n*k)] for i in range(mbar)], q)
    expected = _legacy_checked_lll(root, QQ(q*q*root.public.ncols))
    actual = checked_lll(root, q*q*root.public.ncols)
    # Delta is a versioned deterministic postprocess choice, not a CHKP
    # width condition. Do not assert identical old/new encoded bases.
    assert actual.public == expected.public == root.public
    _check_reduction_postconditions(expected, q*q*root.public.ncols, QQ(99)/100)
    _check_reduction_postconditions(actual, q*q*root.public.ncols, QQ(74)/100)
    assert actual == checked_lll(root, q*q*root.public.ncols)


def test_fixed_lll_profile_handles_public_ill_conditioned_tobasis_fixture():
    dimension, q = 32, 1099511627791
    public = ModMatrixReference(tuple(tuple(
        int.from_bytes(sha256(f"PUBLIC-A/{i}/{j}".encode()).digest()[:6], "big") % q
        for j in range(dimension)) for i in range(2)), q)
    basis = complete_kernel_basis(public)
    mixing = matrix(ZZ, dimension, dimension, lambda i,j:
        (dimension*65536 if i == j else 0)
        + int.from_bytes(sha256(f"PUBLIC-DENSE/{dimension}/{i}/{j}".encode()).digest()[:2], "big")
        - 32768)
    # These are public deterministic algebra fixtures, not Gaussian samples.
    vectors = matrix(ZZ, basis.basis_rows)*mixing
    before = to_basis(vectors, basis)
    assert max(abs(x).bit_length() for row in before.basis_rows for x in row) > 40
    frozen_parent_bound = 150187181128720
    after = checked_lll(before, frozen_parent_bound)
    _check_reduction_postconditions(after, frozen_parent_bound, QQ(74)/100)
    assert after.security_claim == "none"


def test_fixed_lll_profile_cannot_relax_the_callers_gs_bound():
    basis = KernelBasis(_public(), [[7, 0], [0, 1]])
    with pytest.raises(ArithmeticError, match="GS or Lovasz"):
        checked_lll(basis, 1)


def test_lll_size_subtraction_preserves_ordered_gs_vectors_exactly():
    s = matrix(ZZ, [[7, 700, -35], [0, 1, 24], [0, 0, 1]])
    old_star, _ = s.transpose().change_ring(QQ).gram_schmidt()
    s.add_multiple_of_column(2, 1, -24)
    s.add_multiple_of_column(2, 0, 2405)
    s.add_multiple_of_column(1, 0, -100)
    new_star, _ = s.transpose().change_ring(QQ).gram_schmidt()
    assert new_star == old_star
