"""Distribution-preserving exact rank and ToBasis implementation changes."""

from hashlib import sha256

import pytest

pytest.importorskip("sage.all")
from sage.all import QQ, ZZ, matrix, vector

from ibme.lattice.chkp.basis import gram_schmidt_squared_lengths
from ibme.lattice.chkp.finite_randbasis import _ExactIncrementalRank
from ibme.lattice.chkp.root_basis import private_root_basis
from ibme.lattice.chkp.tobasis import canonical_basis, to_basis


def _legacy_to_basis_output(vectors, basis):
    canonical = canonical_basis(basis)
    b = matrix(ZZ, canonical.basis_rows)
    z = matrix(ZZ, matrix(QQ, b).solve_right(matrix(QQ, vectors)))
    r, change = z.hermite_form(transformation=True)
    assert change*z == r and abs(change.det()) == 1
    return b*matrix(ZZ, change.inverse()), r


@pytest.mark.parametrize("q,n,mb", [(2, 1, 1), (3, 1, 2), (5, 2, 1), (17, 2, 2), (257, 1, 2)])
def test_triangular_solution_is_identical_to_inverse_and_preserves_gs(q, n, mb):
    k = (q-1).bit_length()
    a = [[(3*i+5*j+1) % q for j in range(mb)] for i in range(n)]
    r = [[(7*i+3*j) % 5-2 for j in range(n*k)] for i in range(mb)]
    root = private_root_basis(a, r, q)
    d = root.public.ncols
    mixing = matrix(ZZ, d, d, lambda i,j:
                    (20*d if i == j else 0) +
                    sha256(f"public-equivalence/{q}/{i}/{j}".encode()).digest()[0] % 11-5)
    samples = matrix(ZZ, root.basis_rows)*mixing
    expected, triangular = _legacy_to_basis_output(samples, root)
    actual = to_basis(samples, root)
    assert matrix(ZZ, actual.basis_rows) == expected
    old_gs = gram_schmidt_squared_lengths(samples)
    new_gs = gram_schmidt_squared_lengths(actual.basis_rows)
    assert all(new_gs[i]*triangular[i,i]**2 == old_gs[i] for i in range(d))
    assert all(a <= b for a,b in zip(new_gs, old_gs))


def _exact_choices(rows):
    chosen, decisions = [], []
    for row in rows:
        candidate = vector(ZZ, row)
        keep = matrix(ZZ, chosen+[candidate]).rank() > len(chosen)
        decisions.append(keep)
        if keep:
            chosen.append(candidate)
    return decisions, chosen


@pytest.mark.parametrize("prime", [2, 3, 17, 2147483647])
def test_modular_fast_path_keeps_exactly_the_original_sequence(prime):
    dimension = 8
    rows = [tuple(sha256(f"rank/{i}/{j}".encode()).digest()[0]-128
                  for j in range(dimension)) for i in range(20)]
    rows.insert(2, rows[0])
    rows.insert(0, (0,)*dimension)
    rows.insert(4, tuple(prime*x for x in rows[1]))
    expected, chosen = _exact_choices(rows)
    rank = _ExactIncrementalRank(dimension, witness_prime=prime)
    assert [rank.add(row) for row in rows] == expected
    assert rank.chosen == chosen


def test_modular_dependency_is_never_treated_as_rational_dependency():
    rank = _ExactIncrementalRank(2, witness_prime=3)
    assert rank.add((3, 0))
    assert rank.add((0, 3))
    assert not rank.add((3, 3))
    assert rank.exact_fallbacks == 3
    assert rank.echelon == []


def test_modular_witness_remains_valid_after_exact_fallback():
    rank = _ExactIncrementalRank(3, witness_prime=3)
    rows = [(3, 0, 0), (0, 1, 0), (0, 0, 1), (1, 2, 3)]
    expected, chosen = _exact_choices(rows)
    assert [rank.add(row) for row in rows] == expected
    assert rank.chosen == chosen
