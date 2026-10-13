"""Independent Wang/PW linear regressions: no setup, keys, sampling or outer layer.

Only prime moduli are used. The expected contract is lattice-preserving LLL on
dependent integer generators, and a completeness predicate accepting independent
square integer bases. Reference determinants use permutation expansion; finite
images and kernels are enumerated rather than recomputing GF elimination.
"""

from fractions import Fraction
from itertools import combinations, permutations, product
import math

import pytest

from ibme.ibs import wang_pw as w


def _det(matrix):
    n = len(matrix)
    return sum(
        (-1) ** sum(p[i] > p[j] for i in range(n) for j in range(i + 1, n))
        * math.prod(matrix[i][p[i]] for i in range(n))
        for p in permutations(range(n))
    )


def _assert_lll_reduced(basis):
    star, norms, coefficients = [], [], []
    for vector in basis:
        residual = list(map(Fraction, vector))
        mu = []
        for orthogonal, norm in zip(star, norms):
            coefficient = sum(x * y for x, y in zip(vector, orthogonal)) / norm
            mu.append(coefficient)
            residual = [x - coefficient * y for x, y in zip(residual, orthogonal)]
        norm = sum(x * x for x in residual)
        assert norm > 0, (basis, "dependent output")
        star.append(residual)
        norms.append(norm)
        coefficients.append(mu)
    assert all(abs(c) <= Fraction(1, 2) for row in coefficients for c in row)
    assert all(
        norms[k] >= (Fraction(3, 4) - coefficients[k][k - 1] ** 2) * norms[k - 1]
        for k in range(1, len(basis))
    )


def _assert_same_full_rank_lattice(generators, basis):
    dim = len(generators[0])
    expected_index = math.gcd(
        *(abs(_det(list(minor))) for minor in combinations(generators, dim))
    )
    assert expected_index > 0
    assert len(basis) == dim and all(len(v) == dim for v in basis)
    assert all(isinstance(x, int) and not isinstance(x, bool) for v in basis for x in v)
    determinant = _det(basis)
    assert abs(determinant) == expected_index, (generators, basis)
    # Cramer's rule on the transposed basis. Inclusion plus equal index proves
    # equality, not just equal volume of potentially different lattices.
    for generator in generators:
        for i in range(dim):
            replaced = [v[:] for v in basis]
            replaced[i] = generator[:]
            assert _det(replaced) % determinant == 0, (generator, basis)
    _assert_lll_reduced(basis)


@pytest.mark.parametrize(
    "generators",
    [
        [[2], [1]],
        [[2], [3]],
        [[6], [9]],
        [[2, 0], [1, 0], [0, 1]],
        [[0, 0], [2, 0], [1, 0], [0, 1]],
        [[-1, -1], [-1, 1], [-1, 0]],
        [[1, 0, -2], [1, 2, -1], [0, -3, 0], [1, 1, 2]],
    ],
)
def test_lll_preserves_dependent_generators(generators):
    original = [v[:] for v in generators]
    result = w.lll_reduce(generators, max_swaps=2000)
    _assert_same_full_rank_lattice(generators, result)
    assert generators == original


def test_lll_preserves_rank_one_lattice_in_larger_ambient_space():
    basis = w.lll_reduce([[2, 0, 0], [3, 0, 0]], max_swaps=2000)
    assert len(basis) == 1
    assert basis[0][1:] == [0, 0] and abs(basis[0][0]) == 1


def test_lll_exhaustive_one_dimensional_generator_pairs():
    for a, b in product(range(-5, 6), repeat=2):
        if a == b == 0:
            continue
        result = w.lll_reduce([[a], [b]], max_swaps=2000)
        assert len(result) == 1 and len(result[0]) == 1
        assert abs(result[0][0]) == math.gcd(a, b), (a, b, result)


def test_lll_exhaustive_two_dimensional_dependent_generators():
    for flat in product((-1, 0, 1), repeat=6):
        generators = [list(flat[i:i + 2]) for i in range(0, 6, 2)]
        if not any(_det(list(minor)) for minor in combinations(generators, 2)):
            continue
        _assert_same_full_rank_lattice(
            generators, w.lll_reduce(generators, max_swaps=2000)
        )


@pytest.mark.parametrize(
    "rows,q,basis,expected",
    [
        ([[1]], 3, [[3]], True),
        ([[1]], 3, [[-3]], True),
        ([[1]], 3, [[1]], False),          # Strict superlattice.
        ([[1]], 3, [[6]], False),          # Strict sublattice.
        ([[1]], 3, [[0]], False),          # Singular candidate.
        ([[1]], 3, [[6], [9]], False),     # Same lattice, not a square basis.
        ([[1]], 3, [[3], [6]], False),     # Redundant generators.
        ([[1]], 3, [], False),
        ([[1, 0]], 3, [[3, 0], [0, 1]], True),
        ([[1, 0]], 3, [[1, 0], [0, 3]], False),  # Correct det, wrong membership.
        ([[1, 0]], 3, [[6, 0], [0, 1]], False),
        ([[1, 0]], 3, [[3, 0], [6, 0]], False),
        ([[1, 1], [2, 2]], 3, [[3, 0], [-1, 1]], True),
        ([[0, 0], [0, 0]], 3, [[1, 0], [0, 1]], True),
    ],
)
def test_kernel_completeness_checks_both_inclusions_and_square_basis(
    rows, q, basis, expected
):
    before_rows, before_basis = [r[:] for r in rows], [v[:] for v in basis]
    assert w.verify_kernel_basis_is_complete(basis, rows, q) is expected
    assert rows == before_rows and basis == before_basis


@pytest.mark.parametrize(
    "rows,q,rank",
    [
        ([[0, 0], [0, 0]], 3, 0),
        ([[1, 1], [2, 2]], 3, 1),
        ([[1, 2, 0], [2, 4, 0]], 5, 1),
        ([[1, 1], [0, 0], [1, 1]], 2, 1),
        ([[1, 0, 1], [0, 1, 1]], 3, 2),
    ],
)
def test_integer_kernel_determinant_uses_actual_modular_rank(rows, q, rank):
    original = [r[:] for r in rows]
    basis = w.integer_kernel_basis(rows, q)
    assert len(basis) == len(rows[0])
    assert abs(_det(basis)) == q ** rank
    assert all(
        sum(a * x for a, x in zip(row, vector)) % q == 0
        for row in rows for vector in basis
    )
    assert w.verify_kernel_basis_is_complete(basis, rows, q) is True
    _assert_lll_reduced(basis)
    assert rows == original


@pytest.mark.parametrize("q", (2, 3))
@pytest.mark.parametrize("n,m", ((1, 1), (1, 2), (2, 1), (2, 2)))
def test_gf_rank_kernel_and_solve_by_exhaustive_finite_images(q, n, m):
    for flat in product(range(q), repeat=n * m):
        rows = [list(flat[i * m:(i + 1) * m]) for i in range(n)]
        original = [r[:] for r in rows]

        def matvec(vector):
            return tuple(sum(a * x for a, x in zip(row, vector)) % q for row in rows)

        image, kernel = set(), set()
        for vector in product(range(q), repeat=m):
            value = matvec(vector)
            image.add(value)
            if value == (0,) * n:
                kernel.add(vector)
        image_size, rank = len(image), 0
        while image_size > 1:
            assert image_size % q == 0
            image_size //= q
            rank += 1
        assert w._gf_rank(rows, q) == rank
        basis = w._gf_kernel_basis(rows, q)
        assert len(basis) == m - rank
        assert all(len(v) == m and all(0 <= x < q for x in v) for v in basis)
        span = {
            tuple(sum(c * v[j] for c, v in zip(cs, basis)) % q for j in range(m))
            for cs in product(range(q), repeat=len(basis))
        }
        assert span == kernel
        for rhs in product(range(q), repeat=n):
            solution = w._gf_solve(rows, list(rhs), q)
            assert (solution is None) == (rhs not in image)
            assert solution is None or (len(solution) == m and matvec(solution) == rhs)
        assert rows == original


@pytest.mark.parametrize("n", (0, 1, 2, 3))
def test_bareiss_exhaustive_small_integer_matrices(n):
    for flat in product((-1, 0, 1), repeat=n * n):
        matrix = [list(flat[i * n:(i + 1) * n]) for i in range(n)]
        original = [r[:] for r in matrix]
        assert w._det_bareiss(matrix) == _det(matrix), matrix
        assert matrix == original


def _det_fraction(matrix):
    """Rational elimination oracle for the larger trapdoor block matrices."""
    work = [list(map(Fraction, row)) for row in matrix]
    result = Fraction(1)
    for k in range(len(work)):
        pivot = next((i for i in range(k, len(work)) if work[i][k]), None)
        if pivot is None:
            return 0
        if pivot != k:
            work[k], work[pivot] = work[pivot], work[k]
            result = -result
        value = work[k][k]
        result *= value
        work[k] = [x / value for x in work[k]]
        for i in range(k + 1, len(work)):
            factor = work[i][k]
            work[i] = [x - factor*y for x, y in zip(work[i], work[k])]
    assert result.denominator == 1
    return int(result)


def _synthetic_trapdoor_input(q, n, prefix):
    k = (q - 1).bit_length()
    width = n * k
    g = [[(1 << (j % k)) if j // k == i else 0 for j in range(width)]
         for i in range(n)]
    a_bar = [[(2*i - 3*j + 1) % q for j in range(prefix)] for i in range(n)]
    r = [[(i + 2*j) % 5 - 2 for j in range(width)] for i in range(prefix)]
    a = [a_bar[i] + [
        (g[i][j] - sum(a_bar[i][t] * r[t][j] for t in range(prefix))) % q
        for j in range(width)
    ] for i in range(n)]
    return a, r, g


@pytest.mark.parametrize("q,n,prefix", [(2, 1, 1), (3, 1, 2), (5, 1, 3),
                                      (3, 2, 1), (5, 2, 2), (7, 2, 2)])
def test_trapdoor_basis_matches_mp12_lemma_5_3_blocks(q, n, prefix, monkeypatch):
    # MP12 local paper p.23: U[[I,0],[W,S]], specialized to H=I.
    # Production emits the S block first; the column permutation preserves
    # the lattice and the absolute determinant.
    a, r, g = _synthetic_trapdoor_input(q, n, prefix)
    original_a, original_r = [row[:] for row in a], [row[:] for row in r]
    width, dim = len(g[0]), len(a[0])
    captured = []
    original_lll = w.lll_reduce

    def capture(columns, *args, **kwargs):
        captured.append([vector[:] for vector in columns])
        return original_lll(columns, *args, **kwargs)

    monkeypatch.setattr(w, "lll_reduce", capture)
    result = w._trapdoor_kernel_basis(a, r, q)
    raw = captured[-1]
    assert len(raw) == len(result) == dim
    assert all(len(v) == dim for v in raw + result)
    s = [v[prefix:] for v in raw[:width]]
    wc = [v[prefix:] for v in raw[width:]]
    assert abs(_det_fraction(s)) == q ** n
    for j, vector in enumerate(raw):
        bottom = vector[prefix:]
        assert vector[:prefix] == [
            sum(x*y for x, y in zip(row, bottom)) + int(j >= width and i == j-width)
            for i, row in enumerate(r)
        ]
    for i, row in enumerate(g):
        assert all(sum(x*y for x, y in zip(row, v)) % q == 0 for v in s)
        assert all((sum(x*y for x, y in zip(row, v)) + a[i][j]) % q == 0
                   for j, v in enumerate(wc))
    for basis in (raw, result):
        assert abs(_det_fraction(basis)) == q ** n
        assert all(sum(x*y for x, y in zip(row, v)) % q == 0
                   for row in a for v in basis)
        assert w.verify_kernel_basis_is_complete(basis, a, q)
    _assert_lll_reduced(result)
    assert a == original_a and r == original_r


@pytest.mark.parametrize("damage", ["wrong_relation", "wrong_tag", "short_row", "missing_row"])
def test_trapdoor_basis_rejects_invalid_relation_or_shape(damage):
    a, r, _ = _synthetic_trapdoor_input(3, 1, 2)
    if damage == "wrong_relation":
        a[0][len(r)] = (a[0][len(r)] + 1) % 3
    elif damage == "wrong_tag":
        a = [[2*x % 3 for x in row] for row in a]  # H=2 is not the supported H=I.
    elif damage == "short_row":
        r[0] = r[0][:-1]
    else:
        r = r[:-1]
    with pytest.raises(w.InvalidParameterError):
        w._trapdoor_kernel_basis(a, r, 3)
