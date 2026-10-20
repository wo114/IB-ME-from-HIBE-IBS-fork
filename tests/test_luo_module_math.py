"""Independent integer products, DFT evaluations and complete Hint cases."""

from itertools import product
import random

import pytest

from ibme.ibs.luo_module_math import NegacyclicRing, Rounding, negacyclic_schoolbook, sparse_product


@pytest.mark.parametrize("n,root", [(2, 4), (4, 2)])
def test_all_ternary_polynomial_pairs_match_ntt(n, root):
    ring = NegacyclicRing(n, 17, root)
    polynomials = tuple(product((-1, 0, 1), repeat=n))
    for a in polynomials:
        for b in polynomials:
            expected = tuple(x % 17 for x in negacyclic_schoolbook(a, b))
            assert ring.multiply(a, b) == expected
            assert sparse_product(a, b) == negacyclic_schoolbook(a, b)


@pytest.mark.parametrize("n,q,root", [(8, 769, 27), (256, 274877844481, 153250464611)])
def test_ntt_roundtrip_dft_and_large_products(n, q, root):
    ring = NegacyclicRing(n, q, root)
    random_source = random.Random(20261009 + n)
    for _ in range(4):
        a = tuple(random_source.randrange(-q, q) for _ in range(n))
        b = tuple(random_source.randrange(q) for _ in range(n))
        transformed = ring.ntt(a)
        assert ring.inverse_ntt(transformed) == tuple(x % q for x in a)
        assert ring.multiply(a, b) == tuple(x % q for x in negacyclic_schoolbook(a, b))
        # Evaluate at roots independently, without the butterfly implementation.
        for j in (0, 1, n // 2, n - 1):
            point = pow(root, 2 * j + 1, q)
            expected = sum(value * pow(point, i, q) for i, value in enumerate(a)) % q
            assert transformed[j] == expected


def test_x_power_n_equals_minus_one_and_matrix_product():
    ring = NegacyclicRing(8, 769, 27)
    xn1, x = (0,) * 7 + (1,), (0, 1) + (0,) * 6
    assert ring.multiply(xn1, x) == (768,) + (0,) * 7
    rows = ((xn1, x), (x, xn1))
    vector = (x, xn1)
    result = ring.matvec(ring.prepare_matrix(rows), vector)
    for i, row in enumerate(rows):
        products = [negacyclic_schoolbook(poly, v) for poly, v in zip(row, vector)]
        assert result[i] == tuple(sum(poly[j] for poly in products) % 769 for j in range(8))


@pytest.mark.parametrize("n,q,root", [(4, 17, 2), (8, 769, 27), (256, 274877844481, 153250464611)])
def test_prepared_butterflies_match_original_for_signed_boundaries(n, q, root):
    ring = NegacyclicRing(n, q, root)
    info = ring.preparation_info()
    assert info["twiddle_integers"] == 2*(n-1)
    assert info["permutation_integers"] == n
    source = random.Random(20261020)
    for coefficients in ((0,)*n, (q-1,)*n, tuple((-1)**i*(q+1) for i in range(n)),
                         tuple(source.randrange(-2*q, 2*q) for _ in range(n))):
        fast = ring.ntt(coefficients)
        assert fast == ring.ntt(coefficients, prepared=False)
        assert ring.inverse_ntt(fast) == ring.inverse_ntt(fast, prepared=False)
        assert ring.multiply(coefficients, coefficients) == ring.multiply(coefficients, coefficients, prepared=False)
    rows = (((1,)*n, (q-1,)*n),)
    matrix = ring.prepare_matrix(rows)
    assert ring.matvec(matrix, rows[0]) == ring.matvec(matrix, rows[0], prepared=False)


@pytest.mark.parametrize("q", [17, 31, 41, 97])
def test_complete_small_rounding_and_all_three_hint_lemmas(q):
    for alpha in range(2, q, 2):
        if (q - 1) % alpha or q <= 2 * alpha:
            continue
        rounding = Rounding(q, alpha, 3)
        half = alpha // 2
        for r in range(q):
            high, low = rounding.decompose(r)
            assert 0 <= high < (q - 1) // alpha and abs(low) <= half
            assert (high * alpha + low - r) % q == 0
            p1, p0 = rounding.power2round_pair(r)
            assert p1 * 8 + p0 == r and -4 < p0 <= 4
            assert rounding.use_hint(0, r) != rounding.use_hint(1, r)
            for shift in range(1 - half, half):
                hint = rounding.make_hint(shift, r)
                assert rounding.use_hint(hint, r) == rounding.high_bits(r + shift)
            for beta in range(1, half + 1):
                if abs(low) < half - beta:
                    for shift in range(1 - beta, beta):
                        assert rounding.high_bits(r) == rounding.high_bits(r + shift)


def test_exact_large_q_corner_and_power2round_carry():
    q, gamma3 = 274877844481, 15270991360
    rounding = Rounding(q, 2 * gamma3, 28)
    assert rounding.power2round(q - 1) == 1024  # Must not truncate to 10 bits.
    assert rounding.decompose(q - 1) == (0, -1)
    probes = (0, 1, q - 1, q - gamma3 - 1, q - gamma3, gamma3, gamma3 + 1)
    for r in probes:
        for z in (1 - gamma3, -1, 0, 1, gamma3 - 1):
            assert rounding.use_hint(rounding.make_hint(z, r), r) == rounding.high_bits(r + z)


@pytest.mark.parametrize("args", [(3, 17, 2), (4, 17, 1), (4, 16, 2), (True, 17, 2), (512, 12289, 7)])
def test_bad_ntt_context_rejected(args):
    with pytest.raises(ValueError): NegacyclicRing(*args)


@pytest.mark.parametrize("args", [(17, 3, 2), (17, 16, 2), (17, 6, 2), (17, 4, 0), (17, 4, 63)])
def test_bad_rounding_context_rejected(args):
    with pytest.raises(ValueError): Rounding(*args)


def test_wrong_dimensions_and_non_sparse_challenge_rejected():
    ring = NegacyclicRing(4, 17, 2)
    with pytest.raises(ValueError): ring.ntt((1, 2))
    with pytest.raises(ValueError): ring.prepare_matrix((((0,) * 4,), ((0,) * 4, (0,) * 4)))
    with pytest.raises(ValueError): sparse_product((0,) * 4, (2, 0, 0, 0))
    with pytest.raises(ValueError): Rounding(17, 4, 2).use_hint(2, 1)
