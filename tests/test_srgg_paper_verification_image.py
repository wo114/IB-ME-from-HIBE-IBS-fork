"""Independent small-ring checks of the original SRGG verification image."""
from itertools import product

import pytest
from sage.all import GF, ZZ, matrix

from experiments.research.candidates.srgg.paper_verification_image import (
    build_report, image_certificate,
)


def _mul_block(poly, degree):
    """Integer negacyclic convolution matrix, independent of SRGG code."""
    result = matrix(ZZ, degree, degree)
    for input_index, coefficient in enumerate(poly):
        for column in range(degree):
            exponent = input_index + column
            result[exponent % degree, column] += coefficient * (
                -1 if exponent >= degree else 1)
    return result


def _small_verification_matrix(degree, rank, Q):
    """Construct [2(I|U) | Q*zeta*e1-2h] directly over integers."""
    columns = 4 * rank
    zero = (0,) * degree
    one = (1,) + (0,) * (degree - 1)
    zeta = tuple(1 if i == 0 else -1 if i == degree // 2 else 0
                 for i in range(degree))
    U = [[tuple((2 * i + 3 * j + 5 * t + 1) % Q - Q // 2
                for t in range(degree)) for j in range(columns - rank)]
         for i in range(rank)]
    h = [tuple((i + 2 * t + 1) % Q for t in range(degree))
         for i in range(rank)]
    blocks = []
    for i in range(rank):
        row = []
        for j in range(rank):
            row.append(_mul_block(tuple(2 * a for a in (one if i == j else zero)), degree))
        for poly in U[i]:
            row.append(_mul_block(tuple(2 * a for a in poly), degree))
        final = tuple(Q * (zeta[t] if i == 0 else 0) - 2 * h[i][t]
                      for t in range(degree))
        row.append(_mul_block(final, degree))
        blocks.append(row)
    return matrix.block(blocks)


@pytest.mark.parametrize("degree", [4, 8])
@pytest.mark.parametrize("rank", [1, 2])
def test_direct_sage_matrix_image_and_index(degree, rank):
    Q = 15  # Composite and odd, so the check does not assume a field Q.
    full = _small_verification_matrix(degree, rank, Q)
    codimension = rank * degree - degree // 2
    cert = image_certificate(degree=degree, rank=rank, columns=4 * rank, Q=Q)

    assert matrix(GF(2), full).rank() == degree // 2
    for prime in (3, 5):
        assert matrix(GF(prime), full).rank() == rank * degree

    # Smith invariants of [full | 2Q*I] give the exact index of its
    # integer column lattice; this independently checks the CRT result.
    augmented = full.augment(2 * Q * matrix.identity(ZZ, rank * degree))
    divisors = augmented.elementary_divisors()
    index = ZZ.prod(abs(value) for value in divisors)
    assert index == 2**codimension
    image_size = (2 * Q)**(rank * degree) // index
    kernel_size = (2 * Q)**full.ncols() // image_size
    assert kernel_size == (Q**(degree * (4 * rank + 1 - rank))
                           * 2**(degree * (4 * rank + 1) - degree // 2))
    assert cert["mod_2Q"]["image_index_in_full_codomain"] == {
        "base": 2, "exponent": codimension}
    assert cert["mod_2Q"]["image_cardinality"] == {
        "Q_power": rank * degree, "two_power": degree // 2}
    assert cert["mod_2Q"]["kernel_cardinality"] == {
        "Q_power": degree * (4 * rank + 1 - rank),
        "two_power": degree * (4 * rank + 1) - degree // 2}


@pytest.mark.parametrize("degree", [4, 8])
def test_mod_two_ideal_and_annihilator_directly_in_sage(degree):
    from sage.all import PolynomialRing

    ring = PolynomialRing(GF(2), "x")
    x = ring.gen()
    modulus = x**degree + 1
    zeta = 1 - x**(degree // 2)
    assert modulus == (x + 1)**degree
    assert zeta == (x + 1)**(degree // 2)
    images, annihilator = set(), set()
    for coefficients in product((0, 1), repeat=degree):
        poly = ring(list(coefficients))
        value = (zeta * poly) % modulus
        images.add(tuple(value[i] for i in range(degree)))
        if value == 0:
            annihilator.add(coefficients)
    assert len(images) == len(annihilator) == 2**(degree // 2)


def test_original_rows_bind_literal_formula_without_security_upgrade():
    report = build_report()
    assert [row["profile"] for row in report["rows"]] == [
        "PARAM-I", "PARAM-II", "PARAM-III"]
    assert report["proof"] and report["security_claim"] == "none"
    for rank, row in zip((2, 3, 4), report["rows"]):
        assert row["matrix"] == "[2A | Q*zeta_star*e1-2h] mod 2Q"
        assert row["input"] == {
            "n": 512, "d": rank, "A_columns": 4 * rank,
            "verification_columns": 4 * rank + 1,
            "Q": 15744063, "verification_modulus": 31488126}
        assert row["mod_Q"]["coefficient_image_dimension"] == 512 * rank
        assert row["mod_2"]["coefficient_image_dimension"] == 256
        assert row["mod_2"]["coefficient_codimension"] == 512 * rank - 256
        assert row["mod_2Q"]["image_index_in_full_codomain"] == {
            "base": 2, "exponent": 512 * rank - 256}
        assert row["scope"]["paper_theorem_q_Q_2Q_mapping"] is None
        assert row["scope"]["accepted_Setup_or_seeded_planted_law"] is None
        assert row["scope"]["short_kernel_or_forgery_cost"] is None
        assert not row["scope"]["IBS_attack_or_security_inferred"]


@pytest.mark.parametrize("bad", [0, 1, 3, 513, True])
def test_rejects_nonoriginal_ring_shape(bad):
    with pytest.raises(ValueError):
        image_certificate(degree=bad, rank=2, columns=8, Q=15)


@pytest.mark.parametrize("bad", [0, 2, 4, True, 2**32 + 1])
def test_rejects_even_or_unbounded_Q(bad):
    with pytest.raises(ValueError):
        image_certificate(degree=4, rank=2, columns=8, Q=bad)
