"""Independent algebra checks for the paper's zeta/shape correspondence."""
from fractions import Fraction
from itertools import product

import pytest

pytest.importorskip("sage.all")
from sage.all import QQ, RealIntervalField, identity_matrix, matrix

from experiments.research.candidates.srgg.paper_algebra import PaperRing
from experiments.research.candidates.srgg.paper_covariance_correspondence import (
    check_sample, coset_inverse, inverse_center, report, shape_balance,
    zeta_apply, zeta_star_apply,
)
from experiments.research.candidates.srgg.paper_parameters import PaperParams
from experiments.research.candidates.srgg.structured_geometry import signature_operator


def _independent_negacyclic_operator(poly):
    n = len(poly)
    result = matrix(QQ, n, n)
    for col in range(n):
        for coefficient, value in enumerate(poly):
            power = coefficient + col
            result[power % n, col] += value if power < n else -value
    return result


@pytest.mark.parametrize("n", (2, 4, 8))
def test_zeta_and_adjoint_match_independent_dense_ring_matrices(n):
    zeta = (1,) + (0,) * (n // 2 - 1) + (1,) + (0,) * (n // 2 - 1)
    Z = _independent_negacyclic_operator(zeta)
    star = Z.transpose()
    assert star * Z == 2 * identity_matrix(QQ, n)
    for trial in range(3):
        value = tuple((i * 3 + trial * 5) % 7 - 3 for i in range(n))
        assert zeta_apply(value) == tuple(Z * matrix(QQ, n, 1, value).column(0))
        assert zeta_star_apply(value) == tuple(star * matrix(QQ, n, 1, value).column(0))


@pytest.mark.parametrize("n", (2, 4))
def test_shift_energy_and_coset_inverse_exhaustive_small_ring(n):
    for u in product((-2, -1, 0, 1, 2), repeat=n):
        for c in product((0, 1), repeat=n):
            shifted = tuple(a + b for a, b in zip(zeta_apply(u), c))
            assert check_sample(u, c) == sum(x * x for x in shifted)
            assert coset_inverse(shifted, c) == u
            assert all(type(x) is Fraction for x in inverse_center(c))


def test_coset_parity_is_exactly_the_image_condition():
    for c in product((0, 1), repeat=2):
        for t in product(range(-3, 4), repeat=2):
            inverse = coset_inverse(t, c)
            allowed = ((t[0] - c[0]) - (t[1] - c[1])) % 2 == 0
            assert (inverse is not None) == allowed
            if inverse is not None:
                assert tuple(x + y for x, y in zip(zeta_apply(inverse), c)) == t


def test_original_degree_sparse_relation_and_actual_ring_implementation():
    p = PaperParams("PARAM-I", "literal-density-width")
    ring = PaperRing(p)
    n = p.degree
    u = (2,) + (0,) * (n // 2 - 1) + (-3,) + (0,) * (n // 2 - 1)
    c = (1,) + (0,) * (n - 1)
    assert ring.multiply(ring.zeta(), u) == zeta_apply(u)
    assert ring.multiply(ring.zeta(True), c) == zeta_star_apply(c)
    assert tuple(Fraction(-x, 2) for x in ring.multiply(ring.zeta(True), c)) == inverse_center(c)
    assert check_sample(u, c) == sum(x * x for x in ring.add(ring.multiply(ring.zeta(), u), c))
    assert coset_inverse((0,) * n, c) is None


@pytest.mark.parametrize("n", (2, 4))
def test_independent_dense_continuous_shape_accounting(n):
    zeta = (1,) + (0,) * (n // 2 - 1) + (1,) + (0,) * (n // 2 - 1)
    Z = _independent_negacyclic_operator(zeta)
    y = tuple((i % 3) - 1 for i in range(n))
    Y = _independent_negacyclic_operator(y)
    L = matrix(QQ, 2 * n, n)
    L[:n, :] = Y
    L[n:, :] = identity_matrix(QQ, n)
    s = QQ(29) ** 2 / (QQ(25) ** 2)
    target = 1000 * identity_matrix(QQ, 2 * n)
    paper_perturbation = target - s * L * L.transpose()
    output = paper_perturbation + s * L * Z * Z.transpose() * L.transpose()
    assert output == target + s * L * L.transpose()
    assert output[n:, n:] == (1000 + s) * identity_matrix(QQ, n)
    assert output != target
    hypothetical_factor_two = target - 2 * s * L * L.transpose()
    assert hypothetical_factor_two + s * L * Z * Z.transpose() * L.transpose() == target


@pytest.mark.parametrize("interpretation", ("literal-density-width", "table-standard-deviation"))
@pytest.mark.parametrize("name", ("PARAM-I", "PARAM-II", "PARAM-III"))
def test_both_code_width_conventions_preserve_relative_factor(name, interpretation):
    p = PaperParams(name, interpretation)
    s = p.r_squared
    assert Fraction(shape_balance(s)["zeta_u_shape"]) == 2 * s
    assert Fraction(shape_balance(s)["excess_over_target"]) == s
    assert Fraction(shape_balance(s, 2)["excess_over_target"]) == 0
    zero = (0,) * p.degree
    geometry = signature_operator(
        degree=p.degree, rank=p.rank, digits=p.digits,
        user_vector=(zero,) * p.columns,
        first_squared=p.signature_first_squared,
        second_squared=p.signature_second_squared,
        r_squared=p.r_squared, noise_factor=1,
    )
    assert geometry.noise_squared == QQ(s.numerator) / s.denominator
    assert geometry.rounding_squared == QQ(s.numerator) / s.denominator


@pytest.mark.parametrize("interpretation", ("literal-density-width", "table-standard-deviation"))
def test_pair_coset_normalizers_differ_for_both_original_width_readings(interpretation):
    p = PaperParams("PARAM-I", interpretation)
    s = p.r_squared
    F = RealIntervalField(256)
    s_interval = F(s.numerator) / F(s.denominator)
    pi = F.pi()
    cutoff = 32
    q = (-pi / (2 * s_interval)).exp()
    even = F(0)
    odd = F(0)
    for k in range(-cutoff, cutoff + 1):
        weight = q ** (k * k)
        if k % 2:
            odd += weight
        else:
            even += weight
    tail = 2 * q ** ((cutoff + 1) ** 2) / (1 - q ** (2 * cutoff + 3))
    assert (even - odd - tail).lower() > 0
    # A=E^2+O^2, B=2EO; A-B=(E-O)^2 > 0.
    assert ((even - odd - tail) ** 2).lower() > 0


def test_receipt_scope_and_input_validation():
    receipt = report()
    assert receipt["finite_ring"]["zeta_lattice_index"] == {"base": 2, "exponent": 256}
    assert receipt["finite_exact_checks"] == [
        {"degree": 2, "all_u_in": "{-1,0,1}^n", "all_binary_challenges": True, "checked_pairs": 36},
        {"degree": 4, "all_u_in": "{-1,0,1}^n", "all_binary_challenges": True, "checked_pairs": 1296},
        {"degree": 512, "checked_sparse_pairs": 4},
    ]
    assert [row["d"] for row in receipt["original_rows"]] == [2, 3, 4]
    assert receipt["continuous_shape_accounting"]["paper_output_excess_over_Sigma_bar_in_units_of_r_squared_LLstar"] == 1
    assert receipt["author_intended_resolution"] is None
    assert receipt["full_signature_law_bound"] is None
    assert receipt["security_claim"] == "none"
    assert receipt["backend_admitted"] is False
    assert receipt["parameters_are_formal"] is False
    with pytest.raises(ValueError):
        zeta_apply((1, 2, 3))
    with pytest.raises(ValueError):
        coset_inverse((1, 0), (0, 1, 0, 0))
    with pytest.raises(ValueError):
        shape_balance(0)
    with pytest.raises(ValueError):
        shape_balance(1, 3)
