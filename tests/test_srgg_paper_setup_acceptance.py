"""Exact, source-bound SRGG mathematical Setup acceptance checks."""

from fractions import Fraction
from itertools import permutations, product
from math import comb, factorial

import pytest
from sage.all import CyclotomicField, QQ

from experiments.research.candidates.srgg.paper_setup_acceptance import (
    build_report, row_certificate, wishart_trace_moment,
)


def _cycles(mapping):
    seen, count = set(), 0
    for start in range(len(mapping)):
        if start in seen:
            continue
        count += 1
        current = start
        while current not in seen:
            seen.add(current)
            current = mapping[current]
    return count


def test_hook_moment_matches_independent_permutation_formula():
    for a, b in ((1, 1), (2, 3), (4, 4)):
        for k in range(1, 7):
            cycle = tuple((j + 1) % k for j in range(k))
            direct = sum(
                a**_cycles(tuple(cycle[permutation[j]] for j in range(k)))
                * b**_cycles(permutation)
                for permutation in permutations(range(k))
            )
            variance = Fraction(3, 2)
            assert wishart_trace_moment(a, b, k, variance) == direct * variance**k


def test_cbd1_rotation_and_radial_moment_domination_exact_small_ring():
    n = 4
    field = CyclotomicField(2 * n)
    zeta = field.gen()
    weights = {-1: QQ(1) / 4, 0: QQ(1) / 2, 1: QQ(1) / 4}
    outcomes = []
    for coefficients in product((-1, 0, 1), repeat=n):
        probability = QQ(1)
        for coefficient in coefficients:
            probability *= weights[coefficient]
        value = sum((coefficients[j] * zeta**j for j in range(n)), field(0))
        rotated_coefficients = (-coefficients[-1],) + coefficients[:-1]
        rotated_value = sum((rotated_coefficients[j] * zeta**j
                             for j in range(n)), field(0))
        assert rotated_value == zeta * value
        outcomes.append((value, probability))
    assert sum((weight for _, weight in outcomes), QQ(0)) == 1
    for p, q in ((1, 0), (2, 0), (2, 1), (3, 0), (1, 1)):
        moment = sum((weight * value**p * value.conjugate()**q
                      for value, weight in outcomes), field(0))
        if p != q:
            assert moment == 0
        else:
            assert moment == n / 2
    for m in (1, 2, 3):
        radial = sum((weight * (value * value.conjugate())**m
                      for value, weight in outcomes), field(0))
        assert radial in QQ
        assert QQ(radial) <= factorial(m) * (QQ(n) / 2)**m
    for m in range(1, 29):
        assert 2 * factorial(2 * m) >= 4**m * factorial(m)


def test_paper_rows_recompute_moment_and_strict_retry_bounds():
    report = build_report()
    assert report["security_claim"] == "none"
    assert report["backend_admitted"] is False
    assert report["parameters_are_formal"] is False
    assert report["nist_security_category"] is None
    assert report["mathematical_positive_gate_bound_is_not_actual_backend_abort_bound"] is True
    expected = {
        "PARAM-I": (17, "13208769022924878363/2114511742034336",
                    3791147244535293048, 146),
        "PARAM-II": (22, "20467873059782430888/2292993012217061",
                     1754892461997895248, 217),
        "PARAM-III": (28, "6525839712757462581/564733141675732",
                      860971613569823322, 282),
    }
    assert [row["profile"] for row in report["rows"]] == list(expected)
    for row in report["rows"]:
        profile = row["profile"]
        k, threshold, dyadic_floor, bits = expected[profile]
        assert row == row_certificate(profile)
        assert row["interpretations"] == [
            "table-standard-deviation", "literal-density-width"]
        assert row["positive_gate_threshold_squared_exact"] == threshold
        assert row["moment_order"] == k
        assert row["conjugate_paired_blocks"] == 256
        a, b = row["Fourier_block_shape"]
        moment = wishart_trace_moment(a, b, k, Fraction(256))
        q = Fraction(row["mathematical_one_attempt_rejection_upper_exact"])
        assert moment == Fraction(row["complex_gaussian_wishart_trace_moment_exact"])
        assert q == 256 * moment / Fraction(threshold)**k
        assert dyadic_floor <= q * 2**64 < dyadic_floor + 1
        assert row["mathematical_one_attempt_rejection_upper_dyadic64_floor"] == dyadic_floor
        assert q < Fraction(1, 4)
        assert q**64 < Fraction(1, 2**bits)
        assert not q**64 < Fraction(1, 2**(bits + 1))
        assert row["mathematical_64_attempt_exhaustion_strict_dyadic_upper"] == f"2^-{bits}"
        assert row["actual_backend_success_set_vs_paper_positive_set_tv_upper"] is None
        assert row["actual_backend_interval_inconclusive_probability_upper"] is None
        assert row["actual_backend_setup_fault_or_abort_upper"] is None
        assert row["all_accepted_root_finite_source_schur_tv_upper"] is None


@pytest.mark.parametrize("argument", [0, -1, True, 65, 1.25])
def test_wishart_moment_rejects_invalid_order(argument):
    with pytest.raises(ValueError):
        wishart_trace_moment(4, 4, argument, 256)


def test_row_rejects_an_unknown_paper_profile():
    with pytest.raises(ValueError):
        row_certificate("PARAM-IV")
