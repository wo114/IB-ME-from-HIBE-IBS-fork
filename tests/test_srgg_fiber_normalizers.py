"""Independent common-normalizer and denominator-removal evidence."""

from decimal import Decimal, localcontext
from fractions import Fraction
from itertools import product

import pytest

from experiments.research.candidates.srgg.fiber_normalizers import (
    build_report, exp_negative_upper, normalizer_certificate, pi_lower,
    raw_denominator_tv_upper,
)


def _decimal(value):
    value = Fraction(value)
    return Decimal(value.numerator)/Decimal(value.denominator)


def test_rational_pi_lower_and_exp_upper_against_independent_decimal():
    # A display/reference comparison, supplementary to the rational proof.
    with localcontext() as ctx:
        ctx.prec = 90
        pi = Decimal("3.141592653589793238462643383279502884197169399375105820974944592307816406286208998628034825")
        assert Decimal("3.1415926535897932384626433832795028841971693") < _decimal(pi_lower()) < pi
        for value in (Fraction(0), Fraction(1, 100), Fraction(3),
                      Fraction(201), pi_lower()*64):
            bound = _decimal(exp_negative_upper(value))
            reference = (-_decimal(value)).exp()
            assert reference <= bound
            assert bound-reference < Decimal("0.00001")*max(reference, Decimal("1e-100"))


def test_all_nine_scalar_fibers_share_the_same_reference_constant():
    # Independently sum density weights directly; do not invoke the digit
    # recurrence used in the proof. b=3,w=2 gives all nine reachable classes.
    # A 37x37 box is sufficient here: its omitted one-coordinate Gaussian
    # tail is <2*exp(-pi*19^2/9)/(1-exp(-pi*39/9))<1e-53.
    cert = normalizer_certificate(degree=1, rank=1, base=3, digits=2, r_squared=1)
    with localcontext() as ctx:
        ctx.prec = 70
        pi = Decimal("3.141592653589793238462643383279502884197169399375105820974944592307816")
        weights = {k: (-pi*Decimal(k*k)/9).exp() for k in range(-18, 19)}
        normalizers = [Decimal(0)]*9
        for left, right in product(weights, repeat=2):
            normalizers[(left+3*right) % 9] += weights[left]*weights[right]
        lower = _decimal(Fraction(cert["uniform_relative_lower_exact"]))
        upper = _decimal(Fraction(cert["uniform_relative_upper_exact"]))
        # Common constant is r^2=1, identical for every target.
        assert all(lower < z < upper for z in normalizers)
        assert max(normalizers)-min(normalizers) > Decimal("0.01")


def test_reweighting_range_tv_is_sharp_for_reciprocal_endpoints():
    # Exact finite example attaining the stated range-only joint-law bound.
    x = Fraction(1, 5)
    low, high = 1-x, 1/(1-x)
    original = (Fraction(5, 9), Fraction(4, 9))
    tilted = (original[0]*low, original[1]*high)
    assert sum(tilted) == 1
    tv = sum(abs(p-q) for p, q in zip(original, tilted))/2
    assert tv == raw_denominator_tv_upper(x) == Fraction(1, 9)
    # Merging the two states into a single raw output contracts the TV.
    assert abs(sum(original)-sum(tilted))/2 == 0


def test_existing_profiles_have_nontrivial_certificates_without_security_admission():
    report = build_report()
    rows = {row["name"]: row for row in report["profiles"]}
    assert set(rows) == {"baseline-n8", "density-width3-n8",
                         "conditional-n512-d2-w8", "conditional-n512-d3-w8",
                         "conditional-n512-d4-w8"}
    for row in rows.values():
        x = Fraction(row["dimension_times_scalar_deviation_exact"])
        low = Fraction(row["uniform_relative_lower_exact"])
        high = Fraction(row["uniform_relative_upper_exact"])
        assert low == 1-x and low*high == 1
        assert Fraction(row["all_fiber_max_min_ratio_upper_exact"]) == high/low
        assert row["nontrivial_common_constant_certificate"]
        assert row["uniform_in_all_reachable_targets"]
        assert row["security_claim"] == "none"
        assert not row["backend_admitted"] and not row["parameters_are_formal"]
    assert Fraction(8, 100000) < Fraction(rows["baseline-n8"]["raw_denominator_removal_tv_upper_exact"]) < Fraction(9, 100000)
    assert Fraction(rows["density-width3-n8"]["raw_denominator_removal_tv_upper_exact"]) < Fraction(2, 10**11)
    assert Fraction(rows["conditional-n512-d2-w8"]["raw_denominator_removal_tv_upper_exact"]) < Fraction(1, 2**270)
    assert Fraction(rows["conditional-n512-d4-w8"]["raw_denominator_removal_tv_upper_exact"]) == raw_denominator_tv_upper(2*Fraction(rows["conditional-n512-d2-w8"]["dimension_times_scalar_deviation_exact"]))


def test_failed_small_width_large_dimension_screen_is_explicitly_vacuous():
    row = normalizer_certificate(degree=512, rank=2, base=31, digits=8, r_squared=1)
    assert not row["nontrivial_common_constant_certificate"]
    assert row["uniform_relative_lower_exact"] is None
    assert row["uniform_relative_upper_exact"] is None
    assert Fraction(row["raw_denominator_removal_tv_upper_exact"]) == 1


@pytest.mark.parametrize("change", [
    {"degree": True}, {"rank": 0}, {"base": 1}, {"digits": 0},
    {"r_squared": 4.0}, {"r_squared": Fraction(1, 2)}, {"degree": 2**17},
])
def test_input_types_and_certificate_budgets_are_enforced(change):
    values = dict(degree=8, rank=1, base=31, digits=3, r_squared=4)
    values.update(change)
    with pytest.raises(ValueError):
        normalizer_certificate(**values)


@pytest.mark.parametrize("value", [True, 0.2, Fraction(-1, 10), Fraction(1)])
def test_reweighting_requires_a_nonnegative_strictly_subunit_bound(value):
    with pytest.raises(ValueError):
        raw_denominator_tv_upper(value)
