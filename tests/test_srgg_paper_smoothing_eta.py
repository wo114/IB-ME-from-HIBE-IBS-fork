"""Original Table 4 smoothing-width source check, without parameter changes."""

from fractions import Fraction

import pytest
from sage.all import RealIntervalField

from experiments.research.candidates.srgg.paper_smoothing_eta import (
    EPSILON, M, PHYSICAL_BRACKET, ROUNDED_R, build_report, theta_bounds,
)


def test_original_largest_dimension_and_rounded_value():
    report = build_report()
    assert M == 10240 and EPSILON == Fraction(1, 1 << 24)
    assert report["source_rounded_r"] == str(ROUNDED_R)
    assert not report["formal_source_eta"]["printed_1_16_matches_formal_eta_definition"]
    assert report["hypothetical_physical_stddev_conversion"][
        "implicit_unit_conversion_explains_printed_two_decimals"]
    assert not report["formal_source_eta"]["exact_rounded_value_satisfies_smoothing"]
    assert not report["hypothetical_physical_stddev_conversion"][
        "exact_rounded_value_satisfies_smoothing"]
    assert report["security_claim"] == "none"
    assert report["nist_security_category"] is None


@pytest.mark.parametrize("convention", ["physical-standard-deviation",
                                       "literal-density-width"])
def test_bracket_orientation_is_independent_of_report_flags(convention):
    report = build_report()
    row = (report["hypothetical_physical_stddev_conversion"]
           if convention.startswith("physical") else report["formal_source_eta"])
    low = row["lower_endpoint"]
    high = row["upper_endpoint"]
    assert Fraction(low["theta_minus_one_lower_decimal_floor"]) > EPSILON
    assert Fraction(high["theta_minus_one_upper_decimal_ceiling"]) < EPSILON
    assert Fraction(row["width_open_bracket"][0]) < Fraction(row["width_open_bracket"][1])


def test_exact_product_theta_inside_reported_small_dimension_bounds():
    # Independent high-precision interval product for a case where the
    # binomial/geometric upper bound is available.
    field = RealIntervalField(1024)
    w = field(3) / 2
    a = (-2 * field.pi()**2 * w**2).exp()
    scalar = 1 + 2 * sum((a**(k*k) for k in range(1, 8)), field(0))
    truncated_product = scalar**3 - 1
    report = theta_bounds(width=Fraction(3, 2), dimension=3,
                          convention="physical-standard-deviation")
    low = field(report["theta_minus_one_lower_decimal_floor"])
    high = field(report["theta_minus_one_upper_decimal_ceiling"])
    assert low.upper() < truncated_product.lower()
    assert truncated_product.upper() < high.lower()


def test_monotonic_source_failure_is_separate_from_exact_eta():
    rounded = theta_bounds(width=ROUNDED_R, dimension=M,
                           convention="physical-standard-deviation")
    bracket_high = theta_bounds(width=PHYSICAL_BRACKET[1], dimension=M,
                                convention="physical-standard-deviation")
    assert Fraction(rounded["theta_minus_one_lower_decimal_floor"]) > EPSILON
    assert Fraction(bracket_high["theta_minus_one_upper_decimal_ceiling"]) < EPSILON


@pytest.mark.parametrize("kwargs", [
    {"width": 1, "dimension": 1, "convention": "physical-standard-deviation"},
    {"width": Fraction(-1), "dimension": 1, "convention": "physical-standard-deviation"},
    {"width": Fraction(1), "dimension": 0, "convention": "physical-standard-deviation"},
    {"width": Fraction(1), "dimension": 1, "convention": "unknown"},
])
def test_unchecked_input_rejected(kwargs):
    with pytest.raises(ValueError):
        theta_bounds(**kwargs)
