"""Mathematical and input-boundary checks for conditional paper norm tails."""

from fractions import Fraction
import json

import pytest

sage = pytest.importorskip("sage.all", reason="requires designated WSL Sage interval arithmetic")

from experiments.research.candidates.srgg.paper_norm_budget import (
    _fraction_endpoint, build_report, diagonal_mgf_certificate, norm_tail_certificate,
)


def _small(**changes):
    values = dict(degree=2, rank=1, digits=1, first_width=2,
                  second_width=1, gamma=10, interpretation="literal-density-width")
    values.update(changes)
    return norm_tail_certificate(**values)


def test_exact_binary_endpoints_strictly_enclose_independent_high_precision_third():
    coarse = sage.RealIntervalField(128)(1) / 3
    lower, upper = map(_fraction_endpoint, (coarse.lower(), coarse.upper()))
    fine_field = sage.RealIntervalField(512)
    fine = fine_field(1) / 3
    lower_value = fine_field(lower.numerator) / lower.denominator
    upper_value = fine_field(upper.numerator) / upper.denominator
    assert lower_value.upper() < fine.lower()
    assert fine.upper() < upper_value.lower()
    assert lower != upper


def test_directed_log_mgf_encloses_independent_higher_precision_formula():
    result = diagonal_mgf_certificate(widths=(2, 1), multiplicities=(4, 6),
        t=Fraction(1, 100), interpretation="literal-density-width", precision_bits=128)
    field = sage.RealIntervalField(512)
    reference = -2 * (1 - field(4) / (100 * field.pi())).log() - 3 * (
        1 - field(1) / (100 * field.pi())).log()
    lower = Fraction(result["log_mgf_continuous_majorant_lower"])
    upper = Fraction(result["log_mgf_upper"])
    assert (field(lower.numerator) / lower.denominator).upper() < reference.lower()
    assert reference.upper() < (field(upper.numerator) / upper.denominator).lower()


@pytest.mark.parametrize("width", [Fraction(1, 2), Fraction(1), Fraction(3, 2)])
@pytest.mark.parametrize("interpretation", ["literal-density-width", "table-standard-deviation"])
def test_scalar_poisson_mgf_majorant_exceeds_finite_enumeration(width, interpretation):
    field = sage.RealIntervalField(256)
    t = Fraction(1, 40)
    result = diagonal_mgf_certificate(widths=(width,), multiplicities=(1,), t=t,
        interpretation=interpretation)
    shape = (field(width.numerator) / width.denominator)**2 * (
        2 * field.pi() if interpretation == "table-standard-deviation" else 1)
    weights = [(-field.pi() * k*k / shape).exp() for k in range(-32, 33)]
    moment = sum(weight * (field(t.numerator) / t.denominator * k*k).exp()
                 for k, weight in zip(range(-32, 33), weights)) / sum(weights)
    upper = Fraction(result["log_mgf_upper"])
    majorant = (field(upper.numerator) / upper.denominator).exp()
    assert moment.upper() < majorant.lower()
    assert result["strict_t_domain_certified"]
    assert not result["smoothing_epsilon_required_for_this_target_mgf"]


def test_grouped_widths_equal_coordinatewise_log_majorant():
    grouped = diagonal_mgf_certificate(widths=(2, 1), multiplicities=(4, 6),
        t=Fraction(1, 100), interpretation="table-standard-deviation")
    singles = diagonal_mgf_certificate(widths=(2, 2, 2, 2, 1, 1, 1, 1),
        multiplicities=(1, 1, 1, 1, 1, 1, 1, 3), t=Fraction(1, 100),
        interpretation="table-standard-deviation")
    assert grouped["dimension"] == singles["dimension"] == 10
    # Independent interval summation orders may differ by outward rounding.
    difference = abs(Fraction(grouped["log_mgf_upper"]) - Fraction(singles["log_mgf_upper"]))
    assert difference < Fraction(1, 2**240)


def test_published_groups_and_two_interpretations_keep_actual_bridge_missing():
    report = build_report()
    assert len(report["rows"]) == 6
    assert report["actual_bridge_must_include_backend_shape_rounding"]
    json.dumps(report)
    physical_bits = []
    for row in report["rows"]:
        d = row["rank"]
        assert row["multiplicities"] == [2*d*512, (2*d+1)*512]
        assert row["dimension"] == ((2+2)*d+1)*512
        assert row["retries"] == 64
        assert row["actual_attempt_failure_upper_under_input_bridge"] is None
        assert row["actual_retry_exhaustion_upper_under_input_bridge"] is None
        assert not row["production_law_bridge_established_here"]
        assert row["security_claim"] == "none" and row["parameters_are_formal"] is False
        assert row["backend_admitted"] is False and row["nist_security_category"] is None
        tail = row["ideal_centered_diagonal_gaussian_tail"]
        assert 0 < Fraction(tail["probability_upper"]) < 1
        assert Fraction(row["selected_rational_t"]) > 0
        if row["interpretation"] == "table-standard-deviation":
            physical_bits.append(tail["dyadic_bits_lower"])
        else:
            assert tail["dyadic_bits_lower"] > 1000
            assert Fraction(tail["probability_upper"]) == Fraction(1, 2**512)
    assert physical_bits == [1, 2, 2]


def test_explicit_uniform_bridge_and_conditional_retries_do_not_claim_production_law():
    result = _small(uniform_per_history_tv=Fraction(1, 1000))
    ideal = Fraction(result["ideal_centered_diagonal_gaussian_tail"]["probability_upper"])
    actual = Fraction(result["actual_attempt_failure_upper_under_input_bridge"]["probability_upper"])
    retry = Fraction(result["actual_retry_exhaustion_upper_under_input_bridge"]["probability_upper"])
    assert actual >= ideal + Fraction(1, 1000)
    assert retry >= actual**64
    assert retry < actual
    assert result["bridge_is_input_premise_not_a_measured_distance"]
    assert not result["production_law_bridge_established_here"]
    vacuous = _small(uniform_per_history_tv=1)
    assert vacuous["actual_attempt_failure_upper_under_input_bridge"]["probability_upper"] == "1"
    assert vacuous["actual_retry_exhaustion_upper_under_input_bridge"]["probability_upper"] == "1"


@pytest.mark.parametrize("bad", [True, 0, -1, 0.1, float("nan"), "NaN", "Infinity", "1e-4", "1/0"])
def test_nonexact_or_nonpositive_t_rejected(bad):
    with pytest.raises(ValueError):
        _small(t=bad)


@pytest.mark.parametrize("interpretation,t", [
    ("table-standard-deviation", Fraction(1, 8)),
    ("table-standard-deviation", Fraction(1, 7)),
    ("literal-density-width", Fraction(1)),
])
def test_t_at_or_beyond_mgf_pole_is_rejected(interpretation, t):
    with pytest.raises(ValueError, match="strict"):
        _small(interpretation=interpretation, t=t)


@pytest.mark.parametrize("change", [dict(first_width=True), dict(gamma="NaN"),
    dict(first_width=2.0), dict(degree=True), dict(retries=True),
    dict(uniform_per_history_tv=True), dict(uniform_per_history_tv="1.01"),
    dict(precision_bits=True), dict(interpretation="guess")])
def test_unsafe_inputs_reject_without_any_sampler(change):
    with pytest.raises(ValueError):
        _small(**change)


def test_loose_gamma_produces_vacuous_one_without_zero_probability():
    result = _small(gamma=Fraction(1, 10), interpretation="table-standard-deviation")
    tail = result["ideal_centered_diagonal_gaussian_tail"]
    assert tail["probability_upper"] == "1"
    assert tail["dyadic_bits_lower"] == 0
    assert tail["rounded_probability_is_not_zero"]


def test_very_large_gamma_keeps_log_bound_without_constructing_huge_probability_fraction():
    result = _small(gamma=2**2048)
    tail = result["ideal_centered_diagonal_gaussian_tail"]
    assert tail["probability_upper"] == str(Fraction(1, 2**512))
    assert tail["rounded_probability_is_not_zero"]
    assert tail["dyadic_bits_lower"] > 2**4000
