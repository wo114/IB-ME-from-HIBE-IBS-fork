"""Contract arithmetic tests; no sampler, Gaussian, or security test claim."""

import json
from fractions import Fraction

import pytest

from experiments.research.chkp_t2_conditions import (
    _up_probability, ceil_log2, evaluate_sampling_conditions, main,
)


def example(**changes):
    values = dict(dimension=64, gs_sq_bound=16, width_sq=8192,
                  epsilon_bits=96, max_vectors=128,
                  scalar_tv="1/79228162514264337593543950336",
                  arithmetic_tv=0, failure_budget="1/1099511627776")
    values.update(changes)
    return evaluate_sampling_conditions(**values)


@pytest.mark.parametrize("n,k", [(1, 0), (2, 1), (3, 2), (4, 2),
                                    (5, 3), (2**100, 100), (2**100 + 1, 101)])
def test_ceil_log2(n, k):
    assert ceil_log2(n) == k


def test_example_checks_only_conditional_inequalities():
    result = example()
    assert result["integer_smoothing_factor"] == 104
    assert result["required_width_sq"] == "6656"
    assert result["width_sufficient"] and result["sampling_budget_sufficient"]
    assert not result["backend_admitted"]
    assert not result["input_certificates_verified"]
    assert result["security_claim"] == "none"
    assert result["unverified_obligations"]
    assert Fraction(result["bounds"]["randbasis_output_gs_sq_on_good_event"]) == 524288


def test_threshold_has_no_float_tolerance():
    assert example(width_sq=6656)["width_sufficient"]
    result = example(width_sq=Fraction(6656) - Fraction(1, 10**50))
    assert not result["width_sufficient"]
    assert result["bounds"] is None
    assert not result["sampling_budget_sufficient"]


def test_not_enough_rank_slack_is_not_admitted():
    result = example(max_vectors=64)
    assert result["width_sufficient"]
    assert not result["sampling_budget_sufficient"]
    assert result["bounds"]["randbasis_rank_or_norm_or_sampling_bad"] == "1"


@pytest.mark.parametrize("dim,bits", [(1, 2), (2, 3), (8, 10), (64, 96)])
def test_geometry_upper_bounds_exact_normalizer_ratio(dim, bits):
    result = example(dimension=dim, epsilon_bits=bits, max_vectors=dim + 64,
                     width_sq=10**8)
    actual_bound = min(1, (Fraction(2**bits + 1, 2**bits - 1)**dim - 1) / 2)
    assert Fraction(result["bounds"]["gpv_geometry_tv"]) >= actual_bound


def test_norm_rank_and_hybrid_arithmetic_against_independent_formula():
    result = example()
    bounds = result["bounds"]
    eps = Fraction(1, 2**96)
    assert Fraction(bounds["one_ideal_norm_tail"]) >= (1 + eps)/(1 - eps)/2**64
    assert Fraction(bounds["ideal_rank_exhaustion"]) >= Fraction(1, 2**64) + 256*eps
    total = (Fraction(bounds["ideal_rank_exhaustion"])
             + 128*Fraction(bounds["one_ideal_norm_tail"])
             + 128*Fraction(bounds["one_sample_tv"]))
    assert Fraction(bounds["randbasis_rank_or_norm_or_sampling_bad"]) == total


def test_scalar_abort_is_counted_once():
    first = example(scalar_tv=0)
    second = example(scalar_tv="1/1099511627776")
    delta = (Fraction(second["bounds"]["one_sample_tv"])
             - Fraction(first["bounds"]["one_sample_tv"]))
    assert delta == Fraction(64, 2**40)
    assert not second["sampling_budget_sufficient"]


def test_extra_arithmetic_error_cannot_disappear():
    result = example(arithmetic_tv="1/2")
    assert not result["sampling_budget_sufficient"]
    assert Fraction(result["bounds"]["one_sample_tv"]) >= Fraction(1, 2)


@pytest.mark.parametrize("value", [Fraction(0), Fraction(1, 10),
                                    Fraction(1, 2**1000), Fraction(1), Fraction(2)])
def test_probability_rounding_is_outward_and_capped(value):
    rounded = _up_probability(value, 96)
    assert min(value, 1) <= rounded <= 1
    if value > 0:
        assert rounded > 0


@pytest.mark.parametrize("changes", [
    {"dimension": True}, {"dimension": 0}, {"dimension": 1.0},
    {"dimension": 65537}, {"gs_sq_bound": 0}, {"gs_sq_bound": 1.0},
    {"width_sq": "NaN"}, {"width_sq": "1/0"}, {"width_sq": -1},
    {"epsilon_bits": 1}, {"epsilon_bits": 4097}, {"epsilon_bits": True},
    {"max_vectors": 63}, {"max_vectors": 1000000},
    {"scalar_tv": -1}, {"scalar_tv": "3/2"}, {"scalar_tv": 0.0},
    {"arithmetic_tv": -1}, {"failure_budget": 0}, {"failure_budget": "2"},
])
def test_reject_invalid_or_inexact_inputs(changes):
    with pytest.raises(ValueError):
        example(**changes)


def test_large_dimension_json_is_bounded_and_nonzero():
    result = example(dimension=65536, max_vectors=65664, width_sq=10**9)
    text = json.dumps(result)
    assert len(text) < 5000
    assert Fraction(result["bounds"]["one_ideal_norm_tail"]) > 0


@pytest.mark.parametrize("value", ["1e-5000", "1e100000000", "1.25",
                                    "1" * 5001, "1/" + "1" * 2501,
                                    "9" * 2500, 10**5000,
                                    Fraction(1, 1 << 8193)],
                         ids=["negative-exponent", "positive-exponent", "decimal",
                              "long-text", "long-component", "large-text-integer",
                              "large-integer", "large-fraction"])
def test_rational_resources_rejected_before_expansion_or_serialization(value):
    with pytest.raises(ValueError):
        example(gs_sq_bound=value)


def test_json_preserves_distinct_scalar_and_arithmetic_assumptions():
    first = example(scalar_tv=0, arithmetic_tv=Fraction(1, 2**70))
    second = example(scalar_tv=Fraction(1, 2**76), arithmetic_tv=0)
    assert first["bounds"] == second["bounds"]
    assert first["scalar_tv"] != second["scalar_tv"]
    assert first["arithmetic_tv"] != second["arithmetic_tv"]
    assert first["gs_sq_bound"] == second["gs_sq_bound"] == "16"


def test_largest_epsilon_precision_can_roundtrip_json():
    result = example(epsilon_bits=4096, width_sq=10**9,
                     scalar_tv=Fraction(1, 2**4096))
    assert json.loads(json.dumps(result))["scalar_tv"] == str(Fraction(1, 2**4096))


def test_cli_status_and_json(capsys):
    args = ["--dimension", "64", "--gs-sq-bound", "16", "--width-sq", "8192",
            "--epsilon-bits", "96", "--max-vectors", "128", "--scalar-tv", "0",
            "--arithmetic-tv", "0", "--failure-budget", "1/1099511627776"]
    assert main(args) == 0
    assert not json.loads(capsys.readouterr().out)["backend_admitted"]
    args[5] = "1"
    assert main(args) == 2
    assert json.loads(capsys.readouterr().out)["bounds"] is None
