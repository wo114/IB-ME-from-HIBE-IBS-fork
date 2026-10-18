"""Finite original-Table-4 Setup positivity and retry preflight.

Algorithm 1 draws independent CBD1 coefficients for a 2d by wd ring matrix R.
For the *mathematical* SampleF residual after the rounding floor r^2 I,
Schur complementation gives the strict condition ||M(R)||_2^2 < L^2 below.
This module does not identify that event with successful numerical preparation
by either current Python/Sage backend, or with an accepted-root distribution.

The ordinary matrix-Bernstein bound is evaluated first.  A single alternative
uses a deterministic polynomial l1 gate to obtain an exact, albeit very small,
success lower bound.  Both results are kept, including their lack of useful
probability control at the author's parameters.  No entropy is drawn here.
"""
from __future__ import annotations

from fractions import Fraction
from hashlib import sha256
import json
from math import comb, isqrt
from pathlib import Path


SCHEMA = "IBME/SRGG-PAPER-SETUP-CONDITIONING-PREFLIGHT/1"
MAX_DEGREE = 512
MAX_MODULE_DIMENSION = 16
MAX_ATTEMPTS = 1024


def _positive_fraction(value, name):
    if isinstance(value, bool) or not (isinstance(value, (int, Fraction))
            or callable(getattr(value, "numerator", None))):
        raise ValueError("positive exact rational required: " + name)
    try:
        if callable(getattr(value, "numerator", None)):
            result = Fraction(int(value.numerator()), int(value.denominator()))
        else:
            result = Fraction(value)
    except (TypeError, ValueError, ZeroDivisionError, OverflowError):
        raise ValueError("positive exact rational required: " + name) from None
    if result <= 0 or max(result.numerator.bit_length(), result.denominator.bit_length()) > 4096:
        raise ValueError("positive bounded exact rational required: " + name)
    return result


def _integer(value, name, lower, upper):
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError("bounded integer required: " + name)
    return value


def residual_threshold_squared(first_squared, second_squared, r_squared, base):
    """Exact Schur threshold for D-r^2 I-b^2r^2[R;I][R* I] > 0.

    The lower block requires s2^2-r^2-b^2r^2>0.  With that condition, the
    upper Schur complement is positive iff ||R||_2^2 is strictly below L^2.
    All squared widths have the density-shape convention; a common positive
    scale (including the paper's pi interpretation) cancels from L^2.
    """
    first = _positive_fraction(first_squared, "first squared width")
    second = _positive_fraction(second_squared, "second squared width")
    rounding = _positive_fraction(r_squared, "rounding squared width")
    _integer(base, "gadget base", 2, 2**16)
    noise = base * base * rounding
    lower = second - rounding - noise
    if lower <= 0 or first <= rounding:
        raise ValueError("nonpositive root-independent residual diagonal")
    return (first-rounding)*lower/(noise*(second-rounding))


def matrix_bernstein_preflight(*, degree, rows, columns, threshold_squared):
    """Tropp rectangular dilation bound for independent CBD1 coefficients.

    Each coefficient contributes X(E_ij tensor C_k), with E[X]=0,
    E[X^2]=1/2 and each negacyclic C_k an orthogonal signed permutation.
    The dilation has dimension (rows+columns)n, norm-one summands and variance
    n*max(rows,columns)/2.  The standard tail is D exp(-t^2/(2v+2t/3)).
    The exact rational upper on its exponent proves the raw bound exceeds 1
    on the published rows, avoiding an unverified floating-point exponential.
    """
    _integer(degree, "degree", 2, MAX_DEGREE)
    _integer(rows, "rows", 1, MAX_MODULE_DIMENSION)
    _integer(columns, "columns", 1, MAX_MODULE_DIMENSION)
    threshold = _positive_fraction(threshold_squared, "threshold squared")
    variance = Fraction(degree * max(rows, columns), 2)
    exponent_strict_upper = threshold/(2*variance)
    ceiling = (exponent_strict_upper.numerator + exponent_strict_upper.denominator - 1)//exponent_strict_upper.denominator
    dimension = degree*(rows+columns)
    # e<4, so exp(-actual_exponent)>4^-ceiling.  This is only a
    # diagnostic lower bound on the raw Bernstein upper expression.
    raw_tail_lower = Fraction(dimension, 4**ceiling)
    if raw_tail_lower <= 1:
        raise ValueError("Bernstein diagnostic needs a directed exponential bound")
    return {"dilation_dimension": dimension,
        "variance_exact": str(variance), "one_summand_norm_upper": 1,
        "tail_formula": "min(1,D*exp(-L^2/(2*v+2*L/3)))",
        "exponent_strict_upper_exact": str(exponent_strict_upper),
        "raw_tail_lower_using_e_less_than_4_exact": str(raw_tail_lower),
        "failure_upper": "1", "success_lower": "0",
        "informative_at_this_row": False}


def sparse_l1_gate(*, degree, rows, columns, threshold_squared, attempts):
    """One independent alternative giving a compact exact success floor.

    A negacyclic polynomial with at most k nonzero CBD1 coefficients has
    convolution norm <=k.  If all rows*columns polynomials satisfy that cap,
    ||R||_2 <=sqrt(rows*columns)*k.  Each count is Binomial(n,1/2).
    We represent the tiny exact probability in power form, without expanding
    the enormous retry-failure numerator or claiming a useful Setup bound.
    """
    _integer(degree, "degree", 2, MAX_DEGREE)
    _integer(rows, "rows", 1, MAX_MODULE_DIMENSION)
    _integer(columns, "columns", 1, MAX_MODULE_DIMENSION)
    _integer(attempts, "attempts", 1, MAX_ATTEMPTS)
    threshold = _positive_fraction(threshold_squared, "threshold squared")
    blocks = rows*columns
    cap = min(degree, isqrt(threshold.numerator//(threshold.denominator*blocks)))
    while cap and blocks*cap*cap >= threshold:
        cap -= 1
    while cap < degree and blocks*(cap+1)*(cap+1) < threshold:
        cap += 1
    if blocks*cap*cap >= threshold:
        raise AssertionError("strict sparse gate construction failed")
    numerator = sum(comb(degree, j) for j in range(cap+1))
    denominator_power = degree*blocks
    one_attempt_numerator = numerator**blocks
    # 2^-k <= p, proved from integer bit lengths, with no logarithm rounding.
    dyadic_bits = denominator_power-(one_attempt_numerator.bit_length()-1)
    if dyadic_bits < 0:
        dyadic_bits = 0
    return {"polynomial_nonzero_cap": cap, "polynomial_count": blocks,
        "one_polynomial_binomial_numerator": str(numerator),
        "one_polynomial_denominator_power_of_two": degree,
        "one_attempt_success_lower_formula":
            f"({numerator}/2^{degree})^{blocks}",
        "one_attempt_success_lower_dyadic": f"2^-{dyadic_bits}",
        "dyadic_bits": dyadic_bits,
        "independent_attempts": attempts,
        "retry_exhaustion_upper_formula":
            f"(1-({numerator}/2^{degree})^{blocks})^{attempts}",
        "retry_exhaustion_upper_dyadic_formula": f"(1-2^-{dyadic_bits})^{attempts}",
        "retry_exhaustion_target_2_minus_128_certified": False,
        "conditioned_accepted_root_law_distance": None,
        "actual_numerical_sampler_success_lower": None,
        "useful_for_original_table4_acceptance_budget": False}


def build_report(*, setup_max_attempts=64):
    """Apply both bounded routes to the six original Table 4 interpretations."""
    _integer(setup_max_attempts, "operational Setup attempt limit", 1, MAX_ATTEMPTS)
    from .paper_parameters import PaperParams
    from .paper_profiles import profiles, SOURCE_PDF, SOURCE_SHA256

    root = Path(__file__).resolve().parents[4]
    if sha256((root / SOURCE_PDF).read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("frozen original paper checksum differs")
    results = []
    for source in profiles:
        interpretations = []
        for name in ("table-standard-deviation", "literal-density-width"):
            p = PaperParams(source.name, name)
            threshold = residual_threshold_squared(p.master_first_squared,
                p.master_second_squared, p.r_squared, p.base)
            interpretations.append((p, threshold))
        if interpretations[0][1] != interpretations[1][1]:
            raise AssertionError("common density scaling did not cancel")
        p, threshold = interpretations[0]
        rows, columns, n = 2*p.rank, p.digits*p.rank, p.degree
        per_attempt_bytes = rows*columns*n
        results.append({"profile": source.name, "rank": p.rank,
            "interpretations": [item[0].interpretation for item in interpretations],
            "threshold_squared_exact": str(threshold),
            "root_polynomial_shape": [rows, columns], "degree": n,
            "CBD1_coefficient_law": {"-1": "1/4", "0": "1/2", "1": "1/4"},
            "mathematical_gate": "||M(R)||_2^2 < L^2, strict",
            "matrix_bernstein": matrix_bernstein_preflight(degree=n,
                rows=rows, columns=columns, threshold_squared=threshold),
            "sparse_l1_alternative": sparse_l1_gate(degree=n, rows=rows,
                columns=columns, threshold_squared=threshold,
                attempts=setup_max_attempts),
            "CBD1_source_requested_bytes_per_attempt": per_attempt_bytes,
            "seed_requested_bytes": 32,
            "maximum_setup_requested_bytes": 32+setup_max_attempts*per_attempt_bytes,
            "retry_limit": setup_max_attempts,
            "assumes_fresh_independent_uniform_source_bytes": True,
            "runtime_success_probability_or_abort_budget": None,
            "accepted_setup_root_distribution_bound": None,
            "setup_numerical_preparation_covered": False,
            "reason": "positive residual is necessary for both current SampleF paths, but finite Fourier/series preparation and resource failures are separate events"})
    return {"schema": SCHEMA, "source_pdf": SOURCE_PDF,
        "source_sha256": SOURCE_SHA256,
        "paper_locations": "Table 3 p.6; Algorithm 1 p.7; Section 5.1 and Table 4 pp.9-10",
        "scope": "original mathematical Setup positivity and independent raw CBD1 retry envelope only",
        "rows": results, "source_parameters_unchanged": True,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None}


if __name__ == "__main__":
    print(json.dumps(build_report(), ensure_ascii=False, indent=2))
