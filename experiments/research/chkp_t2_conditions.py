"""Exact arithmetic for a CONDITIONAL CHKP/GPV sampling contract, not a sampler.

See docs/research/team-chkp/T2-算法来源与采样契约-2026-10-09.md.
The caller supplies a certified maximum squared Gram--Schmidt length and
uniform scalar/arithmetic error bounds. This calculator does NOT certify
those inputs, GenBasis, ToBasis, a HIBE backend, or any security level.
No secrets, random draws, floating-point arithmetic, or Sage are used.
"""

import argparse
import json
import re
from fractions import Fraction


def _int(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be a Python int in [{low}, {high}]")
    return value


def _rational(value, name, *, probability=False):
    if isinstance(value, bool) or not isinstance(value, (int, str, Fraction)):
        raise ValueError(f"{name} requires an exact int, fraction string, or Fraction")
    if isinstance(value, str):
        # Do not let Fraction expand unbounded scientific-notation exponents.
        # Each decimal component stays below Python's int-string guard too.
        if len(value) > 5000:
            raise ValueError(f"{name} exceeds the rational text limit")
        value = value.strip()
        if not re.fullmatch(r"[+-]?[0-9]+(?:/[0-9]+)?", value):
            raise ValueError(f"{name} requires integer or numerator/denominator text")
        if any(len(part.lstrip("+-")) > 2500 for part in value.split("/")):
            raise ValueError(f"{name} exceeds the rational component limit")
    elif max(abs(value.numerator).bit_length(), value.denominator.bit_length()) > 8192:
        raise ValueError(f"{name} exceeds the rational bit limit")
    try:
        result = Fraction(value)
    except (ValueError, ZeroDivisionError) as exc:
        raise ValueError(f"invalid exact rational for {name}") from exc
    if max(abs(result.numerator).bit_length(), result.denominator.bit_length()) > 8192:
        raise ValueError(f"{name} exceeds the rational bit limit")
    if result < 0 or (probability and result > 1):
        raise ValueError(f"{name} outside its nonnegative range")
    if not probability and result == 0:
        raise ValueError(f"{name} must be positive")
    return result


def ceil_log2(value):
    """Exact ceiling of log_2 of a positive integer."""
    if type(value) is not int or value < 1:
        raise ValueError("ceil_log2 expects a positive Python int")
    return (value - 1).bit_length()


def _up_probability(value, bits):
    """Outward rounding, never round a positive probability down to zero."""
    value = min(Fraction(1), value)
    scale = 1 << bits
    numerator = (value.numerator * scale + value.denominator - 1) // value.denominator
    return Fraction(numerator, scale)


def evaluate_sampling_conditions(*, dimension, gs_sq_bound, width_sq,
                                 epsilon_bits, max_vectors, scalar_tv,
                                 arithmetic_tv, failure_budget):
    """Check the document's stronger finite sufficient condition.

    Resource caps here bound calculator integer sizes, not cryptographic
    parameters. scalar_tv includes scalar abort/truncation/quantization;
    arithmetic_tv is extra whole-vector error, not counted inside scalar_tv.
    Missing certificates must NOT be represented by zero in a real audit.
    """
    dim = _int(dimension, "dimension", 1, 65536)
    bits = _int(epsilon_bits, "epsilon_bits", 2, 4096)
    count = _int(max_vectors, "max_vectors", dim, dim + 65536)
    gs_sq = _rational(gs_sq_bound, "gs_sq_bound")
    s_sq = _rational(width_sq, "width_sq")
    scalar = _rational(scalar_tv, "scalar_tv", probability=True)
    arithmetic = _rational(arithmetic_tv, "arithmetic_tv", probability=True)
    budget = _rational(failure_budget, "failure_budget", probability=True)
    if budget == 0:
        raise ValueError("failure_budget must be positive")

    scale = 1 << bits
    k = ceil_log2(2 * dim * (1 + scale))
    required_sq = 4 * gs_sq * k
    width_ok = s_sq >= required_sq
    result = {
        "scope": "conditional_finite_sampling_inequalities_only",
        "security_claim": "none",
        "backend_admitted": False,
        "input_certificates_verified": False,
        "dimension": dim,
        "epsilon_bits": bits,
        "max_vectors": count,
        "gs_sq_bound": str(gs_sq),
        "scalar_tv": str(scalar),
        "arithmetic_tv": str(arithmetic),
        "integer_smoothing_factor": k,
        "required_width_sq": str(required_sq),
        "provided_width_sq": str(s_sq),
        "width_sufficient": width_ok,
        "failure_budget": str(budget),
        "sampling_budget_sufficient": False,
        "bounds": None,
        "unverified_obligations": [
            "full_integer_basis_and_GS_certificate",
            "uniform_scalar_TV_including_abort_and_random_source",
            "adaptive_center_and_arithmetic_certificate",
            "AP09_GenBasis_variant_distribution_and_setup_failure",
            "ToBasis_full_lattice_and_GS_preservation",
            "level_schedules_and_HIBE_noise_and_lifetime_budgets",
            "security_reduction_mapping_and_attack_estimates",
        ],
    }
    if not width_ok:
        # No probability formula is advertised outside its sufficient domain.
        return result

    # ((1+eps)/(1-eps))**D - 1, divided by 2, is bounded by
    # D/(2**b - 2*D - 1) when the denominator is positive; else use 1.
    denominator = scale - 2 * dim - 1
    geometry = (Fraction(dim, denominator) if denominator > 0 else Fraction(1))
    geometry = _up_probability(geometry, bits)
    sample = _up_probability(geometry + dim * scalar + arithmetic, bits)
    ratio = Fraction(scale + 1, scale - 1)
    tail = _up_probability(ratio * Fraction(1, 1 << dim), bits)
    rank_ideal = _up_probability(Fraction(1, 1 << (count - dim))
                                + Fraction(2 * count, scale), bits)
    # A single K*sample hybrid covers both rank failure and the norm event.
    rand_bad = _up_probability(rank_ideal + count * tail + count * sample, bits)
    result["bounds"] = {
        "rounding": "each probability rounded UP to a multiple of 2^-epsilon_bits",
        "gpv_geometry_tv": str(geometry),
        "one_sample_tv": str(sample),
        "one_ideal_norm_tail": str(tail),
        "ideal_rank_exhaustion": str(rank_ideal),
        "randbasis_rank_or_norm_or_sampling_bad": str(rand_bad),
        "randbasis_output_gs_sq_on_good_event": str(s_sq * dim),
    }
    result["sampling_budget_sufficient"] = rand_bad <= budget
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dimension", type=int, required=True)
    parser.add_argument("--gs-sq-bound", required=True)
    parser.add_argument("--width-sq", required=True)
    parser.add_argument("--epsilon-bits", type=int, required=True)
    parser.add_argument("--max-vectors", type=int, required=True)
    parser.add_argument("--scalar-tv", required=True)
    parser.add_argument("--arithmetic-tv", required=True)
    parser.add_argument("--failure-budget", required=True)
    args = vars(parser.parse_args(argv))
    try:
        result = evaluate_sampling_conditions(**args)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["sampling_budget_sufficient"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
