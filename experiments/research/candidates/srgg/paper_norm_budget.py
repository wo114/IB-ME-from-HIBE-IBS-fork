"""Conditional norm/retry bounds for the SRGG paper's diagonal target law.

This does NOT identify an actual signature with that law.  Fix a key/history
and suppose the reference response is the *centered* discrete Gaussian
``Z ~ D_(Z^D, Sigma)``, density ``exp(-pi*z^T*Sigma^-1*z)``, where Sigma is
diagonal.  For one coordinate with shape lambda, Poisson summation gives

    rho_s(Z) = s * sum_k exp(-pi*s^2*k^2),       s=sqrt(lambda).

For 0<t<pi/lambda, put lambda_t=lambda/(1-t*lambda/pi).  The dual theta sum
decreases when lambda increases, so

    E exp(t*Z_i^2) = rho_sqrt(lambda_t)(Z)/rho_sqrt(lambda)(Z)
                    <= (1-t*lambda/pi)^(-1/2).

The centered diagonal law is a product, hence for groups (lambda_j,D_j),

    Pr[||Z||_2 >= gamma] <= exp(-t*gamma^2)
                          * product_j(1-t*lambda_j/pi)^(-D_j/2).

This argument needs no smoothing epsilon for the centered Z^D target.  It
does not apply unchanged to a shifted coset, a fiber, or the actual adaptive
Fiat--Shamir transcript.  In the paper the groups have D1=2*d*n and
D2=(w*d+1)*n.  A reported width s means lambda=s^2 in the literal-density
reading and lambda=2*pi*s^2 in the physical-standard-deviation reading.
Thus lambda/pi is s^2/pi or 2*s^2 respectively.  All transcendental work
below uses Sage's directed RealIntervalField; the selected t is rational.
The physical-standard-deviation reference shape is the exact real
2*pi*s^2, not PaperParams' rational midpoint approximation.  A bridge to
that backend must also cover its shape rounding difference.

If a supplied delta bounds the ENTIRE actual response-or-abort law against
this Gaussian uniformly for every eligible key and attempted history, an
attempt fails with probability <= tail+delta.  The probability that all K
attempts fail is then <= (tail+delta)^K by conditional probability, without
assuming independent keys/messages.  Fresh attempt randomness and the
uniform law premise remain requirements.  Without that premise the actual
budget is None.  HNF/key-law work can only be bypassed by proving this law
bound uniformly for every key/history that issuance may produce; no such
production bridge is asserted here.  The paper's r enters that bridge and
its smoothing conditions, not the diagonal-target MGF itself.

This is a zero-entropy arithmetic certificate.  It changes no backend,
profile, norm gate, sampler, witness or security-admission flag.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import json
from pathlib import Path
import re

from sage.all import RealIntervalField

from .paper_profiles import SOURCE_SHA256, profiles


SCHEMA = "IBME/SRGG-PAPER-NORM-BUDGET/1"
INTERPRETATIONS = ("literal-density-width", "table-standard-deviation")
PROBABILITY_BITS = 512
MAX_DIMENSION = 2**20


def _integer(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("bounded exact integer required: " + name)
    return value


def _rational(value, name, *, positive=True):
    if type(value) not in (int, Fraction, str):
        raise ValueError("exact integer, Fraction or plain rational string required: " + name)
    if isinstance(value, str) and (len(value) > 1024 or not re.fullmatch(
            r"[+]?[0-9]+(?:/[0-9]+|\.[0-9]+)?", value)):
        raise ValueError("plain finite rational required: " + name)
    try:
        result = Fraction(value)
    except (ValueError, ZeroDivisionError) as error:
        raise ValueError("finite rational required: " + name) from error
    if result < 0 or (positive and result == 0) or max(
            abs(result.numerator).bit_length(), result.denominator.bit_length()) > 4096:
        raise ValueError("rational range/resource limit exceeded: " + name)
    return result


def _fraction_endpoint(endpoint):
    # QQ(real) may select a nearby "simple" rational, which can collapse both
    # directed endpoints (e.g. 1/3) to the same non-dyadic value.  Preserve the
    # exact binary endpoint, not a rational reconstruction of it.
    exact = endpoint.exact_rational()
    return Fraction(int(exact.numerator()), int(exact.denominator()))


def _field(precision_bits):
    _integer(precision_bits, "precision_bits", 128, 1024)
    return RealIntervalField(precision_bits)


def _interval(field, value):
    return field(value.numerator) / value.denominator


def _groups(widths, multiplicities, interpretation, field):
    if interpretation not in INTERPRETATIONS or type(interpretation) is not str:
        raise ValueError("explicit Gaussian interpretation required")
    if not isinstance(widths, (tuple, list)) or not 1 <= len(widths) <= 8:
        raise ValueError("one to eight diagonal width groups required")
    if not isinstance(multiplicities, (tuple, list)) or len(widths) != len(multiplicities):
        raise ValueError("matching width/multiplicity groups required")
    exact = tuple(_rational(value, "width") for value in widths)
    counts = tuple(_integer(value, "multiplicity", 1, MAX_DIMENSION) for value in multiplicities)
    if sum(counts) > MAX_DIMENSION:
        raise ValueError("total diagonal dimension exceeds resource limit")
    coefficients = tuple(2 * _interval(field, width)**2
                         if interpretation == "table-standard-deviation"
                         else _interval(field, width)**2 / field.pi() for width in exact)
    return exact, counts, coefficients


def _log_mgf(field, coefficients, counts, t):
    t_value = _interval(field, t)
    terms = tuple(1 - t_value * coefficient for coefficient in coefficients)
    if any(term.lower() <= 0 for term in terms):
        raise ValueError("t must satisfy strict t*lambda/pi<1 in every group")
    return -sum(field(count) / 2 * term.log() for count, term in zip(counts, terms))


def diagonal_mgf_certificate(*, widths, multiplicities, t, interpretation,
                             precision_bits=256):
    """Directed log-MGF upper enclosure; centered integer diagonal law only."""
    field = _field(precision_bits)
    widths, counts, coefficients = _groups(widths, multiplicities, interpretation, field)
    t = _rational(t, "t")
    value = _log_mgf(field, coefficients, counts, t)
    return {
        "widths": list(map(str, widths)), "multiplicities": list(counts),
        "dimension": sum(counts), "interpretation": interpretation, "t": str(t),
        "log_mgf_continuous_majorant_lower": str(_fraction_endpoint(value.lower())),
        "log_mgf_upper": str(_fraction_endpoint(value.upper())),
        "strict_t_domain_certified": True, "centered_integer_target_only": True,
        "smoothing_epsilon_required_for_this_target_mgf": False,
        "precision_bits": precision_bits,
    }


def _select_t(field, coefficients, counts, cap, widths, interpretation):
    """At most 64 rational bisections; no global-optimization claim is needed."""
    scale = max(width * width for width in widths)
    physical = interpretation == "table-standard-deviation"
    low = Fraction(0)
    # For density widths t*max(s^2)<3<pi is strict.  For physical stddevs
    # t*max(s^2)<1/2 is strict.  Neither endpoint is an inferred parameter.
    high = Fraction(1, 2) - Fraction(1, 2**32) if physical else Fraction(3)
    normalized = tuple(coefficient / _interval(field, scale) for coefficient in coefficients)
    threshold = _interval(field, cap / scale)
    selected = high / 2
    for _ in range(64):
        selected = (low + high) / 2
        x = _interval(field, selected)
        derivative = -threshold + sum(field(count) / 2 * coefficient /
                                      (1 - x * coefficient)
                                      for count, coefficient in zip(counts, normalized))
        if derivative.upper() < 0:
            low = selected
        elif derivative.lower() > 0:
            high = selected
        else:
            break
    return selected / scale


def _probability_record(field, log_upper):
    """Round outward; tiny probabilities retain a visible transport floor."""
    log_upper = min(Fraction(0), log_upper)
    log_interval = _interval(field, log_upper)
    scale = 2**PROBABILITY_BITS
    # Avoid constructing exp(-M) as an exact fraction with Theta(M) denominator
    # bits.  Its logarithm is cheap even for bounded but very large inputs.
    # The comparison uses the lower endpoint of -B*log(2), so the shortcut
    # remains an outward upper bound throughout the directed enclosure.
    if log_interval.upper() <= (-field(PROBABILITY_BITS) * field(2).log()).lower():
        upper = Fraction(1, scale)
    else:
        probability = _fraction_endpoint(log_interval.exp().upper())
        numerator = -(-(probability.numerator * scale) // probability.denominator)
        upper = min(Fraction(1), Fraction(numerator, scale))
    log2_upper = _fraction_endpoint((log_interval / field(2).log()).upper())
    bits = max(0, (-log2_upper).__floor__())
    return {
        "probability_upper": str(upper), "natural_log_upper_exact": str(log_upper),
        "log2_upper_exact": str(log2_upper), "dyadic_bits_lower": bits,
        "probability_rounding_bits": PROBABILITY_BITS,
        "probability_transport_floor": str(Fraction(1, scale)),
        "rounded_probability_is_not_zero": upper > 0,
        "directed_interval_upper": True,
    }


def norm_tail_certificate(*, degree, rank, digits, first_width, second_width,
                          gamma, interpretation, retries=64,
                          uniform_per_history_tv=None, t=None, precision_bits=256):
    """Conditional paper-response norm certificate, with explicit bridge input."""
    n = _integer(degree, "degree", 2, 2**16)
    if n & (n - 1):
        raise ValueError("power-of-two polynomial degree required")
    d = _integer(rank, "rank", 1, 32)
    w = _integer(digits, "digits", 1, 32)
    retries = _integer(retries, "retries", 1, 4096)
    field = _field(precision_bits)
    widths, counts, coefficients = _groups((first_width, second_width),
        (2 * d * n, (w * d + 1) * n), interpretation, field)
    gamma = _rational(gamma, "gamma")
    cap = gamma * gamma
    selected = _select_t(field, coefficients, counts, cap, widths, interpretation) if t is None else _rational(t, "t")
    log_mgf = _log_mgf(field, coefficients, counts, selected)
    log_tail = log_mgf - _interval(field, selected * cap)
    log_upper = min(Fraction(0), _fraction_endpoint(log_tail.upper()))
    ideal = _probability_record(field, log_upper)
    ideal_retry = _probability_record(field, retries * log_upper)
    delta = None if uniform_per_history_tv is None else _rational(
        uniform_per_history_tv, "uniform_per_history_tv", positive=False)
    if delta is not None and delta > 1:
        raise ValueError("uniform_per_history_tv must lie in [0,1]")
    actual, actual_retry = None, None
    if delta is not None:
        failure = min(Fraction(1), Fraction(ideal["probability_upper"]) + delta)
        actual_log = _fraction_endpoint(_interval(field, failure).log().upper())
        actual = _probability_record(field, actual_log)
        actual_retry = _probability_record(field, retries * actual_log)
    return {
        "degree": n, "rank": d, "digits": w, "dimension": sum(counts),
        "widths": list(map(str, widths)), "multiplicities": list(counts),
        "gamma": str(gamma), "gamma_squared": str(cap), "interpretation": interpretation,
        "selected_rational_t": str(selected), "strict_t_domain_certified": True,
        "selection": "64 bounded derivative bisections" if t is None else "explicit input t",
        "norm_event": "||Z||_2>=gamma; also bounds reject ||Z||^2>floor(gamma^2)",
        "ideal_centered_diagonal_gaussian_tail": ideal,
        "retries": retries, "ideal_retry_exhaustion_conditional": ideal_retry,
        "uniform_per_history_tv_input": None if delta is None else str(delta),
        "actual_attempt_failure_upper_under_input_bridge": actual,
        "actual_retry_exhaustion_upper_under_input_bridge": actual_retry,
        "production_law_bridge_established_here": False,
        "bridge_is_input_premise_not_a_measured_distance": delta is not None,
        "requires_uniform_per_key_per_attempt_history_and_fresh_attempt_randomness": True,
        "hnf_key_distribution_is_not_identified_here": True,
        "r_smoothing_or_factor1_factor2_mapping_proved_here": False,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
    }


def build_report(*, uniform_per_history_tv=None):
    rows = []
    for profile in profiles:
        for interpretation in INTERPRETATIONS:
            row = norm_tail_certificate(degree=profile.degree, rank=profile.rank,
                digits=profile.digits, first_width=str(profile.signature_first_stddev),
                second_width=str(profile.signature_second_stddev), gamma=str(profile.gamma),
                interpretation=interpretation, uniform_per_history_tv=uniform_per_history_tv)
            row["profile"] = profile.name
            row["paper_r_rounded"] = str(profile.r_stddev)
            rows.append(row)
    return {
        "schema": SCHEMA, "paper_sha256": SOURCE_SHA256,
        "scope": "HIBE-independent conditional centered-target norm/retry arithmetic",
        "rows": rows, "actual_entropy_bytes": 0,
        "production_signature_law_identified": False,
        "table_stddev_reference_shape": "exact 2*pi*s^2; not backend rational midpoint",
        "actual_bridge_must_include_backend_shape_rounding": True,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(build_report(), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8", newline="\n")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
