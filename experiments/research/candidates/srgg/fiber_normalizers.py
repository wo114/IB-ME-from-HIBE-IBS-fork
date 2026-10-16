"""Uniform SRGG gadget-fiber normalizers and raw denominator-removal TV.

Pure exact rational certificates.  The only transcendental input is a proved
Machin-formula lower bound on pi; an elementary repeated-squaring inequality
bounds exp(-a) from above.  Decimal approximations are display-only.

The reference after removing the denominator is the NORMALIZED product-weight
law on the same approximate-fiber relation.  This module does not identify it
with a PSF, an exact-preimage Gaussian, an HNF key law, or a signature law.
"""

from __future__ import annotations

import argparse
from decimal import Decimal, localcontext
from fractions import Fraction
from functools import lru_cache
import json
from pathlib import Path


CERTIFICATE_BITS = 512
EXPONENT_SPLITS = 32
SCHEMA = "IBME/SRGG-FIBER-NORMALIZERS/1"


def _integer(value, name, low=1, high=2**20):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("bounded exact integer required: " + name)
    return value


def _rational(value, name):
    if type(value) not in (int, Fraction):
        raise ValueError("exact integer or Fraction required: " + name)
    result = Fraction(value)
    if max(result.numerator.bit_length(), result.denominator.bit_length()) > 4096:
        raise ValueError("rational input exceeds certificate resource limit")
    return result


def _ceil_dyadic(value, bits):
    scaled = Fraction(value) * 2**bits
    return Fraction(-(-scaled.numerator // scaled.denominator), 2**bits)


def _atan_partial_inverse(denominator, terms):
    return sum((Fraction((-1)**k, (2*k+1)*denominator**(2*k+1))
                for k in range(terms)), Fraction(0))


@lru_cache(maxsize=1)
def pi_lower():
    """Strict rational lower bound from 16 atan(1/5)-4 atan(1/239).

    An even-length alternating sum is a lower bound, an odd-length one an
    upper bound. The identity follows by tan(4 atan(1/5)-atan(1/239))=1
    and its angle being in (0,pi/2). No decimal pi literal is trusted.
    """
    return 16*_atan_partial_inverse(5, 32)-4*_atan_partial_inverse(239, 33)


def exp_negative_upper(exponent, *, bits=CERTIFICATE_BITS,
                       splits=EXPONENT_SPLITS):
    """Exact upper bound for exp(-exponent), exponent>=0.

    exp(-a) <= (1+a/2^splits)^(-2^splits). Start from the exact reciprocal
    and square `splits` times, rounding upward to a dyadic after every step.
    The rounding floor is deliberately visible in the resulting rational.
    """
    a = _rational(exponent, "nonnegative exponent")
    if a < 0:
        raise ValueError("nonnegative exponent required")
    _integer(bits, "certificate bits", 64, 2048)
    _integer(splits, "exponent splits", 1, 64)
    value = _ceil_dyadic(1/(1+a/Fraction(2**splits)), bits)
    for _ in range(splits):
        value = _ceil_dyadic(value*value, bits)
    return min(Fraction(1), value)


def raw_denominator_tv_upper(relative_sum):
    """Sharp range-only bound for normalizers in [C(1-x),C/(1-x)].

    A normalized product law tilts the original perturbation marginal by
    its gadget normalizer. The maximum TV over all weights in [L,H] is
    (sqrt(H)-sqrt(L))/(sqrt(H)+sqrt(L)). Here L*H=1, yielding x/(2-x).
    Deterministic raw-vector formation cannot increase this joint-law bound.
    """
    x = _rational(relative_sum, "relative normalizer sum")
    if not 0 <= x < 1:
        raise ValueError("relative normalizer sum must lie in [0,1)")
    return x/(2-x)


def decimal_display(value, *, digits=18):
    """Display only: never used to decide whether an inequality holds."""
    number = Fraction(value)
    with localcontext() as ctx:
        ctx.prec = digits
        return format(Decimal(number.numerator)/Decimal(number.denominator), ".12E")


def normalizer_certificate(*, degree, rank, base, digits, r_squared):
    """Every reachable fiber for F=p[I,bI,...,b^(w-1)I], Q=p*b^w.

    The certificate is independent of p and of the target. It uses the density
    exp(-pi*||x||^2/(b^2*r_squared)), coefficient-space Euclidean norm, and
    independent rank*degree coefficient fibers. r_squared>=1 is required.

    A vacuous result at x>=1 does not assert uniform closeness. The identity
    Z_F(s)=E_recursion product(z_state) still holds, but these chosen simple
    common-constant bounds do not establish a useful positive lower factor.
    """
    _integer(degree, "degree", high=2**16)
    _integer(rank, "rank", high=32)
    _integer(base, "gadget base", 2, 2**16)
    _integer(digits, "gadget digits", high=32)
    r2 = _rational(r_squared, "squared rounding width")
    if not 1 <= r2 <= 4096:
        raise ValueError("squared rounding width must lie in [1,4096]")
    coefficient_fibers, draws = degree*rank, degree*rank*digits
    _integer(draws, "total digit dimension", high=2**20)
    q = exp_negative_upper(pi_lower()*r2)
    # k^2 >= 1+3(k-1) for integer k>=1.
    scalar = _ceil_dyadic(2*q/(1-q**3), CERTIFICATE_BITS)
    x = draws*scalar
    useful = x < 1
    low, high, tv = ((1-x, 1/(1-x), raw_denominator_tv_upper(x))
                     if useful else (None, None, Fraction(1)))
    return {
        "degree": degree, "rank": rank, "base": base, "digits": digits,
        "r_squared": str(r2), "digit_width_squared": str(base**2*r2),
        "coefficient_fibers": coefficient_fibers, "total_digit_dimension": draws,
        "density": "exp(-pi*||x||^2/(b^2*r_squared))",
        "reachable_targets": "every coefficient is divisible by p modulo Q=p*b^w",
        "common_constant": {"exact_expression": "r^total_digit_dimension",
                            "squared_base": str(r2), "exponent": draws},
        "pi_lower_exact": str(pi_lower()),
        "exponential_q_upper_exact": str(q),
        "scalar_relative_deviation_upper_exact": str(scalar),
        "dimension_times_scalar_deviation_exact": str(x),
        "uniform_relative_lower_exact": None if low is None else str(low),
        "uniform_relative_upper_exact": None if high is None else str(high),
        "all_fiber_max_min_ratio_upper_exact": None if low is None else str(high/low),
        "raw_denominator_removal_tv_upper_exact": str(tv),
        "scalar_relative_deviation_upper_display": decimal_display(scalar),
        "dimension_times_scalar_deviation_display": decimal_display(x),
        "raw_denominator_removal_tv_upper_display": decimal_display(tv),
        "nontrivial_common_constant_certificate": useful,
        "uniform_in_all_reachable_targets": True,
        "uniform_in_trapdoor_and_perturbation_law": True,
        "certificate_bits": CERTIFICATE_BITS, "exponent_splits": EXPONENT_SPLITS,
        "assumptions": [
            "F is exactly p times the scalar powers-of-b gadget in coefficient space",
            "Q=p*b^w, sigma^2=b^2*r_squared, coefficient norm is Euclidean",
            "ideal digit coset Gaussians and ideal spherical conditional fiber law",
            "raw comparison uses the same approximate-fiber support and NORMALIZES the product law",
            "positive summable perturbation weights; raw output is a deterministic map",
        ],
        "not_certified": [
            "finite sampler approximation or abort, covered separately by existing certificates",
            "completed-square center normalizer, raw-to-PSF or HNF-key Gaussian law",
            "exact-preimage translation/mixture, image regularity, head wrap or norm success",
            "strong security, formal parameter admission or any NIST security category",
        ],
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False,
    }


def build_report():
    """Existing two n8 profiles and all three existing n512 conditional points.

    Only dimensions/base/r_squared affect this proof. Other sampler fields
    cannot change this ideal-fiber certificate and are deliberately excluded.
    """
    from .config import Config
    from .formal_candidates import conditional_candidate

    baseline = Config()
    points = [
        ("baseline-n8", baseline.degree, baseline.rank, baseline.base,
         baseline.digits, baseline.r_squared,
         "Config defaults / qualification_audit.profiles baseline-n8"),
        ("density-width3-n8", baseline.degree, baseline.rank, baseline.base,
         4, 9, "qualification_audit.profiles density-width3-n8: digits=4,r_squared=9"),
    ]
    for rank in (2, 3, 4):
        c = conditional_candidate(rank=rank)
        points.append((c.name, c.degree, c.rank, c.base, c.digits, c.r_squared,
                       "formal_candidates.conditional_candidate"))
    profiles = []
    for name, degree, rank, base, digits, r_squared, source in points:
        profiles.append({"name": name, "parameter_source": source,
                         **normalizer_certificate(degree=degree, rank=rank,
                             base=base, digits=digits, r_squared=r_squared)})
    return {
        "schema": SCHEMA, "profiles": profiles,
        "exact_inequalities": [
            "|z_a/r-1| <= 2*sum_(k>=1)exp(-pi*r_squared*k^2) <= t",
            "Z_F(s)/r^(w*d*n) in [1-x,1/(1-x)], x=w*d*n*t<1",
            "TV(ideal_raw,normalized_denominator_removed_raw) <= x/(2-x)",
        ],
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(build_report(), ensure_ascii=False, indent=2)+"\n"
    if args.output is None:
        print(encoded, end="")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")


if __name__ == "__main__":
    main()
