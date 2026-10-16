"""Conditional SRGG ideal-issuance convolution bounds, without security admission.

The ideal sequential sampler is compared with the Gaussian on its approximate
preimage union S_h.  This is not a comparison with an exact PSF fiber, nor a
certificate for HNF, finite sampling, norm acceptance, or strong unforgeability.
All shapes use density exp(-pi*x^T*Sigma^-1*x).
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import json
from pathlib import Path

from .formal_candidates import conditional_candidate


SCHEMA = "IBME/SRGG-IDEAL-CONVOLUTION-BRIDGE/1"


def _integer(value, name, low=1, high=2**32):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("bounded exact integer required: " + name)
    return value


def _fraction(value, name, low=0, *, strict=False):
    if type(value) not in (int, Fraction):
        raise ValueError("exact rational required: " + name)
    value = Fraction(value)
    if max(abs(value.numerator).bit_length(), value.denominator.bit_length()) > 32768:
        raise ValueError("rational resource limit exceeded: " + name)
    if value < low or (strict and value == low):
        raise ValueError("rational lower bound violated: " + name)
    return value


def public_cbd1_t_squared_upper(degree, rank, digits):
    """For T=[M(R); I], CBD1 support implies ||T||_2^2 <= this value."""
    n = _integer(degree, "degree", high=2**16)
    d = _integer(rank, "rank", high=32)
    w = _integer(digits, "digits", high=32)
    return 2*d*d*w*n*n+1


def c_shape_lower_bound(sigma_squared, target_minimum_squared, t_squared_upper):
    """Conditional exact eigenvalue bound; no supplied witness cap is verified.

    For Sigma >= s I and ||T||_2^2 <= beta, require s>sigma^2*beta.
    Woodbury gives C=sigma^2 I-sigma^4 T^T Sigma^-1 T, hence the bound.
    """
    noise = _fraction(sigma_squared, "sigma_squared", strict=True)
    target = _fraction(target_minimum_squared, "target_minimum_squared", strict=True)
    beta = _fraction(t_squared_upper, "t_squared_upper", strict=True)
    if target <= noise*beta:
        raise ValueError("public sufficient residual positivity condition fails")
    return noise*(target-noise*beta)/target


def _dyadic_upper(value):
    """Small exact power-of-two envelope; avoids giant decimal certificates."""
    if value <= 0:
        raise ValueError("positive value required")
    numerator, denominator = value.numerator, value.denominator
    exponent = numerator.bit_length()-denominator.bit_length()
    covered = (numerator <= denominator << exponent) if exponent >= 0 else (
        numerator << -exponent <= denominator)
    if not covered:
        exponent += 1
    bound = Fraction(2**exponent) if exponent >= 0 else Fraction(1, 2**-exponent)
    return bound, exponent


def center_normalizer_certificate(dimension, c_lower, epsilon_bits=80):
    """Uniform-in-center theta bound from a certified minimum density shape.

    Floors c_lower before using pi>4*ln(2).  The implementation caps that floor
    at 1024 solely to bound rational arithmetic and serialized certificate size.
    Poisson gives |Theta_C(mu)/sqrt(det C)-1| <= rho_C(nonzero Z^m).
    """
    dimension = _integer(dimension, "dimension")
    c_lower = _fraction(c_lower, "c_lower", strict=True)
    epsilon_bits = _integer(epsilon_bits, "epsilon_bits", high=256)
    floor = c_lower.numerator//c_lower.denominator
    used = min(floor, 1024)
    result = {
        "dimension": dimension,
        "lambda_min_lower_exact": str(c_lower),
        "lambda_min_lower_floor": floor,
        "integer_shape_used": used,
        "epsilon_target": str(Fraction(1, 2**epsilon_bits)),
        "all_centers": True,
        "relative_error_upper_exact": None,
        "relative_error_upper_dyadic_exponent": None,
        "nontrivial_relative_lower_certified": False,
        "sufficient_smoothing_condition_passes": False,
        "method": "Poisson plus exact theta geometric bound; floor(lambda), pi>4*ln(2)",
        "scope": "C-normalizer only; excludes fiber mass, sampling and HNF",
    }
    if used < 1:
        result["blocker"] = "floor(lambda_min lower bound)=0; this certificate gives no bound"
        return result
    a = Fraction(1, 2**(4*used))
    t = 2*a/(1-a**3)
    x = dimension*t
    if x >= 1:
        result["blocker"] = "theta geometric-series sufficient condition dimension*t<1 fails"
        return result
    bound, exponent = _dyadic_upper(x/(1-x))
    result.update(relative_error_upper_exact=str(bound),
                  relative_error_upper_dyadic_exponent=exponent,
                  nontrivial_relative_lower_certified=bound < 1,
                  sufficient_smoothing_condition_passes=bound <= Fraction(1, 2**epsilon_bits))
    return result


def normalizer_ratio_tv_upper(fiber_lower, fiber_upper, center_lower, center_upper):
    """Exact conservative TV bound after final normalization of raw weights.

    Fiber masses/K_F lie in [fiber_lower,fiber_upper] and C-normalizers/K_C
    in [center_lower,center_upper], uniformly.  If a(u) is the raw reweight,
    L<=a<=U, then TV(Q*a/E_Q[a],Q)<=min(1,(U-L)/(2*L)).
    """
    fl = _fraction(fiber_lower, "fiber_lower", strict=True)
    fu = _fraction(fiber_upper, "fiber_upper", strict=True)
    cl = _fraction(center_lower, "center_lower", strict=True)
    cu = _fraction(center_upper, "center_upper", strict=True)
    if fl > fu or cl > cu:
        raise ValueError("ordered relative normalizer bounds required")
    lower, upper = cl/fu, cu/fl
    return min(Fraction(1), (upper-lower)/(2*lower))


def normalizer_tv_upper(epsilon_fiber, epsilon_center):
    """Symmetric-error corollary (eps_F+eps_C)/((1-eps_F)(1-eps_C))."""
    ef = _fraction(epsilon_fiber, "epsilon_fiber")
    ec = _fraction(epsilon_center, "epsilon_center")
    if ef >= 1 or ec >= 1:
        raise ValueError("normalizer relative errors must be smaller than one")
    return normalizer_ratio_tv_upper(1-ef, 1+ef, 1-ec, 1+ec)


def bridge_certificate(*, degree, rank, base, digits, r_squared,
                       master_minimum_squared, fiber_lower=None, fiber_upper=None,
                       t_squared_upper=None, witness_bound_origin=None, epsilon_bits=80):
    """Public-shape or explicitly conditional witness-cap certificate.

    Custom t_squared_upper is an input assumption, never an authenticated
    witness certificate.  No trapdoor or witness matrix is read or exported.
    """
    n = _integer(degree, "degree", high=2**16)
    d = _integer(rank, "rank", high=32)
    b = _integer(base, "base", low=2, high=2**16-1)
    w = _integer(digits, "digits", high=32)
    r2 = _fraction(r_squared, "r_squared", strict=True)
    target = _fraction(master_minimum_squared, "master_minimum_squared", strict=True)
    _integer(epsilon_bits, "epsilon_bits", high=256)
    dimension = _integer(w*d*n, "gadget coefficient dimension")
    if (fiber_lower is None) != (fiber_upper is None):
        raise ValueError("both fiber bounds or neither must be supplied")
    if fiber_lower is not None:
        fiber_lower = _fraction(fiber_lower, "fiber_lower", strict=True)
        fiber_upper = _fraction(fiber_upper, "fiber_upper", strict=True)
        if fiber_lower > fiber_upper:
            raise ValueError("ordered fiber normalizer bounds required")
    if t_squared_upper is None:
        if witness_bound_origin is not None:
            raise ValueError("custom origin without custom witness cap")
        beta = Fraction(public_cbd1_t_squared_upper(n, d, w))
        origin = "all CBD1 root witnesses; public Frobenius class bound plus stacked identity"
        verified = True
    else:
        beta = _fraction(t_squared_upper, "t_squared_upper", low=1)
        if not isinstance(witness_bound_origin, str) or not 1 <= len(witness_bound_origin) <= 256:
            raise ValueError("explicit bounded origin for supplied witness cap required")
        origin, verified = witness_bound_origin, False
    noise = b*b*r2
    positive = target > noise*beta
    lower = c_shape_lower_bound(noise, target, beta) if positive else None
    center = center_normalizer_certificate(dimension, lower, epsilon_bits) if positive else None
    ec = None if center is None or center["relative_error_upper_exact"] is None else Fraction(
        center["relative_error_upper_exact"])
    tv = normalizer_ratio_tv_upper(fiber_lower, fiber_upper, 1-ec, 1+ec) if (
        ec is not None and ec < 1 and fiber_lower is not None) else None
    return {
        "parameters": {"degree": n, "rank": d, "base": b, "digits": w,
                       "r_squared": str(r2), "master_minimum_squared": str(target)},
        "N": (2+w)*d*n, "m": dimension,
        "sigma_squared": str(noise), "t_spectral_squared_upper": str(beta),
        "witness_bound_origin": origin, "witness_class_bound_derived_here": verified,
        "actual_witness_cap_verified": False,
        "residual_minimum_lower_exact": str(target-noise*beta),
        "sufficient_residual_positive": positive,
        "C_lambda_min_lower_exact": None if lower is None else str(lower),
        "center_normalizer": center,
        "fiber_normalizer_lower_exact": None if fiber_lower is None else str(fiber_lower),
        "fiber_normalizer_upper_exact": None if fiber_upper is None else str(fiber_upper),
        "ideal_raw_to_union_gaussian_tv_upper_exact": None if tv is None else str(tv),
        "reference": "rho_Sigma normalized on approximate preimage union S_h; not exact PSF fiber",
        "ideal_raw_bridge_has_nontrivial_bound": tv is not None and tv < 1,
        "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False,
    }


def build_report():
    # Only shape fields are used; importing a lifecycle runner would needlessly
    # load service and wire code into this entropy-free arithmetic tool.
    from dataclasses import replace
    from .config import Config
    from .fiber_normalizers import decimal_display, normalizer_certificate

    result = []
    baseline = Config()
    configs = [("baseline-n8", baseline),
               ("density-width3-n8", replace(baseline, digits=4, r_squared=9,
                   signature_first_squared=2**38, signature_second_squared=2**38))]+[
        (f"conditional-n512-d{d}", conditional_candidate(rank=d)) for d in (2, 3, 4)]
    for name, config in configs:
        fiber = normalizer_certificate(degree=config.degree, rank=config.rank, base=config.base,
                                       digits=config.digits, r_squared=config.r_squared)
        fl, fu = (fiber.get("uniform_relative_lower_exact"),
                  fiber.get("uniform_relative_upper_exact"))
        row = bridge_certificate(degree=config.degree, rank=config.rank, base=config.base,
            digits=config.digits, r_squared=config.r_squared,
            master_minimum_squared=min(config.master_first_squared, config.master_second_squared),
            fiber_lower=None if fl is None else Fraction(fl),
            fiber_upper=None if fu is None else Fraction(fu))
        row.update(name=name, fiber_certificate_scope="ideal gadget all reachable fibers")
        raw_tv = row["ideal_raw_to_union_gaussian_tv_upper_exact"]
        row["ideal_raw_to_union_gaussian_tv_upper_display"] = (
            None if raw_tv is None else decimal_display(raw_tv))
        result.append(row)
    return {
        "schema": SCHEMA, "scope": "conditional ideal sequential issuance; no cryptographic execution",
        "profiles": result,
        "unclosed_conditions": [
            "finite sequential-sampler approximation and abort composition",
            "HNF output versus an explicit exact-fiber PSF conditional reference",
            "trapdoor independence, Gaussian norm acceptance and head-wrap losses",
            "source normalization, strong-security premises and formal parameter estimation",
        ],
        "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(build_report(), ensure_ascii=False, indent=2, sort_keys=True)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8", newline="\n")
    print(encoded, end="")


if __name__ == "__main__":
    main()
