"""Exact CBD1 law and public noisy-column bounds modulo 3; no hardness claim.

The bound compares (uniform projected Ahat, Ahat*S+E) to (Ahat,uniform V)
at one factor and both CRT factors jointly, including independent columns
sharing Ahat. It says nothing about 3**w for w>1, other primes, the complete
MLWE distribution, or the IBS security game.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
from hashlib import sha256
from itertools import product
import json
from pathlib import Path
import platform


SCHEMA = "IBME/SRGG-CBD1-MOD3-PROJECTION/1"
CBD1 = {-1: Fraction(1, 4), 0: Fraction(1, 2), 1: Fraction(1, 4)}


def _parameters(degree, rank):
    if type(degree) is not int or not 4 <= degree <= 2**16 or degree & (degree-1):
        raise ValueError("power-of-two degree in [4,2**16] required")
    if type(rank) is not int or not 1 <= rank <= 32:
        raise ValueError("exact module rank in [1,32] required")
    return degree, rank


def _sign(sign):
    if type(sign) is not int or sign not in (-1, 1):
        raise ValueError("factor sign must be exact -1 or +1")
    return sign


def project_block(coefficients, *, sign):
    """Four CBD1 coefficients at j,j+k,j+2k,j+3k, k=n/4."""
    _sign(sign)
    if type(coefficients) is not tuple or len(coefficients) != 4:
        raise ValueError("four exact CBD1 coefficients required")
    if any(type(x) is not int or x not in CBD1 for x in coefficients):
        raise ValueError("exact CBD1 coefficients required")
    a, b, c, d = coefficients
    return (a+c-sign*d) % 3, (b-sign*c-d) % 3


def project_polynomial(coefficients, *, sign):
    """Actual reduction modulo X^(n/2)+sign*X^(n/4)-1 over F3."""
    if type(coefficients) is not tuple:
        raise ValueError("exact CBD1 polynomial tuple required")
    n, _ = _parameters(len(coefficients), 1)
    _sign(sign)
    if any(type(x) is not int or x not in CBD1 for x in coefficients):
        raise ValueError("exact CBD1 coefficients required")
    k = n//4
    blocks = tuple(project_block(tuple(coefficients[j+i*k] for i in range(4)), sign=sign)
        for j in range(k))
    return tuple(x[0] for x in blocks)+tuple(x[1] for x in blocks)


def enumerate_block_law(*, sign):
    """Exhaust all 81 weighted CBD1 inputs, without sampling."""
    _sign(sign)
    result = {pair: Fraction(0) for pair in product(range(3), repeat=2)}
    for values in product((-1, 0, 1), repeat=4):
        weight = Fraction(1)
        for value in values:
            weight *= CBD1[value]
        result[project_block(values, sign=sign)] += weight
    return result


def _pack(value):
    # No decimal conversion or process-wide integer digit limit modification.
    return {"numerator_hex": hex(value.numerator), "denominator_hex": hex(value.denominator)}


def _dyadic_sqrt_upper(square):
    """Largest b with square<=2^(-2b); no floating point or underflow."""
    if square == 0:
        return None, Fraction(0)
    bits = max(0, (square.denominator.bit_length()-square.numerator.bit_length())//2)
    while bits and (square.numerator << (2*bits)) > square.denominator:
        bits -= 1
    while (square.numerator << (2*(bits+1))) <= square.denominator:
        bits += 1
    return bits, Fraction(1, 2**bits)


def projection_certificate(*, degree, rank, columns=1):
    """Uniform-Ahat noisy-hash bounds for actual independent CBD1 S,E.

    Let t=3^(dn/2), c=(57/512)^(dn/4), C=(3/8)^(dn).
    One factor has average chi-square c*(t*c-1). Both factors jointly
    have t²*C²+2*t*c*(c-C)-2*c+C, although their CBD1 projections are
    dependent. TV² is at most chi-square/4. For ell independent columns
    given the same Ahat, a conditional hybrid gives ell times the single
    column TV bound, capped at 1.
    The average is over the public Ahat, not a pointwise bound for every Ahat.
    """
    n, d = _parameters(degree, rank)
    if type(columns) is not int or not 1 <= columns <= 2**16:
        raise ValueError("exact column count in [1,2**16] required")
    blocks = n*d//4
    collision = Fraction(57, 512)**blocks
    full_collision = Fraction(3, 8)**(n*d)
    output_size = 3**(n*d//2)
    chi_square = collision*(output_size*collision-1)
    square = chi_square/4
    bits, upper = _dyadic_sqrt_upper(square)
    multi_square = min(Fraction(1), columns**2*square)
    multi_bits, multi_upper = _dyadic_sqrt_upper(multi_square)
    full_chi_square = (output_size**2*full_collision**2
        + 2*output_size*collision*(collision-full_collision)-2*collision+full_collision)
    full_square = full_chi_square/4
    full_bits, full_upper = _dyadic_sqrt_upper(full_square)
    full_multi_square = min(Fraction(1), columns**2*full_square)
    full_multi_bits, full_multi_upper = _dyadic_sqrt_upper(full_multi_square)
    return {"schema": SCHEMA, "degree": n, "rank": d, "columns": columns,
        "modulus_projected_to": 3, "factor_degree": n//2,
        "factor_polynomials": ["X^(n/2)+X^(n/4)-1", "X^(n/2)-X^(n/4)-1"],
        "factor_is_irreducible_by_ord_2n_3_equals_n_over_2": True,
        "independent_projected_pairs_per_poly": n//4,
        "independent_pairs_per_secret_or_error_vector": blocks,
        "pair_law_zero_exact": _pack(Fraction(1, 8)),
        "pair_law_each_nonzero_exact": _pack(Fraction(7, 64)),
        "pair_collision_probability_exact": _pack(Fraction(57, 512)),
        "projected_secret_collision_probability_exact": _pack(collision),
        "projected_error_collision_probability_exact": _pack(collision),
        "output_cardinality_hex": hex(output_size),
        "average_conditional_chi_square_exact": _pack(chi_square),
        "one_factor_public_Ahat_noisy_column_tv_squared_upper_exact": _pack(square),
        "one_factor_public_Ahat_noisy_column_tv_dyadic_upper_exact": _pack(upper),
        "one_factor_tv_dyadic_bits_lower": bits,
        "one_factor_public_Ahat_shared_columns_tv_squared_upper_exact": _pack(multi_square),
        "one_factor_public_Ahat_shared_columns_tv_dyadic_upper_exact": _pack(multi_upper),
        "one_factor_shared_columns_tv_dyadic_bits_lower": multi_bits,
        "full_mod3_secret_collision_probability_exact": _pack(full_collision),
        "full_mod3_error_collision_probability_exact": _pack(full_collision),
        "full_mod3_output_cardinality_hex": hex(output_size**2),
        "full_mod3_average_conditional_chi_square_exact": _pack(full_chi_square),
        "full_mod3_public_Ahat_noisy_column_tv_squared_upper_exact": _pack(full_square),
        "full_mod3_public_Ahat_noisy_column_tv_dyadic_upper_exact": _pack(full_upper),
        "full_mod3_tv_dyadic_bits_lower": full_bits,
        "full_mod3_public_Ahat_shared_columns_tv_squared_upper_exact": _pack(full_multi_square),
        "full_mod3_public_Ahat_shared_columns_tv_dyadic_upper_exact": _pack(full_multi_upper),
        "full_mod3_shared_columns_tv_dyadic_bits_lower": full_multi_bits,
        "assumptions": ["independent coefficient CBD1 secret and error",
            "Ahat uniform over the complete mod3 quotient and independent of S,E",
            "columns use mutually independent S,E conditional on the shared Ahat",
            "comparison includes the public Ahat; fixed shifts and sign preserve TV"],
        "shared_Ahat_columns_hybrid_covered": True,
        "both_CRT_factor_Ahat_projections_independent": True,
        "both_CRT_factor_CBD1_projections_independent": False,
        "tv_bound_pointwise_for_every_Ahat": False,
        "both_CRT_factors_jointly_covered": True,
        "requires_only_3_divides_original_modulus_not_base_3": True,
        "prime_power_3_to_w_covered": False, "other_prime_factors_covered": False,
        "whole_MLWE_or_IBS_security_established": False,
        "actual_entropy_bytes": 0, "draw_performed": False,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None}


def build_report():
    """Public n/d arithmetic only; no frozen input or sampler is altered."""
    return {"schema": SCHEMA,
        "input": "explicit public arithmetic points; original n512/d2 and candidate n2048/d3",
        "profiles": [projection_certificate(degree=512, rank=2, columns=16),
            projection_certificate(degree=2048, rank=3, columns=66)],
        "source_sha256": {"experiments/research/candidates/srgg/crt_projection.py":
            sha256(Path(__file__).read_bytes()).hexdigest()},
        "environment": {"python": platform.python_version(), "platform": platform.platform(),
            "machine": platform.machine(), "processor": platform.processor()},
        "actual_entropy_bytes": 0, "draw_performed": False,
        "scope": "one factor and full mod3 CBD1 public noisy-column TV, including shared-Ahat columns only",
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")


if __name__ == "__main__":
    main()
