"""Strict public negacyclic spectral and ordered kernel-GSO bounds for SRGG.

No FFT, floating eigensolver, private key file, entropy, or sampler is used.
The public CBD1 support bound is deterministic, valid for every matrix in the
declared class. Per-root coefficient-energy checks are separately labelled.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import json
from pathlib import Path

from .fiber_normalizers import decimal_display, normalizer_certificate, pi_lower


SCHEMA = "IBME/SRGG-PUBLIC-SPECTRAL-BOUNDS/1"
MAX_COEFFICIENTS = 2**20


def _integer(value, name, low=1, high=2**16):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("bounded exact integer required: " + name)
    return value


def _degree(value):
    _integer(value, "degree", 2)
    if value & (value-1):
        raise ValueError("power-of-two negacyclic degree required")
    return value


def _rational(value, name, low=0):
    if type(value) not in (int, Fraction):
        raise ValueError("exact rational required: " + name)
    value = Fraction(value)
    if value < low or max(abs(value.numerator).bit_length(), value.denominator.bit_length()) > 8192:
        raise ValueError("rational range or resource budget exceeded: " + name)
    return value


def _upper_dyadic(value, bits=128):
    value = Fraction(value)*2**bits
    return Fraction(-(-value.numerator//value.denominator), 2**bits)


def public_support_class_bound(*, degree, rows, columns):
    """For any rows x columns real CBD1 polynomial matrix R, T=[M(R);I].

    The caller must check all witness coefficients lie in {-1,0,1} before
    using this class certificate for an actual root. No witness is input here.
    Scalars have operator norm <=csc(pi/(2n)); a rational upper enclosure is
    used. A separate real-conjugate-pair Parseval bound n^2/2 is also valid.
    """
    n = _degree(degree)
    _integer(rows, "polynomial rows", high=128)
    _integer(columns, "polynomial columns", high=128)
    if rows*columns*n > MAX_COEFFICIENTS:
        raise ValueError("public coefficient-class resource budget exceeded")
    pi_scale = 2**64
    rational_pi_lower = Fraction((pi_lower()*pi_scale).__floor__(), pi_scale)
    angle = rational_pi_lower/(2*n)
    sine_lower = angle-angle**3/6
    polygon_squared = _upper_dyadic(1/sine_lower**2)
    conjugate_squared = Fraction(n*n, 2)
    scalar_squared = min(polygon_squared, conjugate_squared)
    beta = 1+rows*columns*scalar_squared
    return {
        "degree": n, "rows": rows, "columns": columns,
        "coefficient_support": "{-1,0,1}",
        "declared_support_checked_against_a_witness": False,
        "public_support_class_certificate": True,
        "requires_probability_or_setup_conditioning": False,
        "pi_lower_64bit_exact": str(rational_pi_lower),
        "sine_lower_exact": str(sine_lower),
        "scalar_polygon_squared_upper_exact": str(polygon_squared),
        "scalar_conjugate_parseval_squared_upper_exact": str(conjugate_squared),
        "scalar_polynomial_spectral_squared_upper_exact": str(scalar_squared),
        "t_spectral_squared_upper_exact": str(beta),
        "legacy_frobenius_squared_upper": 1+rows*columns*n*n,
        "relative_to_legacy_display": decimal_display(beta/(1+rows*columns*n*n)),
        "method": "real negacyclic Fourier block identity, regular-zonotope support, rational sine lower bound",
        "floating_fft_or_eigenvalues_used": False,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False,
    }


def public_t_squared_upper(degree, rank, digits):
    """SRGG 2d x wd CBD1 root class, returned as an exact Fraction."""
    _integer(rank, "module rank", high=32)
    _integer(digits, "gadget digits", high=32)
    return Fraction(public_support_class_bound(degree=degree, rows=2*rank,
        columns=rank*digits)["t_spectral_squared_upper_exact"])


def private_energy_bound(witness, *, degree):
    """Per-root exact check; the result may reveal private aggregate energy.

    Never call this on service keys merely to export telemetry. This validates
    a supplied integer matrix and returns a certificate ONLY FOR THAT MATRIX.
    It is not a public setup class unless a separate public energy cap is
    fixed and the caller verifies it without publishing the measured energy.
    """
    n = _degree(degree)
    if not isinstance(witness, (tuple, list)) or not witness:
        raise ValueError("nonempty integer polynomial matrix required")
    rows = _integer(len(witness), "rows", high=128)
    if not isinstance(witness[0], (tuple, list)) or not witness[0]:
        raise ValueError("rectangular polynomial matrix required")
    columns = _integer(len(witness[0]), "columns", high=128)
    if rows*columns*n > MAX_COEFFICIENTS:
        raise ValueError("private coefficient budget exceeded")
    energy, cbd1 = 0, True
    for row in witness:
        if not isinstance(row, (tuple, list)) or len(row) != columns:
            raise ValueError("rectangular polynomial matrix required")
        for poly in row:
            if not isinstance(poly, (tuple, list)) or len(poly) != n:
                raise ValueError("canonical fixed-degree integer polynomial required")
            for value in poly:
                if type(value) is not int or abs(value).bit_length() > 64:
                    raise ValueError("bounded exact integer coefficient required")
                energy += value*value
                cbd1 &= value in (-1, 0, 1)
    upper = Fraction(1)+Fraction(n, 2)*energy
    if cbd1:
        upper = min(upper, Fraction(public_support_class_bound(degree=n,
            rows=rows, columns=columns)["t_spectral_squared_upper_exact"]))
    return {
        "degree": n, "rows": rows, "columns": columns,
        "actual_coefficient_energy": energy,
        "all_coefficients_in_cbd1_support": cbd1,
        "t_spectral_squared_upper_exact": str(upper),
        "public_support_class_certificate": False,
        "scope": "supplied root only; aggregate may be private; do not export service telemetry",
        "floating_fft_or_eigenvalues_used": False,
    }


def ordered_kernel_gso_bound(*, p, base, witness_spectral_squared_upper):
    """GSO bound for the existing full kernel basis ordered gadget/head/middle.

    The first m gadget columns span im(T). Thus Tz vanishes from all later
    GSO residuals. The next dn columns add the first head subspace, removing
    both the Tz and head terms from the final middle columns. Their residual
    lengths are at most p and 1 respectively, regardless of raw column norm.
    """
    _integer(p, "p", 3, 2**32)
    _integer(base, "base", 3)
    if not p % 2 or not base % 2:
        raise ValueError("odd p and gadget base required")
    beta = _rational(witness_spectral_squared_upper, "declared T bound", 1)
    gadget, head, middle = beta*(base*base+1), Fraction(p*p), Fraction(1)
    return {
        "basis_order": "all gadget columns, all first-head columns, all middle columns",
        "gadget_gso_squared_upper_exact": str(gadget),
        "head_gso_squared_upper_exact": str(head),
        "middle_gso_squared_upper_exact": str(middle),
        "basis_gso_squared_upper_exact": str(max(gadget, head, middle)),
        "declared_t_bound_must_be_verified": True,
        "not_a_bound_on_raw_middle_column_length": True,
        "requires_probability_or_setup_conditioning": False,
    }


def candidate_screen(candidate):
    from .convolution_bridge import bridge_certificate, c_shape_lower_bound
    from .psf_bridge import reference_certificate

    c = candidate
    public = public_support_class_bound(degree=c.degree, rows=2*c.rank,
                                        columns=c.rank*c.digits)
    beta = Fraction(public["t_spectral_squared_upper_exact"])
    old = Fraction(public["legacy_frobenius_squared_upper"])
    width = min(c.master_first_squared, c.master_second_squared)
    noise = c.base**2*c.r_squared
    fiber = normalizer_certificate(degree=c.degree, rank=c.rank, base=c.base,
                                   digits=c.digits, r_squared=c.r_squared)
    raw = bridge_certificate(degree=c.degree, rank=c.rank, base=c.base,
        digits=c.digits, r_squared=c.r_squared, master_minimum_squared=width,
        fiber_lower=Fraction(fiber["uniform_relative_lower_exact"]),
        fiber_upper=Fraction(fiber["uniform_relative_upper_exact"]),
        t_squared_upper=beta,
        witness_bound_origin="spectral_bounds public all-CBD1-support theorem; no root conditioning")
    gso = ordered_kernel_gso_bound(p=c.p, base=c.base,
                                  witness_spectral_squared_upper=beta)
    reference = reference_certificate(degree=c.degree, rank=c.rank, p=c.p,
        base=c.base, digits=c.digits, first_squared=c.master_first_squared,
        second_squared=c.master_second_squared,
        basis_gso_squared_upper=Fraction(gso["basis_gso_squared_upper_exact"]),
        user_norm_squared=c.user_norm_squared_cap)
    for key in ("repaired_approximate_fiber_to_full_reference_tv_upper",
                "max_error_displacement_squared_in_inverse_shape"):
        if key in reference:
            reference[key+"_display"] = decimal_display(Fraction(reference[key]))
    rho = Fraction(noise)*beta/(width-c.r_squared)
    return {
        "name": c.name, "parameter_changes": None,
        "actual_root_or_sampler_executed": False,
        "public_support_bound": public, "ordered_kernel_gso": gso,
        "legacy_C_lower_exact": str(c_shape_lower_bound(noise, width, old)),
        "new_C_lower_exact": raw["C_lambda_min_lower_exact"],
        "new_C_lower_display": decimal_display(Fraction(raw["C_lambda_min_lower_exact"])),
        "C_sufficient_smoothing_passes": raw["center_normalizer"]["sufficient_smoothing_condition_passes"],
        "ideal_raw_to_union_tv_upper_exact": raw["ideal_raw_to_union_gaussian_tv_upper_exact"],
        "structured_binomial_operator_rho_upper_exact": str(rho),
        "structured_binomial_operator_rho_upper_display": decimal_display(rho),
        "reference_with_ordered_GSO": reference,
        "remaining_blockers": [
            "reference displacement-TV remains quantitatively large; not eliminated by kernel smoothing",
            "actual finite n512 perturbation/key/signature sampler, abort and norm gate budgets",
            "source PSF/strong-security theorem correspondence and formal attack estimation",
        ],
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False,
    }


def build_report():
    from .formal_candidates import conditional_candidate
    return {
        "schema": SCHEMA,
        "scope": "deterministic public CBD1 support class and ordered kernel GSO; no FFT estimates",
        "existing_n512_candidates": [candidate_screen(conditional_candidate(rank=d)) for d in (2,3,4)],
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
