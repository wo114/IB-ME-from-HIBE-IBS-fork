"""Conditional SRGG key-law bounds against an explicitly defined PSF reference.

The reference is D_{Z^N,Sigma} conditioned on Ay=h mod Q.  This is an
analysis tool, not a new backend or a proof that the source's PSF/strong
theorems apply.  A complete-law comparison also needs the finite sampler
and raw convolution bounds.  No cryptographic admission flags are changed.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
from fractions import Fraction
from math import isqrt
import json
from pathlib import Path

from .algebra import PublicRelation, identity, matrix, trapdoor_relation
from .formal_candidates import conditional_candidate, smoothing_certificate
from .geometry import module_operator

MAX_DIMENSION = 2**17
MAX_EXACT_DIMENSION = 64
MAX_RATIONAL_BITS = 8192
CERTIFICATE_BITS = 256


def _int(value, name, low=1, high=2**32):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("bounded integer required: " + name)
    return value


def _fraction(value, name, *, positive=False):
    if isinstance(value, bool) or not isinstance(value, (int, Fraction)):
        raise ValueError("exact rational required: " + name)
    result = Fraction(value)
    if max(abs(result.numerator).bit_length(), result.denominator.bit_length()) > MAX_RATIONAL_BITS:
        raise ValueError("rational budget exceeded: " + name)
    if positive and result <= 0:
        raise ValueError("positive rational required: " + name)
    return result


def _upper(value):
    """Outward dyadic probability bound; never silently underflows to zero."""
    value = min(Fraction(1), max(Fraction(0), Fraction(value)))
    scale = 1 << CERTIFICATE_BITS
    return Fraction((value.numerator*scale+value.denominator-1)//value.denominator, scale)


def _sqrt_upper(value):
    value = min(Fraction(1), max(Fraction(0), Fraction(value)))
    scale = 1 << (2*CERTIFICATE_BITS)
    integer = (value.numerator*scale+value.denominator-1)//value.denominator
    root = isqrt(integer)
    return min(Fraction(1), Fraction(root+int(root*root < integer), 1 << CERTIFICATE_BITS))


def _dyadic_product(numerator, denominator, exponent):
    """Outward bound for numerator/(denominator*2^exponent), bounded memory."""
    if exponent >= numerator.bit_length()+CERTIFICATE_BITS:
        return Fraction(1, 1 << CERTIFICATE_BITS)
    return _upper(Fraction(numerator, denominator << exponent))


def kernel_basis_bound(*, degree, rank, p, base, digits, witness_spectral_squared_upper):
    """All-root ordered GSO bound for a full basis of ker(A mod Q).

    In coordinates before [I,R;0,I], use p head units, middle units with
    centered head residues and balanced gadget lifts, and gadget-kernel
    columns b*e_i-e_(i+1), b*e_last. Their determinant is Q^(dn).
    A is surjective because its first block is I, so this is the full kernel.
    Order gadget columns first, then all head columns, then all middle columns.
    Gadgets span im(T). Each head column is p*e_head plus im(T), so its GSO
    length is at most p. After all heads, each middle column is e_middle plus
    the preceding span, so its GSO length is at most one. Only gadget GSO
    lengths require their raw column bound beta*(b^2+1).
    """
    n = _int(degree, "degree", 2, 2**16)
    d = _int(rank, "rank", 1, 32)
    p = _int(p, "p", 3)
    b = _int(base, "base", 3, 2**16-1)
    w = _int(digits, "digits", 1, 32)
    if n & (n-1) or not p % 2 or not b % 2:
        raise ValueError("power-of-two degree and odd p/base required")
    beta = _fraction(witness_spectral_squared_upper, "witness norm", positive=True)
    if beta < 1:
        raise ValueError("stacked T=[R;I] has squared spectral norm at least one")
    k, m, dimension = d*n, w*d*n, (2+w)*d*n
    if dimension > MAX_DIMENSION:
        raise ValueError("analysis dimension budget exceeded")
    head = 2*p*p+2*beta
    middle = 2*(1+k*((p-1)//2)**2)+2*beta*((b-1)//2)**2*m
    gadget = beta*(b*b+1)
    return {
        "dimension": dimension, "head_dimension": k,
        "head_column_squared_upper": head,
        "middle_column_squared_upper": middle,
        "gadget_column_squared_upper": gadget,
        "raw_column_squared_upper": max(head, middle, gadget),
        "basis_order": "all gadget columns, all head columns, all middle columns",
        "head_gso_squared_upper": p*p,
        "middle_gso_squared_upper": 1,
        "basis_gso_squared_upper": max(p*p, 1, gadget),
        "kernel_index": (p*b**w)**k,
        "basis_is_full_kernel_under_declared_relation": True,
        "assumptions": "A=[I,Ahat,B], AT=F=p*g, T=[R;I], declared ||T||^2 bound",
    }


def exact_kernel_basis(public, witness):
    """Construct a private proof witness at small dimensions, without entropy.

    The returned columns can reveal the input trapdoor. Never serialize them
    from real service keys. Published experiments use public test fixtures.
    """
    if not isinstance(public, PublicRelation):
        raise TypeError("SRGG PublicRelation required")
    p = public.params
    dimension, k, m = p.columns*p.degree, p.rank*p.degree, p.rank*p.digits*p.degree
    if dimension > MAX_EXACT_DIMENSION:
        raise ValueError("exact kernel proof dimension budget exceeded")
    r = matrix(p, witness, 2*p.rank, p.rank*p.digits)
    if not trapdoor_relation(public, r):
        raise ValueError("invalid master relation")
    a = module_operator(p, public.a)
    t = module_operator(p, r+identity(p, p.rank*p.digits))

    def lift(x, z):
        result = tuple((x[i] if i < 2*k else 0)+sum(t[i][j]*z[j] for j in range(m))
                       for i in range(dimension))
        if any(sum(row[j]*result[j] for j in range(dimension)) % p.modulus for row in a):
            raise ArithmeticError("constructed column is outside the kernel")
        return tuple(int(value) for value in result)

    columns = []
    # Gadget first usually gives a much tighter GSO certificate than raw length.
    for block in range(p.rank):
        for digit in range(p.digits):
            for coefficient in range(p.degree):
                z = [0]*m
                pos = (block*p.digits+digit)*p.degree+coefficient
                z[pos] = p.base
                if digit+1 < p.digits:
                    z[pos+p.degree] = -1
                columns.append(lift([0]*(2*k), z))
    for j in range(k):
        x, z = [0]*(2*k), [0]*m
        x[j] = p.p
        z[(j//p.degree*p.digits)*p.degree+j % p.degree] = -1
        columns.append(lift(x, z))
    for j in range(k):
        x, z = [0]*(2*k), [0]*m
        x[k+j] = 1
        for i in range(k):
            x[i] = (-int(a[i][k+j])+p.p//2) % p.p-p.p//2
        residual = [-sum(int(row[i])*x[i] for i in range(2*k)) for row in a]
        for i, value in enumerate(residual):
            if value % p.p:
                raise ArithmeticError("nonintegral gadget lift")
            state = (value//p.p) % p.gadget_modulus
            for digit in range(p.digits):
                entry = (state+p.base//2) % p.base-p.base//2
                z[(i//p.degree*p.digits+digit)*p.degree+i % p.degree] = entry
                state = (state-entry)//p.base
        columns.append(lift(x, z))
    return tuple(columns)


def exact_gso_squared(columns):
    """Exact small-basis Gram--Schmidt; stops on intermediate rational budget."""
    dimension = len(columns)
    if not 1 <= dimension <= MAX_EXACT_DIMENSION or any(len(c) != dimension for c in columns):
        raise ValueError("bounded square column basis required")
    orthogonal, norms = [], []
    for column in columns:
        v = [_fraction(x, "basis entry") for x in column]
        for previous, norm in zip(orthogonal, norms):
            mu = _fraction(sum(x*y for x, y in zip(v, previous))/norm, "GSO projection")
            v = [_fraction(x-mu*y, "GSO entry") for x, y in zip(v, previous)]
        norm = _fraction(sum(x*x for x in v), "GSO norm", positive=True)
        orthogonal.append(v)
        norms.append(norm)
    return tuple(norms)


def norm_tail_upper(*, dimension, squared_cap, largest_squared_width, smoothing_epsilon):
    """Gaussian norm tail on any coset, or the approximate-fiber union.

    Scale Sigma by 1/(1-t), t=j/16. Poisson normalizers cost at most
    (1+eps)/(1-eps); pi>4 ln2 gives a rational Markov bound. All enlarged
    shapes retain the original smoothing certificate. No empirical fit.
    """
    n = _int(dimension, "dimension", 2, MAX_DIMENSION)
    if n % 2:
        raise ValueError("even coefficient dimension required")
    cap = _fraction(squared_cap, "norm cap", positive=True)
    width = _fraction(largest_squared_width, "largest squared width", positive=True)
    epsilon = _fraction(smoothing_epsilon, "smoothing epsilon")
    if not 0 <= epsilon < 1:
        raise ValueError("nontrivial smoothing certificate required")
    ratio, best, selected = (1+epsilon)/(1-epsilon), Fraction(1), None
    for j in range(1, 16):
        factor = ratio*Fraction(16, 16-j)**(n//2)
        exponent = (Fraction(j, 4)*cap/width).__floor__()
        value = _dyadic_product(factor.numerator, factor.denominator, exponent)
        if value < best:
            best, selected = value, j
    return {"probability_upper": str(best), "markov_t": None if selected is None else str(Fraction(selected,16)),
            "scope": "normalized Gaussian on exact fiber or finite union of fibers; not the actual sampler"}


def reference_certificate(*, degree, rank, p, base, digits, first_squared,
                          second_squared, basis_gso_squared_upper, user_norm_squared=None):
    """Uniform-in-h shifted Gaussian, HNF wrap and image-regularity bounds.

    The GSO-to-smoothing step is valid for the full kernel basis: applying
    Sigma^-1/2 contracts each GSO distance by at most 1/sqrt(min(first,second)).
    Summing Gaussian coefficients recursively along that transformed GSO
    gives the scalar-theta product bound used by smoothing_certificate.
    Poisson then makes its dual-mass bound uniform over all coset centers.
    """
    layout = kernel_basis_bound(degree=degree, rank=rank, p=p, base=base, digits=digits,
                               witness_spectral_squared_upper=1)
    dimension, k = layout["dimension"], layout["head_dimension"]
    first = _fraction(first_squared, "first width", positive=True)
    second = _fraction(second_squared, "second width", positive=True)
    gso = _fraction(basis_gso_squared_upper, "kernel GSO bound", positive=True)
    ratio = min(first, second)/gso
    floor = min(512, ratio.__floor__())
    result = {
        "dimension": dimension, "head_dimension": k,
        "declared_basis_gso_squared_upper": str(gso),
        "normalized_kernel_width_squared_lower": str(ratio),
        "conservative_integer_smoothing_shape": floor,
        "reference": "D_Z^N,Sigma conditioned on Ay=h mod Q; Sigma=diag(first I_2dn,second I_wdn)",
        "smoothing_scope": "full coefficient kernel ker(A mod Q), not gadget kernel alone",
        "basis_bound_must_be_verified_separately": True,
        "reference_certificate_available": False,
        "source_psf_theorem_correspondence_established": False,
        "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False,
    }
    if floor < 1:
        result["blocker"] = "kernel smoothing lower shape is below one"
        return result
    smooth = smoothing_certificate(dimension, floor, 80)
    value = smooth["dual_gaussian_mass_upper"]
    result["smoothing"] = smooth
    if value is None or Fraction(value) >= 1:
        result["blocker"] = "no nontrivial uniform coset normalizer bound"
        return result
    eps = Fraction(value)
    displacement = Fraction(k*(p-1)**2, 1)/first
    # Hellinger affinity >= exp(-pi*delta^2/4)*(1-eps)/(1+eps).
    # Hence TV^2 <= 2*delta^2+4*eps, using pi/2<2.
    shift = _sqrt_upper(2*displacement+4*eps)
    normalization_ratio = (1+eps)/(1-eps)
    q = p*base**digits
    wrap_factor = 2*k*normalization_ratio
    wrap_exponent = (Fraction(q*q, 2)/first).__floor__()
    wrap = _dyadic_product(wrap_factor.numerator, wrap_factor.denominator, wrap_exponent)
    result.update({
        "reference_certificate_available": True,
        "uniform_coset_relative_error_upper": str(_upper(eps)),
        "image_to_uniform_tv_upper": str(_upper(eps/(1-eps))),
        "max_error_displacement_squared_in_inverse_shape": str(displacement),
        "repaired_approximate_fiber_to_decoded_reference_tv_upper": str(shift),
        "reference_head_wrap_probability_upper": str(wrap),
        "repaired_approximate_fiber_to_full_reference_tv_upper": str(_upper(shift+wrap)),
        "uniform_in_identity_target": True,
        "trapdoor_independent_reference_for_fixed_public_A": True,
        "source_psf_theorem_correspondence_established": False,
    })
    if user_norm_squared is not None:
        cap = _fraction(user_norm_squared, "user norm cap", positive=True)
        raw_cap = cap/2-k*(p-1)**2
        result["norm_cap"] = str(cap)
        result["reference_norm_reject"] = norm_tail_upper(
            dimension=dimension, squared_cap=cap, largest_squared_width=max(first,second), smoothing_epsilon=eps)
        result["raw_cap_sufficient_for_hnf_norm"] = str(raw_cap)
        if raw_cap > 0:
            result["approximate_fiber_hnf_norm_reject"] = norm_tail_upper(
                dimension=dimension, squared_cap=raw_cap, largest_squared_width=max(first,second), smoothing_epsilon=eps)
    return result


def complete_key_comparison(reference, *, sampler_tv_including_abort, raw_convolution_tv):
    """Compose verified implementation/raw inputs with the reference bound.

    No fabricated values: missing/inapplicable inputs do not produce a
    complete-law certificate. The unfiltered reference never aborts. Both laws
    are on decoded full witnesses plus an explicit abort symbol, with public
    A and target h fixed. This is not a success-conditioned comparison.
    """
    if not reference.get("reference_certificate_available"):
        return {"available": False, "reason": "reference certificate unavailable"}
    if sampler_tv_including_abort is None or raw_convolution_tv is None:
        return {"available": False, "reason": "finite implementation or raw convolution bound missing"}
    implementation = _fraction(sampler_tv_including_abort, "sampler TV")
    convolution = _fraction(raw_convolution_tv, "raw convolution TV")
    if not 0 <= implementation <= 1 or not 0 <= convolution <= 1:
        raise ValueError("TV inputs must be probabilities")
    prefilter = _upper(implementation+convolution+Fraction(reference[
        "repaired_approximate_fiber_to_full_reference_tv_upper"]))
    tail = reference.get("reference_norm_reject")
    if tail is None:
        return {"available": False, "prefilter_tv_upper": str(prefilter), "reason": "norm gate not budgeted"}
    return {"available": True, "complete_key_law_to_unfiltered_full_reference_tv_upper": str(_upper(
                prefilter+Fraction(tail["probability_upper"]))),
            "includes_sampler_abort_and_norm_reject": True,
            "comparison_space": "decoded full witness in Z^N plus abort, for fixed public A and h",
            "success_conditioned": False,
            "infrastructure_failure_included": False,
            "strong_security_or_source_psf_admission": False}


def candidate_certificate(candidate):
    c = candidate
    beta = 2*c.rank*c.rank*c.digits*c.degree*c.degree+1
    basis = kernel_basis_bound(degree=c.degree, rank=c.rank, p=c.p, base=c.base, digits=c.digits,
                               witness_spectral_squared_upper=beta)
    reference = reference_certificate(degree=c.degree, rank=c.rank, p=c.p, base=c.base, digits=c.digits,
        first_squared=c.master_first_squared, second_squared=c.master_second_squared,
        basis_gso_squared_upper=basis["basis_gso_squared_upper"], user_norm_squared=c.user_norm_squared_cap)
    # The index may be large; it is proved symbolically rather than serialized.
    return {"name": c.name, "worst_case_basis_gso_squared_upper": str(basis["basis_gso_squared_upper"]),
            "reference": reference, "actual_n512_implementation_tv": None}


def build_report():
    return {"schema": "IBME/SRGG-PSF-REFERENCE-BRIDGE/1",
            "existing_candidates": [candidate_certificate(conditional_candidate(rank=d)) for d in (2,3,4)],
            "scope": "conditional declared reference, not source theorem or formal backend admission",
            "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(build_report(), ensure_ascii=False, indent=2)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8", newline="\n")
    print(encoded, end="")


if __name__ == "__main__":
    main()
