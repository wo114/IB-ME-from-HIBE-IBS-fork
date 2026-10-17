"""Exact SRGG interactive HVZK smoothing and high-probability key bounds.

The reference has an independent uniform interactive challenge.  This module
does not identify its law with Fiat--Shamir signing, program an oracle, prove
UF-NMA/CUR, or give a QROM/hardness/NIST claim.  It consumes no entropy and
does not change the frozen execution, its parameters, or any key selection.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
from math import isqrt
from pathlib import Path

from .fiber_normalizers import exp_negative_upper, pi_lower
from .psf_bridge import norm_tail_upper


SCHEMA = "IBME/SRGG-NATIVE-SIG-INTERACTIVE-BRIDGE/1"
BITS = 256
MAX_DIMENSION = 2**17
DEFAULT_INPUT = Path("docs/research/team-b-delivery/2026-10-16-srgg-bridge/integrated-bridge.json")


def _integer(value, name, low=0, high=2**64):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("bounded exact integer required: " + name)
    return value


def _fraction(value, name, *, positive=False, probability=False):
    if type(value) not in (int, Fraction, str):
        raise ValueError("exact integer, Fraction, or rational string required: " + name)
    try:
        result = Fraction(value)
    except (ValueError, ZeroDivisionError) as exc:
        raise ValueError("exact rational required: " + name) from exc
    if max(abs(result.numerator).bit_length(), result.denominator.bit_length()) > 4096:
        raise ValueError("rational resource limit exceeded: " + name)
    if result < 0 or (positive and result == 0) or (probability and result > 1):
        raise ValueError("rational range violated: " + name)
    return result


def _ceil(value, bits=BITS):
    value = Fraction(value)
    scale = 2**bits
    return Fraction(-(-value.numerator*scale // value.denominator), scale)


def _probability_upper(value):
    return min(Fraction(1), _ceil(value))


def _degree(n):
    _integer(n, "power-of-two negacyclic degree", 2, 2**16)
    if n & (n-1):
        raise ValueError("power-of-two negacyclic degree required")
    return n


def _theta_series_bound(dimension, normalized_minimum):
    """All-center Poisson error from a theta majorant on Z^dimension."""
    n = _integer(dimension, "theta dimension", 1, MAX_DIMENSION)
    t = _fraction(normalized_minimum, "normalized minimum shape", positive=True)
    a = exp_negative_upper(pi_lower()*t)
    result = {"normalized_minimum_on_Zn_exact": str(t), "theta_q_upper_exact": str(a),
        "normalizer_relative_error_upper_exact": None,
        "interactive_joint_tv_upper_exact": "1", "nontrivial": False,
        "method": "Poisson theta majorant, rational pi lower bound and directed exponential upper bound"}
    if a >= 1:
        return result
    # k^2 >= 1+3(k-1), and (1+u)^n <= 1/(1-n*u) when n*u<1.
    scalar = _ceil(2*a/(1-a**3), 512)
    x = n*scalar
    result["scalar_theta_nonzero_upper_exact"] = str(scalar)
    result["dimension_times_scalar_upper_exact"] = str(x)
    if x >= 1:
        return result
    # Relative normalizer error is not a probability and must not be capped
    # at one.  A divergent sufficient series leaves this field unavailable.
    epsilon = _ceil(x/(1-x))
    result["normalizer_relative_error_upper_exact"] = str(epsilon)
    if epsilon < 1:
        # If f(z)=D_Sigma(z)*Theta(z)/E[Theta], the ratio is in
        # [(1-eps)/(1+eps),(1+eps)/(1-eps)].  Half the L1 bound is eps/(1-eps).
        result["interactive_joint_tv_upper_exact"] = str(_probability_upper(epsilon/(1-epsilon)))
        result["nontrivial"] = True
    return result


def zeta_coset_smoothing(*, degree, c_minimum):
    """All-center theta bound on L_zeta=sqrt(2)*O*Z^n.

    If C >= c_minimum*I, dual Gaussian mass is bounded by the Z^n
    theta series at c_minimum/2.  The factor two is essential.  Values are
    exact upper enclosures, with a visible 2^-256 transport floor.
    """
    n = _degree(degree)
    c = _fraction(c_minimum, "minimum C eigenvalue", positive=True)
    return {"degree": n, "C_minimum_lower_exact": str(c),
        "lattice_index": str(2**(n//2)), "all_centers_and_challenge_cosets": True,
        **_theta_series_bound(n, c/2)}


def interactive_certificate(*, degree, r_squared, signature_squared, user_squared_cap):
    """Conditional uniform-in-key bound; does not validate a secret witness.

    Real negacyclic Parseval gives ||[M(y);I]||^2 <= 1+n*||y||^2/2.
    nu=2*r^2 and C=nu*I-nu^2*T^T*Sigma^-1*T for Sigma=s*I.
    """
    n = _degree(degree)
    r2 = _fraction(r_squared, "r squared", positive=True)
    s = _fraction(signature_squared, "signature squared", positive=True)
    cap = _fraction(user_squared_cap, "user squared cap")
    nu = 2*r2
    beta = 1+Fraction(n, 2)*cap
    if s <= nu*beta:
        raise ValueError("positive residual signature shape requires s>nu*beta")
    c = nu*(s-nu*beta)/s
    return {"nu_exact": str(nu), "user_squared_cap_exact": str(cap),
        "T_spectral_squared_upper_exact": str(beta),
        "Sigma_is_public_isotropic": True,
        "witness_relation_and_cap_verified_here": False,
        "smoothing": zeta_coset_smoothing(degree=n, c_minimum=c),
        "scope": "independent uniform interactive challenge joint (w,c,z), not FS signing"}


def _floor_log2_fraction(value):
    """Exact integer floor(log2(value)) for positive rational input."""
    value = _fraction(value, "log2 argument", positive=True)
    exponent = value.numerator.bit_length()-value.denominator.bit_length()
    at_least = (value.numerator >= value.denominator << exponent) if exponent >= 0 else (
        value.numerator << -exponent >= value.denominator)
    return exponent if at_least else exponent-1


def commitment_entropy_certificate(*, degree, rank, r_squared, signature_squared,
        user_squared_cap, modulus):
    """Full-cap ideal commitment min-entropy via a conditional head coset.

    Requires M's first H=rank*degree coefficient columns to be 2I mod 2Q.
    For S between ell*I and s*I, the conditional head Gaussian Schur shape
    is also in that interval.  A W fixes at most one head coset modulo Q.
    No entropy claim for the finite sampler follows without its TV hybrid.
    """
    n = _degree(degree)
    rank = _integer(rank, "rank", 1, 32)
    q = _integer(modulus, "odd modulus", 3, 2**128)
    if q % 2 == 0:
        raise ValueError("odd modulus required")
    r2 = _fraction(r_squared, "r squared", positive=True)
    s = _fraction(signature_squared, "signature squared", positive=True)
    cap = _fraction(user_squared_cap, "user squared cap")
    head = rank*n
    ell = s-2*r2*(1+Fraction(n, 2)*cap)
    if ell <= 0:
        raise ValueError("positive full-cap residual shape required")
    theta = _theta_series_bound(head, ell)
    eps_text = theta["normalizer_relative_error_upper_exact"]
    eps = None if eps_text is None else Fraction(eps_text)
    root = isqrt(s.numerator//s.denominator)
    root += root*root*s.denominator < s.numerator
    width_bits = _floor_log2_fraction(ell)
    growth_bits = -_floor_log2_fraction(Fraction(q, q+root))
    available = theta["nontrivial"] and eps <= Fraction(1, 2)
    bits = max(0, width_bits*(head//2)-growth_bits*head-1) if available else 0
    return {"head_dimension": head, "S_minimum_lower_exact": str(ell),
        "S_maximum_upper_exact": str(s),
        "conditional_head_Schur_bounds_uniform_in_tail": True,
        "head_theta_normalizer_relative_error_upper_exact": None if eps is None else str(eps),
        "ceil_sqrt_s_integer": root, "floor_log2_ell": width_bits,
        "ceil_log2_head_growth": growth_bits,
        "ideal_commitment_min_entropy_bits_lower": bits,
        "ideal_commitment_max_atom_upper_dyadic_exponent": -bits,
        "entropy_certificate_available": available,
        "keygen_exception_probability_within_full_cap_class": "0",
        "real_finite_commitment_entropy_established": False,
        "source_keygen_correspondence_established": False,
        "scope": "P1 commitment W under ideal D_ZD,S, every valid key within full public cap"}


def conditional_statistical_ledger(*, counted_issuances, signing_queries, max_sign_attempts,
        issuance_tv, ideal_bad_key, finite_sign_tv, interactive_hvzk_tv, norm_reject):
    """Arithmetic ledger conditional on the separately proved hybrid structure.

    First replace each entire key-issuance law (retaining abort); then mark
    ideal bad keys once per issuance; finally use per-attempt signing bounds.
    This is not itself a simulation, a FS/QROM hybrid, or a security bound.
    """
    qe = _integer(counted_issuances, "counted issuances")
    qs = _integer(signing_queries, "signing queries")
    attempts = _integer(max_sign_attempts, "max sign attempts", 1, 2**16)
    delta = _fraction(issuance_tv, "issuance TV", probability=True)
    bad = _fraction(ideal_bad_key, "ideal bad-key probability", probability=True)
    finite = _fraction(finite_sign_tv, "finite signing TV", probability=True)
    zk = _fraction(interactive_hvzk_tv, "interactive HVZK TV", probability=True)
    norm = _fraction(norm_reject, "norm reject", probability=True)
    key_term = _probability_upper(qe*(delta+bad))
    sign_term = _probability_upper(qs*attempts*(finite+zk+norm))
    total = _probability_upper(key_term+sign_term)
    return {"counted_issuances": qe, "signing_queries": qs,
        "max_sign_attempts": attempts, "key_terms_upper_exact": str(key_term),
        "sign_terms_upper_exact": str(sign_term), "total_upper_exact": str(total),
        "at_most_2_minus_128": total <= Fraction(1, 2**128),
        "FS_or_QROM_simulation_proved": False,
        "meaning": "conditional statistical arithmetic; no cryptographic advantage bound"}


def profile_certificate(profile, *, queries=(1, 2**20, 2**40)):
    """Read previously established issuance/finite/tail certificates as premises."""
    if not isinstance(profile, dict):
        raise ValueError("integrated profile dictionary required")
    p = profile["parameters"]
    n = _degree(p["degree"])
    rank = _integer(p["rank"], "rank", 1, 32)
    digits = _integer(p["digits"], "digits", 1, 32)
    prime_scale = _integer(p["p"], "p", 1, 2**32)
    dimension, head = (2+digits)*rank*n, rank*n
    if dimension > MAX_DIMENSION:
        raise ValueError("coefficient dimension budget exceeded")
    user_cap = _fraction(p["user_norm_cap"], "user norm cap", positive=True)
    full = interactive_certificate(degree=n, r_squared=p["r_squared"],
        signature_squared=p["signature_squared"], user_squared_cap=user_cap)
    q = _integer(p["p"]*p["base"]**digits, "modulus", 3, 2**128)
    entropy = commitment_entropy_certificate(degree=n, rank=rank, r_squared=p["r_squared"],
        signature_squared=p["signature_squared"], user_squared_cap=user_cap, modulus=q)
    good_cap = user_cap/4
    good = interactive_certificate(degree=n, r_squared=p["r_squared"],
        signature_squared=p["signature_squared"], user_squared_cap=good_cap)
    shift_envelope = 2*head*(prime_scale-1)**2
    raw_threshold = (good_cap-shift_envelope)/2
    eps = _fraction(profile["full_kernel_reference"]["uniform_coset_relative_error_upper"],
        "kernel smoothing epsilon", probability=True)
    if raw_threshold <= 0:
        tail = {"probability_upper": "1", "markov_t": None,
            "scope": "HNF envelope gives no positive raw threshold"}
    else:
        tail = norm_tail_upper(dimension=dimension, squared_cap=raw_threshold,
            largest_squared_width=_fraction(p["master_squared"], "master squared", positive=True),
            smoothing_epsilon=eps)
    bad = Fraction(tail["probability_upper"])
    delta = _fraction(profile["hnf_common_gate_comparison"][
        "complete_issuance_to_common_hnf_gate_reference_tv_upper"], "issuance TV", probability=True)
    abort = _fraction(profile["hnf_common_gate_comparison"][
        "actual_issuance_abort_upper_excluding_infrastructure"], "issuance abort", probability=True)
    finite = _fraction(profile["sign_attempt_finite_tv_upper"], "finite sign TV", probability=True)
    norm = _fraction(profile["sign_norm"]["ideal_sequential_sign_attempt_norm_reject_upper"],
        "sign norm reject", probability=True)
    good_tv = Fraction(good["smoothing"]["interactive_joint_tv_upper_exact"])
    full_tv = Fraction(full["smoothing"]["interactive_joint_tv_upper_exact"])
    actual_bad = _probability_upper(delta+bad)
    if not isinstance(queries, (tuple, list)) or not 1 <= len(queries) <= 16:
        raise ValueError("bounded query sequence required")
    ledgers = []
    for q in queries:
        row = conditional_statistical_ledger(counted_issuances=q, signing_queries=q,
            max_sign_attempts=p["sign_max_attempts"], issuance_tv=delta, ideal_bad_key=bad,
            finite_sign_tv=finite, interactive_hvzk_tv=good_tv, norm_reject=norm)
        row["full_cap_interactive_hvzk_term_alone_upper_exact"] = str(
            _probability_upper(q*p["sign_max_attempts"]*full_tv))
        ledgers.append(row)
    return {"profile": profile["profile"], "parameters": p,
        "full_cap_interactive": full, "good_key_interactive": good,
        "full_cap_ideal_commitment_entropy": entropy,
        "GoodKey_is_analysis_event_only": True, "runtime_key_filter_changed": False,
        "good_key_event": "issued nonabort y with ||y||^2 <= user_norm_cap/4",
        "raw_threshold_exact": str(raw_threshold), "ideal_raw_tail": tail,
        "ideal_bad_issued_key_upper_exact": str(bad),
        "actual_bad_issued_key_including_abort_law_upper_exact": str(actual_bad),
        "actual_bad_issued_key_given_success_upper_exact": None if abort >= 1 else
            str(_probability_upper(actual_bad/(1-abort))),
        "issuance_tv_premise_exact": str(delta), "finite_sign_tv_premise_exact": str(finite),
        "sign_norm_reject_premise_exact": str(norm),
        "conditional_statistical_ledgers": ledgers,
        "input_certificate_hypotheses_reproved_by_this_tool": False,
        "ideal_raw_tail_requires_uniform_union_kernel_smoothing": True,
        "infrastructure_failure_or_service_capacity_model_included": False,
        "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False}


def build_report(input_path=DEFAULT_INPUT):
    path = Path(input_path)
    data = path.read_bytes()
    source = json.loads(data)
    if source.get("schema") != "IBME/SRGG-INTEGRATED-BRIDGE/1":
        raise ValueError("known integrated bridge schema required")
    dependency_names = ("native_sig.py", "fiber_normalizers.py", "psf_bridge.py")
    sources = {"experiments/research/candidates/srgg/"+name:
        hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
        for name in dependency_names}
    return {"schema": SCHEMA, "input_path": path.as_posix(),
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "source_sha256": sources,
        "profiles": [profile_certificate(p) for p in source["profiles"]],
        "actual_entropy_bytes": 0,
        "scope": "interactive joint smoothing and conditional arithmetic; FS/QROM bridge unproved",
        "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = build_report(args.input)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
