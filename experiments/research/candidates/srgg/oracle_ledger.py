"""SRGG issuance-reference and conditional oracle budgets, without admission.

The principal key reference is the HNF/norm-gate pushforward of the Gaussian
on the approximate-fiber union. It depends only on public A and fixed public
shape, but is NOT identified with the source PSF SampleDom conditional law.
All probabilities retain the abort atom. No output is conditioned on success.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import json
from pathlib import Path

from .convolution_bridge import bridge_certificate
from .fiber_normalizers import normalizer_certificate
from .formal_candidates import smoothing_certificate
from .psf_bridge import (
    _upper, complete_key_comparison, kernel_basis_bound, norm_tail_upper,
    reference_certificate,
)


def _probability(value):
    if isinstance(value, bool) or not isinstance(value, (int, Fraction, str)):
        raise ValueError("exact probability required")
    result = Fraction(value)
    if not 0 <= result <= 1:
        raise ValueError("probability outside [0,1]")
    return result


def _count(value, name, maximum=2**64):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("bounded nonnegative integer required: "+name)
    return value


def _positive_exact(value):
    if isinstance(value,bool) or not isinstance(value,(int,Fraction)):
        raise ValueError("positive exact rational required")
    value = Fraction(value)
    if value <= 0 or max(value.numerator.bit_length(),value.denominator.bit_length()) > 4096:
        raise ValueError("positive bounded exact rational required")
    return value


def hnf_reference_comparison(*, sampler_tv_including_abort, raw_convolution_tv,
                             ideal_union_norm_reject=None):
    """Common HNF+norm gate is data processing, including its abort outcome.

    Norm rejection is not added to TV when both laws use the same gate.
    The separately returned actual abort bound compares to the unfiltered union.
    Infrastructure failures are not assigned a fabricated probability.
    """
    if sampler_tv_including_abort is None or raw_convolution_tv is None:
        return {"available": False, "reason": "finite or convolution input missing"}
    distance = _upper(_probability(sampler_tv_including_abort)+_probability(raw_convolution_tv))
    result = {
        "available": True,
        "complete_issuance_to_common_hnf_gate_reference_tv_upper": str(distance),
        "reference": "norm_gate(HNF#(D_Z^N,Sigma | h-Ax mod Q in [0,p)^dn))",
        "reference_depends_only_on_fixed_public_A_shape_and_target": True,
        "abort_atom_retained": True,
        "success_conditioned": False,
        "source_psf_sampledom_correspondence_established": False,
        "infrastructure_failure_included": False,
    }
    if ideal_union_norm_reject is not None:
        norm = _probability(ideal_union_norm_reject)
        result.update(reference_norm_reject_upper=str(norm),
                      actual_issuance_abort_upper_excluding_infrastructure=str(_upper(distance+norm)))
    return result


def signature_norm_bound(*, dimension, degree, response_squared_cap,
                         perturbation_largest_squared_width, perturbation_smoothing_epsilon,
                         scalar_squared_width, scalar_smoothing_epsilon,
                         signing_stacked_spectral_squared_upper):
    """Uniform even for challenge c chosen from the perturbation commitment.

    Write v=u+zeta* c/2, hence z=p+T*zeta*v. The scalar law of v is a
    centered Gaussian on a shifted Z^n; ||zeta||^2=2. Allocate norm radii
    alpha*sqrt(B), (1-alpha)*sqrt(B), alpha=j/32, and union-bound the two
    tails. No independence of c and p, or final signature Gaussian, is used.
    """
    _count(dimension, "dimension", 2**17)
    _count(degree, "degree", 2**16)
    if degree < 2 or dimension < degree or dimension % degree:
        raise ValueError("whole polynomial blocks required")
    cap, width, beta = map(_positive_exact, (response_squared_cap,
        perturbation_largest_squared_width, signing_stacked_spectral_squared_upper))
    scalar_squared_width = _positive_exact(scalar_squared_width)
    best, selected = Fraction(1), None
    for j in range(1, 32):
        alpha = Fraction(j, 32)
        perturbation_cap = alpha**2*cap
        scalar_cap = (1-alpha)**2*cap/(2*beta)
        perturbation = norm_tail_upper(dimension=dimension, squared_cap=perturbation_cap,
            largest_squared_width=width, smoothing_epsilon=perturbation_smoothing_epsilon)
        scalar = norm_tail_upper(dimension=degree, squared_cap=scalar_cap,
            largest_squared_width=scalar_squared_width, smoothing_epsilon=scalar_smoothing_epsilon)
        value = _upper(Fraction(perturbation["probability_upper"])+Fraction(scalar["probability_upper"]))
        if value < best:
            best, selected = value, {
                "radius_fraction_alpha": str(alpha),
                "perturbation_norm_squared_cap": str(perturbation_cap),
                "centered_scalar_norm_squared_cap": str(scalar_cap),
                "perturbation_tail": perturbation, "shifted_scalar_tail": scalar,
            }
    return {
        "ideal_sequential_sign_attempt_norm_reject_upper": str(best),
        "selected_allocation": selected,
        "uniform_in_key_with_declared_norm_cap_and_adaptive_challenge": True,
        "signature_gaussian_identified": False,
        "declared_spectral_bound_verified_by_caller": False,
    }


def service_ledger(*, new_identities, signing_queries, max_sign_attempts,
                   issuance_to_reference_tv, sign_attempt_to_reference_tv,
                   issuance_abort, sign_sampling_abort, sign_norm_reject,
                   infrastructure_abort=None):
    """Conditional per-history union/coupling bounds, including all norm retries.

    sign_norm_reject must bound the ACTUAL attempt, rather than an unrelated
    Gaussian. normReject^K uses fresh entropy and a uniform conditional bound
    at every attempted history; it does not assume independent messages/keys.
    """
    qe, qs = _count(new_identities, "new identities"), _count(signing_queries, "signing queries")
    attempts = _count(max_sign_attempts, "max attempts", 128)
    if attempts < 1:
        raise ValueError("at least one signature attempt required")
    etv, stv, ea, sa, sr = map(_probability, (issuance_to_reference_tv,
        sign_attempt_to_reference_tv, issuance_abort, sign_sampling_abort, sign_norm_reject))
    sign_abort = _upper(attempts*sa+sr**attempts)
    crypto = _upper(qe*ea+qs*sign_abort)
    infra = None if infrastructure_abort is None else _probability(infrastructure_abort)
    return {
        "new_identities": qe, "signing_queries": qs, "max_sign_attempts": attempts,
        "transcript_to_hnf_key_and_sequential_sign_reference_tv_upper": str(_upper(qe*etv+qs*attempts*stv)),
        "actual_signature_operation_abort_upper_excluding_infrastructure": str(sign_abort),
        "service_abort_upper_conditional_on_no_infrastructure_failure": str(crypto),
        "full_service_abort_upper": None if infra is None else str(_upper(crypto+infra)),
        "infrastructure_model_supplied": infra is not None,
        "cached_issuance_adds_no_sampler_call": True,
        "requires_uniform_conditional_bounds_and_fresh_attempt_entropy": True,
        "reference_is_not_a_proved_security_game_simulator": True,
    }


def profile_report(name, config, sampling_report):
    """Combine concrete executable n8 profile certificates, not measured rates."""
    c = config
    beta = 2*c.rank*c.rank*c.digits*c.degree*c.degree+1
    fiber = normalizer_certificate(degree=c.degree,rank=c.rank,base=c.base,
                                  digits=c.digits,r_squared=c.r_squared)
    convolution = bridge_certificate(degree=c.degree,rank=c.rank,base=c.base,digits=c.digits,
        r_squared=c.r_squared,master_minimum_squared=min(c.master_first_squared,c.master_second_squared),
        fiber_lower=Fraction(fiber["uniform_relative_lower_exact"]),
        fiber_upper=Fraction(fiber["uniform_relative_upper_exact"]))
    basis = kernel_basis_bound(degree=c.degree,rank=c.rank,p=c.p,base=c.base,digits=c.digits,
                               witness_spectral_squared_upper=beta)
    exact = reference_certificate(degree=c.degree,rank=c.rank,p=c.p,base=c.base,digits=c.digits,
        first_squared=c.master_first_squared,second_squared=c.master_second_squared,
        basis_gso_squared_upper=basis["basis_gso_squared_upper"],user_norm_squared=c.user_norm_squared)
    convolution_tv = convolution["ideal_raw_to_union_gaussian_tv_upper_exact"]
    # Derive the PRE-RAW bound from the actual hybrid components. A TV bound
    # stated only after HNF would not permit reversing data processing.
    implementation_tv = str(_upper(Fraction(sampling_report["master_perturbation"][
        "perturbation_target_tv_upper_including_abort"])+Fraction(sampling_report["gadget"][
        "total_fiber_tv_upper_including_abort"])))
    norm_tail = exact.get("approximate_fiber_hnf_norm_reject")
    key = hnf_reference_comparison(sampler_tv_including_abort=implementation_tv,
        raw_convolution_tv=convolution_tv,
        ideal_union_norm_reject=None if norm_tail is None else norm_tail["probability_upper"])
    n, dim = c.degree, (c.algebra.columns+1)*c.degree
    # Perturbation shape >=r²I follows the already-enforced public class gate.
    eps_p = smoothing_certificate(dim,c.r_squared,80)["dual_gaussian_mass_upper"]
    eps_u = smoothing_certificate(n,c.r_squared,80)["dual_gaussian_mass_upper"]
    norm = signature_norm_bound(dimension=dim,degree=n,response_squared_cap=c.signature_bound_squared,
        perturbation_largest_squared_width=max(c.signature_first_squared,c.signature_second_squared),
        perturbation_smoothing_epsilon=Fraction(eps_p),scalar_squared_width=c.r_squared,
        scalar_smoothing_epsilon=Fraction(eps_u),
        signing_stacked_spectral_squared_upper=n*c.user_norm_squared+1)
    sign_tv = Fraction(sampling_report["sign_attempt_vs_sequential_ideal_sampler_tv_upper_including_abort"])
    actual_reject = _upper(sign_tv+Fraction(norm["ideal_sequential_sign_attempt_norm_reject_upper"]))
    ledgers = []
    if "actual_issuance_abort_upper_excluding_infrastructure" in key:
        for queries in (1,2**20,2**40):
            ledgers.append(service_ledger(new_identities=c.max_users,signing_queries=queries,
                max_sign_attempts=c.sign_max_attempts,
                issuance_to_reference_tv=key["complete_issuance_to_common_hnf_gate_reference_tv_upper"],
                sign_attempt_to_reference_tv=str(sign_tv),
                issuance_abort=key["actual_issuance_abort_upper_excluding_infrastructure"],
                sign_sampling_abort=sampling_report["sign_attempt_internal_sampling_abort_upper"],
                sign_norm_reject=actual_reject))
    return {"name":name,"parameters":c.record(),
        "master_witness_public_support_beta_squared": beta,
        "finite_issuance_tv_stage":"pre-raw convolution; sum of perturbation and gadget hybrid bounds",
        "full_kernel_gso_squared_upper": str(basis["basis_gso_squared_upper"]),
        "convolution":convolution,"hnf_reference_comparison":key,
        "exact_gaussian_reference":exact,
        "exact_gaussian_reference_comparison":complete_key_comparison(exact,
            sampler_tv_including_abort=Fraction(implementation_tv),
            raw_convolution_tv=None if convolution_tv is None else Fraction(convolution_tv)),
        "sign_norm":norm,"actual_sign_attempt_norm_reject_upper_including_sampling_error":str(actual_reject),
        "service_ledgers":ledgers}


def build_report():
    # Only the concrete-profile sampler certificate needs Sage.
    from .qualification_audit import profiles
    from .sampling_error import build_report as sampling_report
    return {"schema":"IBME/SRGG-ORACLE-LEDGER/1",
        "profiles":[profile_report(name,c,sampling_report(c)) for name,c in profiles().items()],
        "scope":"public-reference distribution and conditional algorithmic abort, not security reduction",
        "infrastructure_failure_model":None,
        "security_claim":"none","backend_admitted":False,"parameters_are_formal":False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path)
    args = parser.parse_args()
    encoded = json.dumps(build_report(),ensure_ascii=False,indent=2)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(encoded,encoding="utf-8",newline="\n")
    else:
        print(encoded,end="")


if __name__ == "__main__":
    main()
