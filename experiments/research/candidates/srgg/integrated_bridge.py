"""Join the structured SRGG sampler, mixed HNF reference and oracle ledger.

This is an entropy-free certificate for an independent execution namespace.
It is not a public backend, a fixed issuer, or a cryptographic reduction.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from fractions import Fraction
import json
from math import isqrt
from pathlib import Path

from .convolution_bridge import bridge_certificate
from .fiber_normalizers import normalizer_certificate
from .formal_candidates import conditional_candidate, smoothing_certificate
from .mixed_domain import image_uniformity_bound
from .oracle_ledger import hnf_reference_comparison, service_ledger, signature_norm_bound
from .psf_bridge import _upper, kernel_basis_bound, norm_tail_upper, reference_certificate
from .spectral_bounds import public_t_squared_upper


def _integer(value, name, low=1, high=2**32):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("bounded exact integer required: "+name)
    return value


def _probability(value):
    if isinstance(value,bool) or not isinstance(value,(int,Fraction,str)):
        raise ValueError("exact probability required")
    result = Fraction(value)
    if not 0 <= result <= 1:
        raise ValueError("probability outside [0,1]")
    return result


def mixed_entropy_bound(*, dimension, head_dimension, squared_width, modulus,
                        kernel_relative_error):
    """Coarse conditional entropy without a global-wrap probability loss.

    For isotropic, zero-centered U, Poisson gives rho_s(Z^N)>=s^(N/2).
    A shifted Gaussian sum on QZ is <=1+sqrt(s)/Q (peak plus integral).
    Independent head translations cannot increase that maximum. Conditioning
    costs at most Q^H*(1+eps)/(1-eps). No one-wayness follows from this.
    """
    n = _integer(dimension,"dimension",2,2**17)
    h = _integer(head_dimension,"head dimension",1,n)
    s = _integer(squared_width,"isotropic squared width",1,2**128)
    q = _integer(modulus,"modulus",2,2**128)
    eps = _probability(kernel_relative_error)
    if n%2 or eps>Fraction(1,3):
        raise ValueError("even dimension and kernel relative error <=1/3 required")
    root = isqrt(s)
    root += root*root<s
    lower_log = s.bit_length()-1
    upper_log = (q+root-1).bit_length()
    bits = max(0,lower_log*(n//2)-upper_log*h-1)
    return {"ideal_conditional_min_entropy_bits_lower":bits,
        "ideal_conditional_atom_upper_dyadic_exponent":-bits,
        "squared_width_log2_lower":lower_log,"Q_plus_ceil_width_log2_upper":upper_log,
        "head_aliases_included":True,"global_wrap_bound_used":False,
        "scope":"unfiltered D_mix conditioned on public A Y=h; isotropic zero-centered base",
        "onewayness_or_signature_entropy_proved":False}


def successful_key_entropy(*, ideal_bits, key_tv_including_abort, actual_abort_upper):
    """Atom bound for returned keys, conditional on success, not entropy of abort."""
    bits = _integer(ideal_bits,"ideal bits",0,2**24)
    delta,abort = map(_probability,(key_tv_including_abort,actual_abort_upper))
    if abort>=1:
        return {"available":False,"reason":"no positive success lower bound"}
    # A 1024-bit envelope is sufficient for transport; preserve the full count.
    atom = min(Fraction(1),(Fraction(1,2**min(bits,1024))+delta)/(1-abort))
    lower = 0
    while lower<1024 and atom<=Fraction(1,2**(lower+1)):
        lower+=1
    return {"available":True,"conditional_success_max_atom_upper_exact":str(atom),
        "conditional_success_min_entropy_bits_lower":lower,
        "ideal_atom_envelope_bits_used":min(bits,1024),
        "uniform_in_target_given_verified_class_bounds":True,
        "onewayness_or_signature_entropy_proved":False}


def execution_certificate(execution, *, profile, queries=(1,2**20,2**40)):
    """Compose the actual independent class plans; consumes no random bytes."""
    from .structured_execution import Execution
    if not isinstance(execution,Execution):
        raise ValueError("validated independent Execution required")
    if not isinstance(profile,str) or not 1<=len(profile)<=64:
        raise ValueError("bounded profile name required")
    if not isinstance(queries,(tuple,list)) or not 1<=len(queries)<=16:
        raise ValueError("bounded query list required")
    for count in queries:
        _integer(count,"queries",0,2**64)
    p = execution.params
    master,sign = execution.class_master_certificate,execution.class_sign_certificate
    gadget,u = execution.gadget.certificate(),execution.u_batch
    finite_key = _upper(Fraction(master["full_target_integer_tv_upper_including_abort"])+
                        Fraction(gadget["total_fiber_tv_upper_including_abort"]))
    finite_sign = _upper(Fraction(sign["full_target_integer_tv_upper_including_abort"])+
                         Fraction(u["scalar_kernel_tv_including_aggregate_exact"]))
    fiber = normalizer_certificate(degree=p.degree,rank=p.rank,base=p.base,
                                  digits=p.digits,r_squared=p.r_squared)
    beta = public_t_squared_upper(p.degree,p.rank,p.digits)
    convolution = bridge_certificate(degree=p.degree,rank=p.rank,base=p.base,digits=p.digits,
        r_squared=p.r_squared,master_minimum_squared=p.master_squared,
        fiber_lower=Fraction(fiber["uniform_relative_lower_exact"]),
        fiber_upper=Fraction(fiber["uniform_relative_upper_exact"]),t_squared_upper=beta,
        witness_bound_origin="verified entire CBD1 class: public_t_squared_upper")
    conv_tv = convolution["ideal_raw_to_union_gaussian_tv_upper_exact"]
    if conv_tv is None:
        raise ValueError("convolution certificate unavailable")
    basis = kernel_basis_bound(degree=p.degree,rank=p.rank,p=p.p,base=p.base,digits=p.digits,
                               witness_spectral_squared_upper=beta)
    exact = reference_certificate(degree=p.degree,rank=p.rank,p=p.p,base=p.base,digits=p.digits,
        first_squared=p.master_squared,second_squared=p.master_squared,
        basis_gso_squared_upper=basis["basis_gso_squared_upper"])
    if not exact["reference_certificate_available"]:
        raise ValueError("full-kernel smoothing certificate unavailable")
    eps = Fraction(exact["uniform_coset_relative_error_upper"])
    raw_reject = norm_tail_upper(dimension=p.columns*p.degree,squared_cap=p.raw_norm_cap,
        largest_squared_width=p.master_squared,smoothing_epsilon=eps)
    raw_tail = Fraction(raw_reject["probability_upper"])
    # Execution also gates the PRE-repair raw vector. This gate is not a
    # predicate of Y alone when repair has aliases. Removing it costs its
    # ideal-union tail before comparison with the common PUBLIC Y norm gate.
    key = hnf_reference_comparison(sampler_tv_including_abort=_upper(finite_key+raw_tail),
        raw_convolution_tv=Fraction(conv_tv),ideal_union_norm_reject=Fraction(raw_reject["probability_upper"]))
    key["additional_pre_repair_raw_gate_tv_upper"] = str(raw_tail)
    key["reference_is_mixed_domain_given_target_with_public_output_norm_gate"] = True
    key["abort_bound_conservatively_counts_raw_tail_twice"] = True
    # The strict constructor enforces user_cap>=2 raw_cap+2dn(p-1)^2,
    # so this raw gate covers BOTH executable key norm gates.
    entropy = mixed_entropy_bound(dimension=p.columns*p.degree,head_dimension=p.rank*p.degree,
        squared_width=p.master_squared,modulus=p.modulus,kernel_relative_error=eps)
    successful = successful_key_entropy(ideal_bits=entropy["ideal_conditional_min_entropy_bits_lower"],
        key_tv_including_abort=key["complete_issuance_to_common_hnf_gate_reference_tv_upper"],
        actual_abort_upper=key["actual_issuance_abort_upper_excluding_infrastructure"])
    ds = (p.columns+1)*p.degree
    eps_p = Fraction(smoothing_certificate(ds,p.r_squared,80)["dual_gaussian_mass_upper"])
    eps_u = Fraction(smoothing_certificate(p.degree,p.r_squared,80)["dual_gaussian_mass_upper"])
    sign_norm = signature_norm_bound(dimension=ds,degree=p.degree,response_squared_cap=p.signature_norm_cap,
        perturbation_largest_squared_width=p.signature_squared,perturbation_smoothing_epsilon=eps_p,
        scalar_squared_width=p.r_squared,scalar_smoothing_epsilon=eps_u,
        signing_stacked_spectral_squared_upper=1+Fraction(p.degree,2)*p.user_norm_cap)
    actual_norm = _upper(finite_sign+Fraction(sign_norm["ideal_sequential_sign_attempt_norm_reject_upper"]))
    # Each sampler abort event is bounded by its full coupling error to the
    # non-aborting ideal law, under the stated correct-MPFR/no-arithmetic-
    # failure assumptions. Runtime-library/hardware faults are not assigned
    # a probability by this arithmetic certificate.
    ledgers = []
    for count in queries:
        row = service_ledger(new_identities=count,signing_queries=count,max_sign_attempts=p.sign_max_attempts,
            issuance_to_reference_tv=key["complete_issuance_to_common_hnf_gate_reference_tv_upper"],
            sign_attempt_to_reference_tv=finite_sign,
            issuance_abort=key["actual_issuance_abort_upper_excluding_infrastructure"],
            sign_sampling_abort=finite_sign,sign_norm_reject=actual_norm)
        row["transcript_tv_passes_2_minus_128"] = Fraction(row[
            "transcript_to_hnf_key_and_sequential_sign_reference_tv_upper"])<=Fraction(1,2**128)
        row["conditional_algorithm_abort_passes_2_minus_128"] = Fraction(row[
            "service_abort_upper_conditional_on_no_infrastructure_failure"])<=Fraction(1,2**128)
        ledgers.append(row)
    return {"profile":profile,"parameters":asdict(p),"Q":p.modulus,
        "series_options":asdict(execution.series_options),"scalar_options":asdict(execution.scalar_options),
        "master_sampler":master,"sign_sampler":sign,"gadget":gadget,"u_batch":u,
        "issuance_pre_raw_finite_and_recurrence_tv_upper":str(finite_key),
        "convolution":convolution,"full_kernel_reference":exact,
        "hnf_common_gate_comparison":key,"raw_union_norm_reject":raw_reject,
        "mixed_image_uniformity":image_uniformity_bound(eps),"mixed_ideal_entropy":entropy,
        "successful_issued_key_entropy":successful,"sign_attempt_finite_tv_upper":str(finite_sign),
        "sign_norm":sign_norm,"actual_sign_norm_reject_upper":str(actual_norm),"query_ledgers":ledgers,
        "raw_gate_covers_repaired_user_gate":True,
        "query_ledger_is_conditional_arithmetic_not_executed_service_capacity":True,
        "unclosed":["source Gaussian-secret SIG/PSF and mixed-domain one-wayness",
            "adaptive IBS reduction and native strong game",
            "underlying hardness estimates and NIST classification",
            "public backend and persistent service for this new execution namespace",
            "infrastructure/global operational-cap probability model"],
        "security_claim":"none","backend_admitted":False,"parameters_are_formal":False}


def build_report(*,degree=512,rank=2,digits=8):
    from .structured_execution import Execution,ExecutionParams,sampler_profile
    class NoEntropy:
        def read(self,size):
            raise RuntimeError("certificate must not consume entropy")
    params = ExecutionParams.from_candidate(conditional_candidate(degree=degree,rank=rank,digits=digits))
    rows = []
    for profile in ("default","query-bounded-deep"):
        series,scalar = sampler_profile(profile)
        execution = Execution(params,rng=NoEntropy(),series_options=series,scalar_options=scalar)
        rows.append(execution_certificate(execution,profile=profile))
    return {"schema":"IBME/SRGG-INTEGRATED-BRIDGE/1","profiles":rows,"actual_entropy_bytes":0,
        "scope":"conditional final integer/HNF/oracle bounds; no security reduction or NIST admission",
        "security_claim":"none","backend_admitted":False,"parameters_are_formal":False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--degree",type=int,default=512)
    parser.add_argument("--rank",type=int,default=2)
    parser.add_argument("--digits",type=int,default=8)
    parser.add_argument("--output",type=Path,required=True)
    args = parser.parse_args()
    report = build_report(degree=args.degree,rank=args.rank,digits=args.digits)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8",newline="\n")


if __name__=="__main__":
    main()
