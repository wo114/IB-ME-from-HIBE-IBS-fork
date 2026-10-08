"""Finite analytic prescreen for the matrix-SIS Foo-Li research route.

No matrices, keys, signatures or security levels are produced. Log bounds are
outward MPFI endpoints. Passing these necessary/sufficient numeric checks is
NOT backend admission: actual DelTrap/SampleD, ROM reduction and SIS cost remain
separate obligations. No frozen teammate evidence is overwritten.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
from functools import lru_cache
import json
from math import isqrt
from pathlib import Path
import platform
import sys

from sage.all import GF, QQ, ZZ, RealIntervalField, matrix
from sage.version import version as sage_version

from .online_gaussian_reference import (
    OnlineOptions, OnlineScalarGaussian, capped_exp_minus_pi, interval_upper,
)
from .gaussian_reference import draw_uniform_integer
from ibme.core.randomness import DeterministicRandom


FIELD = RealIntervalField(256)


def integer(value, name, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer in [{minimum},{maximum}]")
    return value


def log2_interval(value):
    value = FIELD(value)
    if value.lower() <= 0:
        raise ValueError("log2 requires a strictly positive interval")
    return value.log()/FIELD(2).log()


def log2_upper(value):
    return interval_upper(log2_interval(value))


def logsum_upper(*upper_logs):
    """sum(a_i) <= count * 2^max(log_upper_i); safe also for tiny terms."""
    if not upper_logs:
        raise ValueError("No terms in log sum")
    return interval_upper(FIELD(max(upper_logs))+log2_interval(len(upper_logs)))


def log_record(upper_log):
    upper_log = QQ(upper_log)
    return {"log2_upper_exact": str(upper_log), "log2_upper_display": float(upper_log)}


def lll_determinant_control(q, n, m, beta_squared):
    """Conservative standard LLL bound for a public n x (3n+4) submatrix.

On an invertible leading n-block det(kernel)=q^n. With delta=3/4 and
eta=501/1000, delta-eta^2>1/3, hence ||b1||<=3^((h-1)/4)q^(n/h).
For uniform challenges the leading block is singular with probability <=n/q.
This is an analytic attack exclusion, not a measured bit-security estimate.
"""
    h=min(m,3*n+4)
    squared_log=interval_upper(((h-1)/QQ(2))*log2_interval(3)+
        (2*n/QQ(h))*log2_interval(q))
    beta_log_lower=log2_interval(beta_squared).lower().exact_rational()
    return {"active_columns":h,"LLL_alpha_upper":3,
        "LLL_squared_norm_bound":log_record(squared_log),
        "bound_fits_beta_red":h>n and squared_log<=beta_log_lower,
        "leading_block_singular_probability_upper":str(min(QQ(1),QQ(n)/q)),
        "model":"uniform prime-q SIS challenge; exact standard polynomial-time LLL theorem",
        "Lean_formalized":False}


def regularity_bound(q, n, m_bar, width_squared):
    """Unfiltered ideal GenTrap: w/2 sqrt(q^n c^mbar), c<=1/q+1/r.

Prime-q linear universal hashing; a Gaussian residue atom is at most
(1+r/q)/rho_r(Z) <= 1/q+1/r. Hybrid columns retain the SAME Abar.
This bounds TV(public A, uniform), not TV(implementation, ideal Gaussian).
"""
    integer(q, "q", 2, 2**256)
    integer(n, "n", 1, 4096)
    integer(m_bar, "m_bar", 1, 8*10**6)
    integer(width_squared, "generation width squared", 1, 10**12)
    if not ZZ(q).is_prime():
        raise ValueError("Prime modulus required for the universal family")
    w = n*(q-1).bit_length()
    c = min(QQ(1), interval_upper(FIELD(1)/q+1/FIELD(width_squared).sqrt()))
    uncapped = interval_upper(log2_interval(w)-1+
        (n*log2_interval(q)+m_bar*log2_interval(c))/2)
    return {"residue_atom_upper": str(c),
        "ideal_public_tv_log2_uncapped": str(uncapped),
        "ideal_public_tv": log_record(min(QQ(0), uncapped)),
        "before_quality_filter": True, "column_factor": w,
        "assumptions": "prime q; uniform Abar; iid infinite zero-center Gaussian entries"}


@lru_cache(maxsize=128)
def scalar_profile(width_squared, bits):
    opts = OnlineOptions(tail_bits=bits, mass_bits=bits+32,
        precision_bits=bits+128, gaussian_abort_bits=bits+16,
        max_uniform_trials=bits+16)
    scalar = OnlineScalarGaussian(width_squared, width_squared, options=opts)
    return scalar.tv_upper, scalar.certificate(), opts


def uniform_good_matrix_logs(q, n, m, width_squared, epsilon):
    """Round-six Markov/rank bound, extended analytically without dense matrices.

Ambient (1+b)^m-1 <= mb exp(mb), avoiding cancellation and exponent underflow.
Tiny exp(-pi*v) is replaced by a rigorously LARGER capped interval.
"""
    a = capped_exp_minus_pi(QQ(width_squared), FIELD, 512)
    b = interval_upper(2*a/(1-a**3))
    ambient = interval_upper(log2_interval(m)+log2_interval(b)+FIELD(m*b)/FIELD(2).log())
    c = interval_upper(FIELD(1)/q+1/FIELD(width_squared).sqrt())
    nonzero = interval_upper(n*log2_interval(q)+m*log2_interval(c))
    expected = logsum_upper(ambient, nonzero)
    rank = interval_upper(log2_interval(n)+(n-1-m)*log2_interval(q))
    bad = logsum_upper(rank, interval_upper(FIELD(expected)-log2_interval(epsilon)))
    eta = 2*epsilon/(1+epsilon)
    atom = interval_upper(n*log2_interval(q)-log2_interval(1-eta)-
        (m/QQ(2))*log2_interval(width_squared))
    return {"uniform_A_bad_event": log_record(min(QQ(0), bad)),
        "conditional_column_atom": log_record(min(QQ(0), atom)),
        "pointwise_image_error": str(eta),
        "basis": "round-six uniform-matrix rank/Markov proof; not empirical spectral constants"}


def screen(q, n, *, bits=160, generation_width_squared=16, m_bar=None):
    """One conservative analytic family. `bits` is a component budget, NOT security."""
    integer(q, "q", 2, 2**256)
    integer(n, "n", 1, 4096)
    integer(bits, "component budget bits", 16, 512)
    integer(generation_width_squared, "generation width squared", 1, 10**12)
    if not ZZ(q).is_prime():
        raise ValueError("Need a prime modulus")
    k, gamma = (q-1).bit_length(), 5
    w = n*k
    c = min(QQ(1), interval_upper(FIELD(1)/q+1/FIELD(generation_width_squared).sqrt()))
    if m_bar is None:
        if c >= 1:
            raise ValueError("Automatic regularity family needs a nonvacuous residue atom bound")
        denominator = -log2_interval(c)
        lower = denominator.lower().exact_rational()
        numerator = interval_upper(n*log2_interval(q)+2*(bits+4+log2_interval(w)-1))
        m_bar = max(w+16, int((numerator/lower).ceil()))
    integer(m_bar, "m_bar", 1, 8*10**6)
    m, d = m_bar+w, m_bar+2*w
    entries = m_bar*w
    e0 = QQ(1)/2**bits
    inner_epsilon = QQ(1)/2**(bits+(w-1).bit_length()+8)
    mp12_need = interval_upper(FIELD(2*w*(1+1/inner_epsilon)).log()/FIELD.pi())
    c2_factor = interval_upper(FIELD(2*m*(1+1/e0)).log()/FIELD.pi())
    r_squared = max(1, int(mp12_need.ceil()), int((10*c2_factor/(gamma+2)).ceil()))
    q0 = entries*generation_width_squared
    s_squared = r_squared*(gamma+2)*(q0+1)
    q1 = m*w*s_squared
    t_squared = r_squared*(gamma+2)*(q1+1)
    beta_squared = 4*t_squared*d*(1+q1)
    signature_bound_squared = t_squared*d
    c2_threshold = interval_upper(FIELD(10*(q0+1))*FIELD(2*m*(1+1/e0)).log()/FIELD.pi())
    reg = regularity_bound(q, n, m_bar, generation_width_squared)
    scalar_bits = bits+(max(entries,n*m_bar)-1).bit_length()+12
    scalar_tv, scalar_certificate, options = scalar_profile(generation_width_squared, scalar_bits)
    e_gen = entries*scalar_tv+QQ(n*m_bar)/2**options.max_uniform_trials
    log_public = logsum_upper(QQ(reg["ideal_public_tv"]["log2_upper_exact"]), log2_upper(e_gen))
    good = uniform_good_matrix_logs(q, n, m, s_squared, e0)
    ef = 2*e0+e0**2
    # Since F extends A and t>=s, theta_F(t)<=2e0+e0^2, and rho_t(Z)>=t.
    z_atom = interval_upper(n*log2_interval(q)-log2_interval((1-ef)/(1+ef))-
        (d/QQ(2))*log2_interval(t_squared))
    a = capped_exp_minus_pi(QQ(r_squared), FIELD, 512)
    denominator = 1-2*w*a
    if denominator.lower() <= 0:
        raise ValueError("MP12 smoothing denominator not positive")
    epsilon = interval_upper(2*w*a/denominator)
    convolution = interval_upper(FIELD(4*epsilon)/(1-FIELD(epsilon))**2)
    signature_bits = (2*isqrt(signature_bound_squared)).bit_length()
    master_bits = (2*isqrt(q0)).bit_length()
    user_bits = (2*isqrt(q1)).bit_length()
    checks = {
        "ideal_plus_finite_generation_regularity": log_public <= -bits,
        "C2_sufficient_width": s_squared >= c2_threshold,
        "uniform_A_good_event": QQ(good["uniform_A_bad_event"]["log2_upper_exact"]) <= -bits,
        "conditional_R_atom": QQ(good["conditional_column_atom"]["log2_upper_exact"]) <= -bits,
        "conditional_reference_z_atom": z_atom <= -bits,
        "ideal_MP12_convolution_times_columns": w*convolution <= QQ(1)/2**bits,
        "nontrivial_SIS_norm": beta_squared < q*q,
        "matrix_dimension_conditions": m >= 2*w and w >= n,
    }
    limits = {"q_at_most_32_bits": q <= 2**32, "base_dimensions_at_most_128": n <= 128 and m_bar <= 128,
        "complete_output_dimension_at_most_128": d <= 128,
        "quality_caps": max(q0,q1) <= 10**12,
        "output_squared_width_caps": max(s_squared,t_squared) <= 10**12,
        "public_Sigma_caps": (gamma+2)*(max(q0,q1)+1) <= 2**40}
    return {"parameters": {"q":q,"n":n,"k":k,"w":w,"m_bar":m_bar,"m":m,"d":d,
            "component_budget_bits":bits,"generation_width_squared":generation_width_squared,
            "gamma":gamma,"r_squared":r_squared,"master_quality_squared":q0,
            "user_quality_squared":q1,"s_squared":s_squared,"t_squared":t_squared,"epsilon0":str(e0)},
        "regularity":reg,"conditional_generation_tv":log_record(log2_upper(e_gen)),
        "conditional_public_tv":log_record(min(QQ(0),log_public)),
        "C2_required_width_squared_upper":str(c2_threshold),
        "uniform_matrix":good,"conditional_reference_z_atom":log_record(min(QQ(0),z_atom)),
        "master_ideal_quality_tail":log_record(-entries),
        "user_ideal_quality_tail":log_record(interval_upper(log2_interval(w)-m+log2_interval((1+e0)/(1-e0)))),
        "signature_ideal_norm_tail":log_record(interval_upper(FIELD(-d)+log2_interval((1+ef)/(1-ef)))),
        "ideal_MP12_convolution_upper":str(convolution),
        "beta_red_squared":beta_squared,"signature_norm_bound_squared":signature_bound_squared,
        "beta_red_over_q_log2":log_record(interval_upper((log2_interval(beta_squared)-2*log2_interval(q))/2)),
        "analytic_checks":checks,"analytic_prescreen_pass":all(checks.values()),
        "known_reference_limits":limits,"known_reference_limits_pass":all(limits.values()),
        "actual_runtime_prepare_checked":False,
        "standard_LLL_attack_control":lll_determinant_control(q,n,m,beta_squared),
        "costs": {"packed_public_matrix_bytes":(n*m*k+7)//8,
            "packed_master_R_bytes_upper":(entries*master_bits+7)//8,
            "packed_user_R_bytes_upper":(m*w*user_bits+7)//8,
            "packed_signature_vector_and_bit_bytes_upper":(d*signature_bits+1+7)//8,
            "dense_geometry_8byte_cells_bytes":8*d*d,
            "public_matrix_JSON_bytes_upper":n*m*(len(str(q-1))+1)+2*n+1,
            "not_measured_RSS_or_wire_sizes":True},
        "scalar_generation_options":asdict(options),"scalar_generation_certificate":scalar_certificate,
        "open_obligations": {"actual_DelTrap_total_TV":None,"actual_SampleD_total_TV":None,
            "full_ROM_query_loss_budget":None,"reference_sampling_mu_R_mu_z":None,
            "SIS_classical_cost":None,"SIS_quantum_cost":None,
            "SHAKE_instantiation_gap":None,"Lean_MP12_geometry_bridge":None},
        "admitted_backend":False,"security_claim":"none"}


def sis_public_control(case):
    """Small public SIS diagnostic, not an IBS forgery or a hardness estimate.

Only n<=64 and 3n+4 public columns are materialized. A singular leading block
is recorded without retries. Exact output checks certify a found relation.
The public fixed SHAKE test source is not a fresh cryptographic experiment.
"""
    p=case["parameters"]
    q,n,m=p["q"],p["n"],p["m"]
    if n>64:
        raise ValueError("Control deliberately capped at n<=64")
    active=min(m,3*n+4)
    if active<=n:
        raise ValueError("Need more columns than rows")
    rng=DeterministicRandom(f"FooLi-SIS-public-control:n={n}:q={q}".encode())
    a=matrix(GF(q),n,active,[draw_uniform_integer(rng,q) for _ in range(n*active)])
    leading=a[:,:n]
    if not leading.is_invertible():
        return {"n":n,"q":q,"status":"leading_block_singular","no_retry":True}
    quotient=leading.inverse()*a[:,n:]
    basis=matrix(ZZ,active,active)
    for i in range(n):basis[i,i]=q
    for j in range(active-n):
        for i in range(n):basis[n+j,i]=-int(quotient[i,j])
        basis[n+j,n+j]=1
    reduced=basis.LLL(delta=0.75,eta=0.501)
    z=min(reduced.rows(),key=lambda v:sum(int(x)**2 for x in v))
    square=sum(int(x)**2 for x in z)
    equation=bool((a*z).is_zero())
    nonzero=any(z)
    solves=equation and nonzero and square<=case["beta_red_squared"]
    assert equation and nonzero
    return {"n":n,"q":q,"active_columns":active,"full_challenge_columns":m,
        "public_A_active_rows":[[int(x) for x in row] for row in a.rows()],
        "solution_active_coefficients":[int(x) for x in z],
        "zero_padding_to_full_dimension_valid":True,"norm_squared":square,
        "beta_red_squared":case["beta_red_squared"],"equation_mod_q":equation,
        "nonzero":bool(nonzero),"solves_SIS_at_reduction_bound":bool(solves),
        "status":"explicit_public_SIS_solution" if solves else "no_solution_within_bound",
        "source":"one public fixed test seed per n/q; no retries",
        "lattice_algorithm":"Sage integer-row LLL, delta=0.75; exact output relation checked",
        "IBS_forgery_generated":False,"security_claim":"none"}


def report():
    primes = [65537,2147483647,4294967291,2**61-1,2**89-1,2**127-1]
    cases = [screen(q,n) for n in [1,8,64,128,256,512] for q in primes]
    controls=[sis_public_control(x) for x in cases if x['parameters']['n']<=64
        and x['parameters']['k'] in [61,89,127]]
    by_control={(x['n'],x['q']):x for x in controls}
    for x in cases:
        p=x['parameters'];control=by_control.get((p['n'],p['q']))
        x['public_SIS_solution_found']=bool(control and control.get('solves_SIS_at_reduction_bound'))
    return {"schema_version":1,"security_claim":"none","status":"analytic_prescreen_only",
        "environment":{"python":sys.version.split()[0],"sage":sage_version,"platform":platform.platform()},
        "parameter_source":"hand-defined conservative matrix-SIS family; no security-bit selection",
        "models":"ideal independent uniform bytes and classical ROM obligations; no complete QROM claim",
        "identity_bytes":None,"message_bytes":None,"monte_carlo_repetitions":0,
        "full_cryptographic_matrices_generated":0,"keys_generated":0,"signatures_generated":0,
        "public_SIS_control_count":len(controls),"public_SIS_controls":controls,
        "teammate_baseline":"35fb11a","integration_commit":"50f8ac3","cases":cases,
        "counts":{"cases":len(cases),"analytic_pass":sum(x['analytic_prescreen_pass'] for x in cases),
            "reference_limits_pass":sum(x['known_reference_limits_pass'] for x in cases),
            "public_SIS_solutions":sum(x.get('solves_SIS_at_reduction_bound',False) for x in controls),
            "standard_LLL_bound_exclusions":sum(x['standard_LLL_attack_control']['bound_fits_beta_red'] for x in cases),
            "analytic_pass_but_LLL_bound_excludes":sum(x['analytic_prescreen_pass'] and
                x['standard_LLL_attack_control']['bound_fits_beta_red'] for x in cases),
            "admitted_backends":0},
        "limitations":["A failed sufficient bound is inconclusive about actual security",
            "Finite generator bound is conditional on same scalar/uniform kernels and declared byte model",
            "Only the displayed family was screened; this is not an impossibility result for Foo-Li",
            "Packed payload bounds and a dense-cell model are not benchmarks or actual serialized sizes",
            "Actual sampler refinement, ROM total advantage and SIS attacks are not yet certified"]}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    value=json.dumps(report(),ensure_ascii=False,indent=2)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(value,encoding="utf-8",newline="\n")
    else:
        print(value,end="")


if __name__=="__main__":
    main()
