"""Finite CHKP numeric gates and rounded-Gaussian noise; RESEARCH ONLY.

The obstruction concerns CURRENT finite AP09 dimensions, GPV C1-exec and
the selected sufficient Lemma 5.1 modulus condition. It is not a claim that
CHKP, smaller noise, or another correctly certified sampler is impossible.
Noise bounds are conditional on the fixed preimage norm and exact CHKP
rounded continuous Gaussian. Sampling TV/abort and LWE hardness are separate.
"""

import argparse
from fractions import Fraction
import json
from math import isqrt
import re
from pathlib import Path

from .ibme_handoff_screen import _constant
from .chkp_paper_preflight import _is_prime


def integer(value, name, low=1, high=65536):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an exact integer in {low}..{high}")
    return value


def rational(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, str, Fraction)):
        raise ValueError(f"{name} requires an exact rational")
    if isinstance(value, str):
        if len(value) > 2400 or not re.fullmatch(r"[+-]?[0-9]+(?:/[0-9]+)?", value):
            raise ValueError(f"{name} requires bounded integer/fraction text")
    try:
        value = Fraction(value)
    except (ValueError, ZeroDivisionError) as exc:
        raise ValueError(f"invalid {name}") from exc
    if max(abs(value.numerator).bit_length(), value.denominator.bit_length()) > 4096:
        raise ValueError(f"{name} exceeds rational bit budget")
    return value


def ceil_sqrt(value):
    value = rational(value, "square")
    if value < 0:
        raise ValueError("square must be nonnegative")
    root = isqrt(value.numerator // value.denominator)
    return root + int(root * root < value)


def smoothing_factor(dimension, epsilon_bits):
    return (2 * dimension * (1 + 2**epsilon_bits) - 1).bit_length()


def matrix_tv_upper(n, q, random_rows, m2):
    """Match the delivered AP09 certificate's two upward rounding steps."""
    numerator, denominator = q**n * 2**160, 2**random_rows
    scaled = (numerator + denominator - 1) // denominator
    root = isqrt(scaled)
    if root * root < scaled:
        root += 1
    return min(Fraction(1), Fraction(m2 * root, 2**80))


def dimension_obstruction(*, leaf_cap, minimum_epsilon_bits=2):
    """Cover all q intervals, including composite endpoints, optimistically.

    ell=ceil(log2 q), r>=n*ell+1, m>=3*r+2*n*ell>=5*n*ell+3.
    Any complete integer lattice basis has max GS^2>=1: the product is the
    nonzero integer det(B)^2. C1-exec then requires s2^2>=4*k(3*m,b).
    Larger m,b only tighten this lower bound; q<=2^ell is optimistic.
    """
    cap = integer(leaf_cap, "leaf_cap", high=65536)
    bits = integer(minimum_epsilon_bits, "minimum_epsilon_bits", low=2, high=4096)
    product_cap = (cap // 3 - 3) // 5
    rows = []
    for n in range(1, min(16, product_cap) + 1):
        for ell in range(1, product_cap // n + 1):
            # The implementation's 61-bit modulus ceiling can only remove
            # cases. Use the larger power-of-two bound to preserve coverage.
            if ell > 61:
                continue
            dimension = 3 * (5 * n * ell + 3)
            factor = smoothing_factor(dimension, bits)
            q_upper = 2**ell
            required_q_squared = 64 * factor * (dimension + 1)**2
            rows.append(dict(n=n,ceil_log2_q=ell,minimum_leaf_dimension=dimension,
                             optimistic_q_upper=q_upper,minimum_s2_squared=4*factor,
                             required_q_squared=required_q_squared,
                             conflict=q_upper**2 < required_q_squared))
    return dict(scope="current finite dimension/C1-exec/Lemma5.1 sufficient gates",
                leaf_cap=cap,minimum_epsilon_bits=bits,intervals=rows,
                all_intervals_conflict=all(row["conflict"] for row in rows),
                empty_dimension_domain=not rows,
                physical_decryption_impossibility_claim=False,
                backend_admitted=False,security_claim="none")


def current_dimension_obstruction():
    return dimension_obstruction(leaf_cap=_constant("gpv", "MAX_DIMENSION"))


def evaluate_noise(*, q, dimension, width_squared, alpha, error_bits=64,
                   seed_bits=256, encapsulations=1):
    """Exact sufficient decode budget, conditional on ||x||^2<=s^2*D.

    c0-x^T*c1 = bit*floor(q/2) + rounded-error-combination modulo q.
    Rounding contributes <=(||x||_1+1)/2. Its continuous part is Gaussian
    of squared width q^2*alpha^2*(||x||^2+1). Chernoff gives
    Pr[|Z|>sqrt(b+1)*width] <= 2*exp(-pi*(b+1)) <= 2^-b.
    A union bound covers shared-preamble bits without assuming independence.
    """
    q = integer(q, "q", low=2, high=2**61-1)
    dim = integer(dimension, "dimension")
    bits = integer(error_bits, "error_bits", low=2, high=4096)
    count = integer(seed_bits, "seed_bits")
    calls = integer(encapsulations, "encapsulations", high=2**32)
    width, rate = rational(width_squared, "width_squared"), rational(alpha, "alpha")
    if width <= 0 or not 0 < rate < 1:
        raise ValueError("need positive width_squared and 0<alpha<1")
    norm_squared = width * dim
    l1_upper = ceil_sqrt(dim * norm_squared)
    rounding = Fraction(l1_upper + 1, 2)
    # Strict nearest-centre distance, including odd q and ties going to one.
    phase_radius = (q // 2 - 1) // 2
    margin = phase_radius - rounding
    continuous_squared = q*q*rate*rate*(norm_squared + 1)*(bits + 1)
    noise_ok = margin > 0 and continuous_squared <= margin*margin
    return dict(q=q,dimension=dim,width_squared=str(width),alpha=str(rate),
                assumed_preimage_norm_squared_upper=str(norm_squared),
                preimage_norm_measured_or_certified=False,
                l1_integer_upper=l1_upper,rounding_error_upper=str(rounding),
                integer_phase_radius=phase_radius,continuous_margin=str(margin),
                continuous_squared_upper=str(continuous_squared),
                conditional_noise_sufficient=noise_ok,error_bits=bits,
                conditional_per_bit_failure_upper=str(Fraction(1,2**bits)) if noise_ok else None,
                conditional_lifetime_failure_upper=str(min(1,Fraction(count*calls,2**bits))) if noise_ok else None,
                seed_bits=count,encapsulations=calls,q_times_alpha=str(q*rate),
                shared_preamble_independence_required=False,
                noise_definition="CHKP section 2.3.1: round(q*continuous Gaussian width alpha) mod q",
                noise_implementation_verified=False,lwe_hardness_or_reduction_verified=False,
                excluded=["key norm bad event", "sampler TV and abort", "basis/resource failures",
                          "finite continuous-noise implementation", "security estimation"],
                backend_admitted=False,security_claim="none")


def plan_numeric_candidate(*, n, q, public_tv_bits=32, epsilon_bits=64, error_bits=64,
                           seed_bits=256, encapsulations=2**20):
    """Plan a HYPOTHETICAL larger-resource diagnostic; do not override caps.

    Split the public error target into three quarter budgets for matrix TV,
    A1 rank failure (union upper n/q^(m1-n+1)), and uniform rejection abort.
    The actual GenBasis/GS/scalar profiles and HIBE are not executed here.
    """
    n = integer(n, "n", high=16)
    q = integer(q, "q", low=2, high=2**61-1)
    # Delivered public-TV certificates round to 2^-80, so arbitrary stronger
    # targets cannot be certified by simply increasing random_rows.
    public_bits = integer(public_tv_bits, "public_tv_bits", low=2, high=64)
    eps = integer(epsilon_bits, "epsilon_bits", low=2, high=128)
    integer(error_bits,"error_bits",low=2,high=4096)
    integer(seed_bits,"seed_bits")
    integer(encapsulations,"encapsulations",high=2**32)
    if not _is_prime(q):
        raise ValueError("plan requires a prime q")
    ell, d = (q-1).bit_length(), n*(q-1).bit_length()+1
    while True:
        m2 = 2*n*ell + 2*d
        if (matrix_tv_upper(n,q,d,m2) <= Fraction(1,2**(public_bits+2))
                and q**(d-n+1) >= n*2**(public_bits+2)):
            break
        d += 1
        if d > 4096:
            raise ValueError("planned random row count exceeds calculator budget")
    m, w = d+m2, 1 << ((m2-2*n*ell).bit_length()-1)
    scale = ceil_sqrt(Fraction(4*d*m2,w))
    root_gs = max((scale+3)**2*d+5,8*n*ell+2)
    d1, d2 = 2*m, 3*m
    s1_squared = 4*root_gs*smoothing_factor(d1,eps)
    s2_squared = 4*(s1_squared*d1)*smoothing_factor(d2,eps)
    modulus_ok = q*q >= 16*s2_squared*(d2+1)**2
    noise = None
    for exponent in range(1,257):
        trial = evaluate_noise(q=q,dimension=d2,width_squared=s2_squared,
                               alpha=Fraction(1,2**exponent),error_bits=error_bits,
                               seed_bits=seed_bits,encapsulations=encapsulations)
        if trial["conditional_noise_sufficient"]:
            noise = trial
            break
        if rational(trial["continuous_margin"], "margin") <= 0:
            break
    return dict(scope="numeric candidate only; source resource caps unchanged",
                parameters=dict(n=n,q=q,random_rows=d,m1=d,m2=m2,hadamard_scale=scale,
                                root_dimension=m,level1_dimension=d1,leaf_dimension=d2,
                                public_tv_bits=public_bits,epsilon_bits=eps,
                                root_gs_squared_upper=root_gs,s1_squared=s1_squared,s2_squared=s2_squared),
                public_error=dict(matrix_tv_quarter_budget=True,rank_quarter_budget=True,
                                  matrix_tv_upper=str(matrix_tv_upper(n,q,d,m2)),
                                  rank_abort_union_upper=str(Fraction(1,2**(public_bits+2))),
                                  rank_upper_rounding="n/q^(d-n+1) bounded upward by quarter quota",
                                  uniform_abort_upper=str(Fraction(n*d,2**192)),
                                  uniform_abort_quarter_budget=n*d*2**(public_bits+2)<=2**192,
                                  target=str(Fraction(1,2**public_bits))),
                selected_q_relation_sufficient=modulus_ok,conditional_noise=noise,
                caps=dict(ap09_root_fits=m<=192,ap09_parts_fit=max(d,m2)<=192,
                          gpv_levels_fit=d2<=_constant("gpv","MAX_DIMENSION"),
                          appended_leaf_unit_width_fits=s2_squared<=10**12,
                          fixed_seed_capacity_fits=seed_bits<=_constant("cache","MAX_CAPACITY")),
                actual_genbasis_or_sampling_executed=False,
                actual_scalar_tape_or_width_profiles=None,
                sampler_tv_and_abort=None,parameters_are_formal=False,
                backend_admitted=False,security_claim="none")


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",required=True)
    parser.add_argument("--n",type=int,default=1)
    parser.add_argument("--q",type=int,default=274877844481)
    args=parser.parse_args(argv)
    try:
        report=dict(current_domain=current_dimension_obstruction(),
                    hypothetical_candidate=plan_numeric_candidate(n=args.n,q=args.q),
                    security_claim="none",backend_admitted=False,parameters_are_formal=False)
    except ValueError as exc:
        parser.error(str(exc))
    Path(args.output).write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    # Deliberately nonzero: generating evidence does not admit a current HIBE.
    return 2


if __name__=="__main__":
    raise SystemExit(main())
