"""Interval substitution of the main agent's pending theorem; proves no theorem."""
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.repo / "src"))
    from ibme.ibs.luo_module import LuoModuleParams, HASH_BYTES
    from run_current_screens import profiles
    from sage.all import RealIntervalField, ZZ
    R = RealIntervalField(192)
    def interval(x):
        return dict(lower=str(x.lower()), upper=str(x.upper()))
    def log2(x):
        return interval(x.log()/R(2).log())
    output = []
    for name, p in profiles(LuoModuleParams()):
        bc = 2*p.gamma2-4*p.beta2-1
        h = (p.q-1)//(2*p.gamma3)
        good = h*(2*p.gamma3-4*p.beta2-1)
        epsilon = R(1)/256
        f = (R(good)/p.q)**(p.degree*p.k)
        zero = R(p.degree)/ZZ(bc)**p.l
        pair = zero + R(p.degree)/ZZ(bc)**(p.l-1)
        bad_a = (pair+2*zero*f*f)/(epsilon*epsilon*f*f)
        sign_p = (R(bc)/(2*p.gamma2+1))**(p.degree*p.l)*(1-epsilon)*f
        extract_p = (R(2*p.gamma1-4*p.kappa*p.eta+1)/(2*p.gamma1+1))**(p.degree*(p.k+p.l))
        sign_abort = (1-sign_p)**p.max_sign_attempts
        extract_abort = (1-extract_p)**p.max_extract_attempts
        # Illustrative lifetime, NOT a configured enforcement mechanism.
        total = bad_a + 64*extract_abort + 2**20*sign_abort
        samplers = []
        for label,bound in [("public-A",p.q),("secret",2*p.eta+1),
                            ("extract-mask",2*p.gamma1+1),("sign-mask",2*p.gamma2+1),
                            ("worst-challenge-position",p.degree-p.kappa+1)]:
            width = max(1,((bound-1).bit_length()+7)//8)
            ceiling=2**(8*width)
            rejected=ceiling%bound
            tail=(R(rejected)/ceiling)**p.max_uniform_attempts
            samplers.append(dict(label=label,bound=bound,draw_bytes=width,
                rejection_numerator=rejected,rejection_denominator=ceiling,
                abort_log2=None if rejected==0 else log2(tail)))
        output.append(dict(name=name,parameters=asdict(p),constructor_valid=True,
            theorem_status="PENDING_MAIN_PROOF",epsilon="1/256",interval_precision_bits=192,
            Bc=bc,good_residue_count=good,h=h,F=interval(f),delta_A_upper_log2=log2(bad_a),
            sign_per_trial_lower=interval(sign_p),sign_abort_cond_goodA_log2=log2(sign_abort),
            extract_per_trial_lower=interval(extract_p),extract_abort_log2=log2(extract_abort),
            illustrative_lifetime=dict(setups=1,distinct_extract_calls=64,sign_calls=2**20,
                unclipped_union_log2=log2(total),bound_nontrivial=bool(total.upper()<1),
                at_most_2pow_minus128=bool(total.upper() <= (R(2)**-128).lower()),
                excludes="uniform-draw/RO-programming/other primitive/state failures; not enforced counters"),
            sampler_tail_per_call=samplers,
            challenge_xof_worst_consumption_bytes=p.kappa*(p.max_uniform_attempts+1),
            hash_bytes=HASH_BYTES,
            xof_budget_sufficient= p.kappa*(p.max_uniform_attempts+1)<=HASH_BYTES,
            security_claim="none",backend_admitted=False))
    print(json.dumps(dict(schema="IBME/LUO2024/PENDING-ROUTE-NUMERICS/1",profiles=output)))


if __name__ == "__main__":
    main()
