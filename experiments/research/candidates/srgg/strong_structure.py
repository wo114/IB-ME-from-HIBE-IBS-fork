"""Exact challenge-quotient facts for SRGG native-strong reduction research.

This is finite algebra and an ideal random-oracle counting model. It is not a
Fiat--Shamir security proof, a QROM bound, or a large-parameter attack run.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path


def _degree(n):
    if type(n) is not int or not 2<=n<=4096 or n&(n-1):
        raise ValueError("bounded power-of-two degree required")
    return n


def _vector(values):
    if not isinstance(values,(tuple,list)):
        raise ValueError("explicit coefficient sequence required")
    _degree(len(values))
    if any(type(x) is not int or abs(x).bit_length()>256 for x in values):
        raise ValueError("bounded exact integer coefficient required")
    return tuple(values)


def challenge(values):
    values=_vector(values)
    if any(x not in (0,1) for x in values):
        raise ValueError("binary challenge required")
    return values


def zeta_apply(values,*,adjoint=False):
    """Multiply by 1 +/- X^(n/2) in Z[X]/(X^n+1)."""
    values=_vector(values)
    if type(adjoint) is not bool:
        raise ValueError("explicit adjoint flag required")
    h=len(values)//2
    a,b=values[:h],values[h:]
    if adjoint:
        return tuple(x+y for x,y in zip(a,b))+tuple(y-x for x,y in zip(a,b))
    return tuple(x-y for x,y in zip(a,b))+tuple(x+y for x,y in zip(a,b))


def effective_challenge(values):
    values=challenge(values)
    h=len(values)//2
    return tuple((x+y)%2 for x,y in zip(values[:h],values[h:]))


def same_challenge_coset(first,second):
    first,second=challenge(first),challenge(second)
    if len(first)!=len(second):
        raise ValueError("challenge degree mismatch")
    return effective_challenge(first)==effective_challenge(second)


def quotient_certificate(degree):
    n=_degree(degree);h=n//2
    return {"degree":n,"binary_challenge_cardinality":str(2**n),
        "effective_cosets":str(2**h),"binary_challenges_per_coset":str(2**h),
        "effective_challenge_bits":h,
        "independent_uniform_same_coset_probability_exact":str(Fraction(1,2**h)),
        "uniform_distinct_challenge_same_coset_probability_exact":str(Fraction(2**h-1,2**n-1)),
        "zero_response_zero_commitment_one_fresh_message_success_exact":str(Fraction(1,2**h)),
        "conditions":["n is a power of two at least two","binary H2 uniform on all 2^n challenges",
            "verification uses Q*zeta_adjoint*c modulo 2Q","zero response is in the accepted norm/object domain",
            "fresh messages yield independent ideal classical random-oracle outputs"],
        "different_challenge_alone_guarantees_nonzero_response_difference":False,
        "same_effective_challenge_counterexample":{
            "c_zero":True,"c_prime_nonzero_positions":[0,h],
            "zeta_adjoint_c_prime_nonzero_coefficients":{"0":2},
            "same_zero_response_recovers_same_zero_commitment":True},
        "large_parameter_attack_executed":False,"qrom_search_bound_established":False,
        "security_claim":"none","backend_admitted":False,"parameters_are_formal":False}


def build_report():
    return {"schema":"IBME/SRGG-STRONG-CHALLENGE-STRUCTURE/1",
        "source_sha256":{"experiments/research/candidates/srgg/strong_structure.py":
            hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
        "rows":[quotient_certificate(n) for n in (2,4,8,16,32,512)],
        "scope":"exact ring/quotient counts; no cryptographic security reduction",
        "security_claim":"none","backend_admitted":False,"parameters_are_formal":False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(build_report(),indent=2)+"\n",encoding="utf-8",newline="\n")


if __name__=="__main__":main()
