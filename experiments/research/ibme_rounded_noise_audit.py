"""Six public rounded-noise profiles; statistics are diagnostic, not proofs."""

import argparse
from collections import Counter
from fractions import Fraction
import json
from pathlib import Path
import time

import mpmath as mp

from ibme.core.randomness import DeterministicRandom
from ibme.core.errors import InvalidParameterError
from .ibme_joint_parameters import plan_numeric_candidate
from .ibme_noise_budget import RoundedNoiseParams,attach_finite_noise_budget
from .ibme_rounded_noise import build_rounded_noise


class CountingRandom:
    def __init__(self,seed):
        self.source=DeterministicRandom(seed)
        self.bytes_used=0

    def read(self,n):
        value=self.source.read(n)
        self.bytes_used+=len(value)
        return value


def independent_infinite_pmf_tv(table):
    """Numerical cross-check with mpmath, separate from Arb certificates."""
    with mp.workdps(120):
        w=mp.mpf(table.params.scaled_width.numerator)/table.params.scaled_width.denominator
        cdf=lambda x:(1+mp.erf(mp.sqrt(mp.pi)*x/w))/2
        delta=mp.mpf(0)
        for z,mass in zip(range(-table.radius,table.radius+1),table.masses):
            actual=mp.mpf(mass)/table.total
            ideal=cdf(mp.mpf(z)+mp.mpf('0.5'))-cdf(mp.mpf(z)-mp.mpf('0.5'))
            delta+=abs(actual-ideal)
        outside=mp.erfc(mp.sqrt(mp.pi)*(table.radius+mp.mpf('0.5'))/w)
        observed=(delta+outside)/2
        upper=Fraction(table.certificate()["tv_upper_including_abort"])
        return dict(numeric_tv=mp.nstr(observed,30),
                    numeric_tv_below_certificate=observed<=mp.mpf(upper.numerator)/upper.denominator,
                    numerical_check_is_not_certificate=True,mpmath_decimal_precision=120)


def audit_profile(label,params,*,count=16384):
    if type(count) is not int or not 1<=count<=65536:
        raise InvalidParameterError("audit count must be an integer in 1..65536")
    start=time.perf_counter()
    table=build_rounded_noise(params)
    construction=time.perf_counter()-start
    source=CountingRandom(("rounded-noise-audit:"+label).encode())
    start=time.perf_counter()
    values=table.sample_vector(count,rng=source)
    elapsed=time.perf_counter()-start
    histogram=Counter(values)
    mean=Fraction(sum(values),count)
    second=Fraction(sum(v*v for v in values),count)
    target_mean=sum((Fraction(z*mass,table.total) for z,mass in
                     zip(range(-table.radius,table.radius+1),table.masses)),Fraction(0))
    target_second=sum((Fraction(z*z*mass,table.total) for z,mass in
                       zip(range(-table.radius,table.radius+1),table.masses)),Fraction(0))
    record=dict(label=label,certificate=table.certificate(),samples=count,
                actual_entropy_bytes=source.bytes_used,construction_seconds=construction,
                sample_seconds=elapsed,empirical_mean_display=float(mean),
                empirical_variance_display=float(second-mean*mean),
                finite_table_mean=str(target_mean),finite_table_variance=str(target_second-target_mean*target_mean),
                zero_count=histogram[0],zero_probability_display=float(Fraction(table.masses[table.radius],table.total)),
                histogram={str(k):v for k,v in sorted(histogram.items())},
                independent_pmf_check=independent_infinite_pmf_tv(table),
                fixed_seed_tests_only=True,security_claim="none",backend_admitted=False)
    if params.q==274877844481:
        record["conditional_composed_noise_budget"]=attach_finite_noise_budget(
            plan_numeric_candidate(n=1,q=params.q)["conditional_noise"],record["certificate"])
    return record


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",required=True)
    args=parser.parse_args(argv)
    profiles=[
        ("unit-width",RoundedNoiseParams(q=17,alpha=Fraction(1,17))),
        ("width-four",RoundedNoiseParams(q=257,alpha=Fraction(1,64))),
        ("candidate-default",RoundedNoiseParams(q=274877844481,alpha=Fraction(1,2**33))),
        ("candidate-high-precision",RoundedNoiseParams(q=274877844481,alpha=Fraction(1,2**33),
                                                      tail_bits=160,mass_bits=192,precision_bits=320)),
        ("narrow-noise-control",RoundedNoiseParams(q=257,alpha=Fraction(1,2**16))),
        ("small-modulus-fold",RoundedNoiseParams(q=7,alpha=Fraction(3,7))),
    ]
    rejected=[]
    for label,inputs in (
        ("scaled-width-outside",dict(q=274877844481,alpha=Fraction(1,2**20))),
        ("support-budget",dict(q=65537,alpha=Fraction(1,32))),
        ("precision-budget",dict(q=17,alpha=Fraction(1,17),mass_bits=512,precision_bits=256)),
    ):
        try:
            build_rounded_noise(RoundedNoiseParams(**inputs))
        except InvalidParameterError as exc:
            rejected.append(dict(label=label,expected_rejection=True,error=str(exc),
                                 sampling_attempted=False,uniform_or_zero_fallback=False))
        else:
            raise AssertionError("negative input control unexpectedly accepted")
    records=[]
    for label,params in profiles:
        record=audit_profile(label,params)
        records.append(record)
        Path(args.output).write_text(json.dumps(dict(profiles=records,rejected_input_controls=rejected),
                                               ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        print(label,record["samples"],"samples; numerical PMF check",record["independent_pmf_check"]["numeric_tv_below_certificate"],flush=True)
    return 0 if all(r["independent_pmf_check"]["numeric_tv_below_certificate"] for r in records) else 2


if __name__=="__main__":
    raise SystemExit(main())
