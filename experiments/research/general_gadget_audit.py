"""Reproduce finite-error general-q gadget research; no keys or backend changes."""

from __future__ import annotations

import argparse
from itertools import product
import json
from pathlib import Path
import platform
import sys

from sage.all import QQ, RealIntervalField
from sage.version import version as sage_version

from ibme.core.randomness import DeterministicRandom
from .gaussian_reference import build_gaussian_table_squared, interval_record
from .general_gadget_reference import (GeneralModulusGadgetSampler,
    finite_general_gadget_distribution, gadget_basis)


def finite_box_comparison(sampler, syndrome):
    """Independent spherical weights on a box containing the full finite PMF.

    This compares ideal uniform-ticket nearest-plane outputs with a target
    conditioned on that box. It is not an infinite-coset TV measurement.
    """
    law = finite_general_gadget_distribution(sampler,syndrome)
    bounds = [(min(v[i] for v in law),max(v[i] for v in law)) for i in range(sampler.k)]
    box_states = 1
    for low,high in bounds:
        box_states *= high-low+1
    if box_states > 100000:
        raise ValueError("Independent comparison box exceeds resource limit")
    field = RealIntervalField(192)
    weights = {}
    for v in product(*(range(low,high+1) for low,high in bounds)):
        if sum((1 << j)*x for j,x in enumerate(v)) % sampler.q == syndrome:
            weights[v] = (-field.pi()*field(QQ(sum(x*x for x in v))/sampler.s_squared)).exp()
    total = sum(weights.values(),field(0))
    tv = sum((abs(field(law.get(v,QQ(0)))-weight/total)
              for v,weight in weights.items()),field(0))/2
    return {"q":sampler.q,"syndrome":syndrome,"s_squared":str(sampler.s_squared),
            "box_bounds":bounds,"box_states":box_states,"coset_states":len(weights),
            "cdf_states":len(law),"cdf_total_probability":str(sum(law.values(),QQ(0))),
            "all_cdf_vectors_satisfy_equation":all(sum((1 << j)*x for j,x in enumerate(v))
                % sampler.q == syndrome for v in law),
            "finite_box_tv_interval":interval_record(tv),
            "finite_box_tv_display_approx":float(tv.center()),
            "zero_vector_cdf_probability":str(law.get((0,)*sampler.k,QQ(0))),
            "zero_vector_box_target_probability":interval_record(1/total) if syndrome==0 else None,
            "scope":"ideal-ticket finite CDF law versus spherical target conditioned on box; abort excluded from PMF"}


def audit_report(*, samples=8192):
    if isinstance(samples,bool) or not isinstance(samples,int) or samples < 1:
        raise ValueError("samples must be a positive integer")
    survey = [gadget_basis(q).record() for q in (3,5,6,7,8,11,13,17,31,257)]
    irrational_width = build_gaussian_table_squared("144/5",center="2/5")
    narrow = []
    for q in (3,5):
        sampler = GeneralModulusGadgetSampler(q,"9/4",tail_bits=16,mass_bits=96,precision_bits=160)
        narrow.append({"geometry":sampler.geometry.record(),"certificate":sampler.certificate(),
                       "comparisons":[finite_box_comparison(sampler,u) for u in range(q)]})
    sampler = GeneralModulusGadgetSampler(17,144)
    targets = (0,16)
    rng = DeterministicRandom(b"ibme-round5:prime-gadget")
    failures,first,total_norm_squared = 0,[],0
    for i in range(samples):
        values = sampler.sample(targets,rng=rng)
        if i < 4:
            first.append(list(values))
        actual = tuple(sum((1 << j)*values[b*sampler.k+j] for j in range(sampler.k))
                       % sampler.q for b in range(2))
        failures += actual != targets
        total_norm_squared += sum(x*x for x in values)
    return {"schema_version":1,"security_claim":"none",
            "source":{"paper":"MP12 ePrint 2011/501","locations":["section 4.2, Lemma 4.3, PDF 20-21"],
                      "method":"generic randomized nearest-plane permitted by MP12; explicit finite-center certification is this repository's reference adaptation"},
            "environment":{"python":sys.version.split()[0],"sage":sage_version,"platform":platform.platform()},
            "parameter_source":"hand-selected mathematical research examples, no lattice-security estimate",
            "convention":{"weight":"exp(-pi*||x||^2/s_squared)",
                "coordinate_width_squared":"s_squared/||b_i*||^2", "centers":"exact rational; integer shifts separated before table lookup"},
            "rom_use":"none for sampling; labelled deterministic test entropy is not a random-oracle proof",
            "identity_length_bytes":None,"message_length_bytes":None,
            "identity_message_note":"not applicable: no cryptographic identities, messages, keys or signatures",
            "basis_survey":survey,"irrational_coordinate_width_example":irrational_width.certificate(),
            "narrow_gadgets":narrow,
            "wide_prime_gadget":{"geometry":sampler.geometry.record(),"certificate":sampler.certificate(2),
                "samples":samples,"syndrome":list(targets),"modular_equation_failures":failures,
                "observed_mean_norm_squared":total_norm_squared/samples,"first_four_vectors":first,
                "seed_ascii":"ibme-round5:prime-gadget","random_source":"DeterministicRandom; test only"},
            "limitations":["reference uses all-center table precomputation; resource cap rejects large-q parameter sets without a partial certificate",
                "q=257 is a basis-only survey here, not an admitted sampler or formal parameter set",
                "variable-time sampling; bounded entropy rejection abort is included as extra output symbol",
                "no full TrapGen, DelTrap, perturbation, SamplePre or cryptographic backend",
                "finite-box diagnostics and tests do not prove an IBS/HIBE/IBME security theorem"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples",type=int,default=8192)
    parser.add_argument("--output",type=Path)
    args = parser.parse_args()
    serialized = json.dumps(audit_report(samples=args.samples),ensure_ascii=False,indent=2)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(serialized,encoding="utf-8",newline="\n")
    else:
        print(serialized,end="")


if __name__ == "__main__":
    main()
