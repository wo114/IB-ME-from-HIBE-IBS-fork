"""Reproduce connected generation/delegation, admission and failure budgets."""

from __future__ import annotations

import argparse
from hashlib import sha256
from itertools import product
import json
from pathlib import Path
import platform
import sys

from sage.all import QQ, ZZ, RealIntervalField, matrix, vector
from sage.version import version as sage_version

from ibme.core.randomness import DeterministicRandom
from .gaussian_reference import SamplingAbort, build_gaussian_table_squared, draw_uniform_integer, interval_record
from .mp12_sampled_reference import outward_upper
from .mp12_trapdoor_chain import (GaussianGenTrap, RankOneParameters, delegate_from_tape,
    make_master_sampler, make_user_sampler, rank_one_profile, sampling_class_certificate)


def generation_law(generator, quality_squared):
    """Exact ideal-ticket q=2 scalar GenTrap law BEFORE any quality filter."""
    if (generator.q, generator.n, generator.m_bar, generator.w) != (2, 1, 1, 1):
        raise ValueError("Exact public-law audit supports the scalar q=2 instance")
    law = {(a, b): QQ(0) for a, b in product(range(2), repeat=2)}
    bad = QQ(0)
    for value in generator.table.support:
        p = generator.table.probability(value)
        bad += p if value*value > quality_squared else 0
        for a in range(2):
            law[(a, (1-a*value) % 2)] += p/2
    distance = sum((abs(p-QQ(1)/4) for p in law.values()), QQ(0))/2
    abort = generator.table.abort_upper
    return {"public_pmf": [{"A": [list(a)], "probability": str(p)} for a, p in law.items()],
        "exact_total_probability": str(sum(law.values(), QQ(0))),
        "finite_CDF_public_to_uniform_TV": str(distance),
        "finite_CDF_public_to_uniform_TV_approx": float(distance),
        "generation_abort_upper": str(abort),
        "actual_public_or_abort_to_uniform_TV_upper": str(min(QQ(1), distance+abort)),
        "master_quality_squared": quality_squared,
        "master_quality_rejection_upper": str(bad),
        "generator_gaussian_tv_upper": str(generator.table.tv_upper),
        "CDF_sha256": generator.table.certificate()["cdf_sha256"],
        "public_generation_tape_bytes": generator.random_tape_bytes,
        "quality_filter_used_for_public_law": False,
        "scope": "unfiltered finite Gaussian GenTrap ideal-ticket law; abort added to the unconditional TV bound",
        "satisfies_negligible_regularity": False, "security_claim": "none"}


def delegated_quality_budget(params):
    """Uniform infinite-coset norm tail over ALL nonzero binary parent rows/u."""
    stage = sampling_class_certificate(params, "master")
    width_squared = QQ(stage["spherical_width_squared"])
    field = RealIntervalField(256)
    even = build_gaussian_table_squared(width_squared, step=2, residue=0,
        tail_bits=128, mass_bits=192, precision_bits=256).normalizer
    odd = build_gaussian_table_squared(width_squared, step=2, residue=1,
        tail_bits=128, mass_bits=192, precision_bits=256).normalizer
    total = even+odd
    radius = int(ZZ(params.user_quality_squared).isqrt())
    points = [(x, y) for x, y in product(range(-radius, radius+1), repeat=2)
        if x*x+y*y <= params.user_quality_squared]
    weights = {(x, y): (-field.pi()*field(QQ(x*x+y*y)/width_squared)).exp()
        for x, y in points}
    cases = []
    for a in ((0, 1), (1, 0), (1, 1)):
        for u in (0, 1):
            if a == (1, 1):
                normalizer = even**2+odd**2 if u == 0 else 2*even*odd
            else:
                normalizer = total*(even if u == 0 else odd)
            inside = sum((weight for (x, y), weight in weights.items()
                if (a[0]*x+a[1]*y) % 2 == u), field(0))
            tail = 1-inside/field(normalizer)
            cases.append({"A": [list(a)], "syndrome": [u],
                "infinite_target_norm_rejection_interval": interval_record(tail),
                "tail_upper": str(outward_upper(tail))})
    worst = max(QQ(c["tail_upper"]) for c in cases)
    error = QQ(stage["uniform_SampleD_tv_upper"])
    return {"master_output_width_squared": str(width_squared),
        "user_quality_squared": params.user_quality_squared,
        "qualified_integer_vectors_enumerated": len(points), "cases": cases,
        "worst_ideal_norm_rejection_upper": str(worst),
        "finite_delegation_error_upper": str(error),
        "user_quality_rejection_upper": str(outward_upper(min(QQ(1), worst+error))),
        "bound_uniform_in_parent_public_master_trapdoor_and_extension": True,
        "no_rejection_resampling": True,
        "resource_rejection_given_user_quality_upper": "0", "security_claim": "none"}


def audit_report(*, attempts=128, user_prefix=4, samples_per_user=64):
    if any(isinstance(x, bool) or not isinstance(x, int) for x in (attempts, user_prefix, samples_per_user)):
        raise ValueError("Counts must be integers")
    if not 1 <= attempts <= 4096 or not 0 <= user_prefix <= min(attempts, 8) or not 1 <= samples_per_user <= 4096:
        raise ValueError("Audit counts outside resource limits")
    params = RankOneParameters()
    generator = GaussianGenTrap(2, 1, 1, params.generator_width_squared, **params.table_options)
    classes = {stage: sampling_class_certificate(params, stage) for stage in ("master", "user")}
    counts = {name: 0 for name in ("generation_abort", "master_quality_rejected", "delegation_abort",
        "user_quality_rejected", "qualified_users", "unexpected_resource_failure",
        "user_sampler_materialized", "user_sample_attempts", "user_sample_abort", "user_equation_errors")}
    rows, parent_cache, local_certificates = [], {}, []
    for i in range(attempts):
        prefix = f"ibme-round9:attempt:{i}".encode("ascii")
        row = {"attempt": i, "seed_prefix_ascii": prefix.decode("ascii"),
            "materialization_requested_by_public_prefix": i < user_prefix}
        try:
            setup_tape = DeterministicRandom(prefix+b":setup").read(generator.random_tape_bytes)
            generated = generator.generate_from_tape(setup_tape)
        except SamplingAbort:
            counts["generation_abort"] += 1
            row["status"] = "generation_abort"
            rows.append(row)
            continue
        row.update({"A": [[int(x) for x in generated.public.row(0)]],
            "R0": [[int(x) for x in generated.trapdoor.row(0)]],
            "setup_tape_sha256": sha256(setup_tape).hexdigest(),
            "master_norm_squared": generated.norm_squared})
        cache_key = tuple(generated.a_bar.list()), tuple(generated.trapdoor.list())
        if cache_key not in parent_cache:
            parent_cache[cache_key] = make_master_sampler(generated, params)
        master = parent_cache[cache_key]
        if master.status != "admitted":
            counts["master_quality_rejected"] += 1
            row["status"] = master.status
            rows.append(row)
            continue
        parent = master.sampler
        extension_value = draw_uniform_integer(DeterministicRandom(prefix+b":extension"), 2)
        extension = [[extension_value]]
        delegation_tape = DeterministicRandom(prefix+b":delegation").read(parent.w*parent.random_tape_bytes)
        try:
            delegated = delegate_from_tape(parent, extension, delegation_tape)
        except SamplingAbort:
            counts["delegation_abort"] += 1
            row["status"] = "delegation_abort"
            rows.append(row)
            continue
        profile = rank_one_profile(delegated.trapdoor, params, "user")
        row.update({"H1_extension": extension, "R_delegated": [[int(x) for x in r] for r in delegated.trapdoor.rows()],
            "Foo_Li_R_id": [[int(x) for x in r] for r in delegated.foo_li_R_id.rows()],
            "delegation_tape_sha256": sha256(delegation_tape).hexdigest(),
            "user_profile": profile})
        if profile["status"] != "qualified":
            counts["user_quality_rejected"] += 1
            row["status"] = "user_quality_rejected"
            rows.append(row)
            continue
        counts["qualified_users"] += 1
        row["status"] = "qualified"
        if i < user_prefix:
            # Materialize a predetermined PUBLIC prefix, not a search for cheap
            # keys. Quality rejections in that prefix remain in the dataset.
            user = make_user_sampler(delegated, params)
            if user.status != "admitted":
                counts["unexpected_resource_failure"] += 1
                raise AssertionError("A qualified key failed the public class admission")
            sampler = user.sampler
            counts["user_sampler_materialized"] += 1
            certificate = sampler.certificate()
            local_certificates.append({"attempt": i, "certificate": certificate})
            first, norm_tails = [], 0
            for syndrome in (0, 1):
                rng = DeterministicRandom(prefix+f":user:{syndrome}".encode("ascii"))
                for j in range(samples_per_user):
                    counts["user_sample_attempts"] += 1
                    try:
                        x = sampler.sample((syndrome,), rng=rng)
                    except SamplingAbort:
                        counts["user_sample_abort"] += 1
                        continue
                    norm_tails += sum(v*v for v in x) >= 3*3612
                    if j < 2:
                        first.append({"syndrome": syndrome, "output": list(x)})
                    counts["user_equation_errors"] += tuple(int(v) % 2 for v in
                        sampler.public_matrix()*vector(ZZ, x)) != (syndrome,)
            replay_delegated = delegate_from_tape(parent, extension, delegation_tape)
            user_tape = DeterministicRandom(prefix+b":user-tape").read(sampler.random_tape_bytes)
            output = sampler.sample_from_tape((1,), user_tape)
            row.update({"first_user_outputs": first, "user_norm_tail_count": norm_tails,
                "delegation_replay_equal": replay_delegated.trapdoor == delegated.trapdoor,
                "user_tape_sha256": sha256(user_tape).hexdigest(),
                "user_replay_equal": sampler.sample_from_tape((1,), user_tape) == output,
                "user_replay_output": list(output)})
        rows.append(row)
    budget = delegated_quality_budget(params)
    beta_squared = 4*3612*3*(1+params.user_quality_squared)
    source = Path("papers/2011_lattice_trapdoors_micciancio.pdf")
    return {"schema_version": 1, "research_round": 9, "checked_on": "2026-10-05", "security_claim": "none",
        "environment": {"python": sys.version.split()[0], "sage": sage_version, "platform": platform.platform()},
        "sources": {"MP12": {"url": "https://eprint.iacr.org/2011/501", "pdf_sha256": sha256(source.read_bytes()).hexdigest(),
            "locations": ["Algorithm 1, section 5.2, PDF 23-25", "Algorithms 3/4, PDF 27-29"]},
            "rounding": "https://doc.sagemath.org/html/en/reference/spkg/mpfi.html"},
        "parameter_source": "hand-selected binary rank-one mathematical reference class, not cryptographic parameters",
        "rom_use": "none in experiments; the planned Foo-Li proof is classical ROM",
        "identity_length_bytes": None, "message_length_bytes": None,
        "production_keys_or_IBS_signatures_generated": 0,
        "generation_law": generation_law(generator, params.master_quality_squared),
        "sampling_classes": classes, "delegated_quality_budget": budget,
        "experiment": {"attempts": attempts, "user_materialization_public_prefix": user_prefix,
            "samples_per_user_per_syndrome": samples_per_user, "counts": counts, "all_attempts": rows,
            "parent_sampler_cache_reuses_geometry_not_random_samples": True,
            "failed_attempts_discarded_or_retried": False},
        "materialized_user_certificates": local_certificates,
        "SIS_gate": {"beta_reduction_squared": beta_squared, "q_squared": 4, "passed": beta_squared < 4},
        "limitations": ["q=2,n=w=m_bar=1 uniform admission proof; multi-column delegation separately tested at q=3",
            "public GenTrap distribution in this tiny instance is far from uniform",
            "full sampler geometry materialized only for the fixed public prefix; every attempt and quality rejection recorded",
            "resource coverage relies on correctly-rounded MPFR/MPFI operations as stated in the class certificate",
            "no full key lifecycle, canonical RO encoding, formal IBS/HIBE backend or practical security parameters",
            "old public forgery and ciphertext tamper remain pending backend/wrapper repairs"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attempts", type=int, default=128)
    parser.add_argument("--user-prefix", type=int, default=4)
    parser.add_argument("--samples-per-user", type=int, default=64)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    serialized = json.dumps(audit_report(attempts=args.attempts, user_prefix=args.user_prefix,
        samples_per_user=args.samples_per_user), ensure_ascii=False, indent=2)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8", newline="\n")
    else:
        print(serialized, end="")


if __name__ == "__main__":
    main()
