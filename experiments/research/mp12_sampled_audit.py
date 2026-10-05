"""Reproduce round-eight full MP12 sampling certificates and diagnostics."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import platform
import sys

from sage.all import QQ, RealIntervalField, matrix, vector, ZZ
from sage.version import version as sage_version

from ibme.core.randomness import DeterministicRandom
from .gaussian_reference import build_gaussian_table_squared, interval_bounds, interval_record
from .mp12_sampled_reference import MP12SampleD, SamplingAbort, finite_sampled_distribution


def research_fixtures():
    """Hand-picked valid trapdoors; neither is a TrapGen or a cryptographic key."""
    return {
        "master_delegation_oracle": MP12SampleD(3, [[2]], [[1, -1]],
            r_squared=9, sigma_squared=24),
        "user_signing_oracle": MP12SampleD(3, [[2, 2, 1]], [[-1, 1], [-1, 0], [0, -1]],
            r_squared=16, sigma_squared=40),
    }


def factorized_infinite_target_comparison():
    """Exact finite Algorithm 3 PMF versus an independently factored infinite target.

    A=[1,0], q=2, syndrome=0 factors the target into 2Z x Z. Scalar interval
    normalizers include the infinite tails. The comparison includes target mass
    outside the full CDF support; it is not a target conditioned on a finite box.
    Rejection aborts are excluded from this ideal-ticket PMF and budgeted in TV.
    """
    sampler = MP12SampleD(2, [[1]], [[1]], r_squared=1, sigma_squared=14,
        tail_bits=12, mass_bits=64, precision_bits=160, max_trials=64)
    law = finite_sampled_distribution(sampler, 0)
    assert sampler.public_matrix() == matrix(ZZ, [[1, 0]])
    normalizers = [build_gaussian_table_squared(14, step=h,
        tail_bits=128, mass_bits=192, precision_bits=256).normalizer for h in (2, 1)]
    field = RealIntervalField(256)
    normalizer = field(normalizers[0])*field(normalizers[1])
    target_mass, differences = field(0), field(0)
    for x, probability in law.items():
        assert x[0] % 2 == 0
        target = (-field.pi()*field(QQ(sum(v*v for v in x))/14)).exp()/normalizer
        target_mass += target
        differences += abs(field(probability)-target)
    outside = 1-target_mass
    lower, upper = interval_bounds(outside)
    if upper < 0:
        raise AssertionError("Independent normalizer interval is inconsistent")
    outside = field(max(QQ(0), lower), max(QQ(0), upper))
    distance = (differences+outside)/2
    diagonal_mass = build_gaussian_table_squared(7, step=2,
        tail_bits=128, mass_bits=192, precision_bits=256).normalizer
    target_diagonal_probability = field(diagonal_mass)/normalizer
    certificate = sampler.certificate()
    return {"parameters": {"q": 2, "A": [[1, 0]], "syndrome": [0],
            "r_squared": "1", "Sigma_scalar": "14", "Sigma_G_scalar": "5",
            "tail_bits": 12, "mass_bits": 64, "precision_bits": 160, "max_trials": 64},
        "cdf_states": len(law), "cdf_total_probability": str(sum(law.values(), QQ(0))),
        "all_vectors_satisfy_equation": all(x[0] % 2 == 0 for x in law),
        "infinite_target_tv_interval": interval_record(distance),
        "infinite_target_tv_display_approx": float(distance.center()),
        "target_mass_outside_finite_cdf_support_interval": interval_record(outside),
        "zero_vector_cdf_probability": str(law.get((0, 0), QQ(0))),
        "zero_vector_infinite_target_probability": interval_record(1/normalizer),
        "certificate_tv_upper_including_abort": certificate["tv_upper_including_abort"],
        "certificate_dominates_independent_distance": interval_bounds(distance)[1] <=
            QQ(certificate["tv_upper_including_abort"]),
        "without_perturbation_negative_control": {
            "event": "x[0] equals x[1]",
            "all_unperturbed_gadget_outputs_satisfy_equation": True,
            "unperturbed_event_probability": "1",
            "infinite_target_event_probability": interval_record(target_diagonal_probability),
            "tv_lower_witness": str(1-interval_bounds(target_diagonal_probability)[1])},
        "scope": "ideal-ticket complete SampleD law versus infinite spherical coset Gaussian; abort excluded from PMF and included in certificate",
        "security_claim": "none"}


def fixture_diagnostics(name, sampler, samples):
    seed = f"ibme-round8:{name}".encode("ascii")
    rng = DeterministicRandom(seed)
    means = [0]*sampler.dimension
    second = [[0]*sampler.dimension for _ in range(sampler.dimension)]
    p_second = [[0]*sampler.dimension for _ in range(sampler.dimension)]
    first, equation_failures, aborts, norm_tail = [], 0, 0, 0
    target_width_squared = sampler.r_squared*sampler.sigma_squared
    for i in range(samples):
        try:
            trace = sampler.sample_trace((0,), rng=rng)
        except SamplingAbort:
            aborts += 1
            continue
        x, p = trace.output, trace.perturbation
        if len(first) < 4:
            first.append(list(x))
        equation_failures += any(int(v) % sampler.q != 0 for v in
            sampler.public_matrix()*vector(ZZ, x))
        norm_tail += sum(v*v for v in x) >= target_width_squared*sampler.dimension
        for j in range(sampler.dimension):
            means[j] += x[j]
            for k in range(sampler.dimension):
                second[j][k] += x[j]*x[k]
                p_second[j][k] += p[j]*p[k]
    valid = samples-aborts
    if valid == 0:
        raise AssertionError("All diagnostic draws aborted")
    observed_means = [x/valid for x in means]
    covariance = [[second[j][k]/valid-observed_means[j]*observed_means[k]
        for k in range(sampler.dimension)] for j in range(sampler.dimension)]
    corners_rng = DeterministicRandom(seed+b":all-tags-and-u")
    corner_draws, corner_errors = 0, 0
    for tag in range(1, sampler.q):
        a = sampler.public_matrix([[tag]])
        for u in range(sampler.q):
            for _ in range(16):
                x = sampler.sample((u,), tag=[[tag]], rng=corners_rng)
                corner_draws += 1
                corner_errors += tuple(int(v) % sampler.q for v in a*vector(ZZ, x)) != (u,)
    tape_rng = DeterministicRandom(seed+b":finite-tape")
    tape = tape_rng.read(sampler.random_tape_bytes)
    recomputation = sampler.sample_from_tape((1,), tape)
    reproduced = sampler.sample_from_tape((1,), tape)
    f = RealIntervalField(128)
    return {"certificate": sampler.certificate(),
        "public_matrix_tag_identity": [[int(x) for x in row] for row in sampler.public_matrix().rows()],
        "sampling": {"attempts": samples, "completed": valid, "aborts": aborts,
            "syndrome": [0], "tag": [[1]], "seed_ascii": seed.decode("ascii"),
            "random_source": "DeterministicRandom; test only", "equation_failures": equation_failures,
            "first_four_vectors": first, "observed_means": observed_means,
            "observed_covariance": covariance,
            "observed_perturbation_second_moment": [[x/valid for x in row] for row in p_second],
            "continuous_spherical_variance_for_diagnostics_only": float(f(target_width_squared)/(2*f.pi())),
            "continuous_perturbation_covariance_for_diagnostics_only": [[float(f(x)/(2*f.pi()))
                for x in row] for row in sampler.perturbation.covariance.rows()],
            "norm_tail_count_at_width_times_sqrt_dimension": norm_tail,
            "diagnostics_are_not_the_distribution_proof": True},
        "all_tags_all_syndromes": {"draws": corner_draws, "equation_failures": corner_errors},
        "finite_tape": {"length_bytes": len(tape), "sha256": sha256(tape).hexdigest(),
            "output": list(recomputation), "same_tape_exactly_reproduces": recomputation == reproduced}}


def audit_report(*, samples=4096):
    if isinstance(samples, bool) or not isinstance(samples, int) or not 1 <= samples <= 100000:
        raise ValueError("samples must be an integer in [1,100000]")
    fixtures = research_fixtures()
    source = Path("papers/2011_lattice_trapdoors_micciancio.pdf")
    return {"schema_version": 1, "research_round": 8, "checked_on": "2026-10-05",
        "security_claim": "none", "environment": {"python": sys.version.split()[0],
            "sage": sage_version, "platform": platform.platform()},
        "source": {"paper": "Micciancio-Peikert, ePrint 2011/501",
            "url": "https://eprint.iacr.org/2011/501", "pdf_path": source.as_posix(),
            "pdf_sha256": sha256(source.read_bytes()).hexdigest(),
            "locations": ["Lemma 2.3, PDF 12", "Lemma 2.5, PDF 13",
                "Algorithm 3 and Theorem 5.5, PDF 27-29"],
            "adaptation": "exact rational inverse-metric nearest plane for perturbation; finite all-center CDF and bounded tapes are project adaptations"},
        "parameter_source": "hand-selected valid small trapdoor fixtures; no SIS security estimate or TrapGen distribution",
        "rom_use": "none in sampling experiments; future Foo-Li analysis is classical ROM",
        "identity_length_bytes": None, "message_length_bytes": None,
        "identity_message_note": "not applicable: no IBS keys, signatures or identities generated",
        "convention": "C is the squared parameter matrix in exp(-pi*x^T*C^-1*x), not probability covariance C/(2*pi)",
        "fixtures": {name: fixture_diagnostics(name, sampler, samples) for name, sampler in fixtures.items()},
        "independent_full_distribution_comparison": factorized_infinite_target_comparison(),
        "limitations": ["variable time, small dimension and all-center resource caps; rejected trapdoors not covered",
            "master and user fixtures are hand-selected, not a connected KeyExt/Sign execution",
            "fixed tape replay verifies the sampler interface, not the complete key lifecycle or RO encoding",
            "no TrapGen/DelTrap backend, practical security parameters or full Foo-Li IBS",
            "old public forgery and ciphertext tampering remain for the planned backend/wrapper repairs",
            "empirical moments and tests do not replace sampling or cryptographic security proofs"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=4096)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    serialized = json.dumps(audit_report(samples=args.samples), ensure_ascii=False, indent=2)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8", newline="\n")
    else:
        print(serialized, end="")


if __name__ == "__main__":
    main()
