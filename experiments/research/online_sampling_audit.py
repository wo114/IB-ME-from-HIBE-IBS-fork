"""Reproduce online Gaussian/gadget/MP12 resource and distribution checks."""

from __future__ import annotations

import argparse
from hashlib import sha256, shake_256
import json
from pathlib import Path
import platform
import sys

from sage.all import QQ, ZZ, RealIntervalField, identity_matrix, matrix, vector
from sage.version import version as sage_version

from .gaussian_reference import SamplingAbort, build_gaussian_table_squared, draw_uniform_integer, interval_record
from .mp12_sampled_reference import NonSphericalGaussianSampler, finite_nonspherical_distribution
from .online_gaussian_reference import OnlineScalarGaussian, exact_integer, interval_upper
from .online_mp12_reference import (OnlineGadgetSampler, OnlineGaussianGenTrap,
    OnlineNonSphericalSampler, delegate_stream, quality_stage, sampler_for_quality)


class AuditRandom:
    """Test-only frozen byte stream, 64-KiB SHAKE blocks; NEVER production.

    Larger blocks avoid millions of Python calls when hashing full public tape
    bands. read chunking is invariant. This is only reproducibility machinery;
    the sampler proofs instead assume independently uniform bytes.
    """
    block_size = 65536

    def __init__(self, seed):
        if not isinstance(seed, bytes) or not 1 <= len(seed) <= 4096:
            raise ValueError("Need a nonempty test seed")
        self.prefix = b"IBME-ROUND10-TEST-STREAM"+len(seed).to_bytes(4, "big")+seed
        self.counter, self.buffer = 0, bytearray()

    def read(self, n):
        n = exact_integer(n, "byte count", maximum=256*1024*1024)
        while len(self.buffer) < n:
            self.buffer.extend(shake_256(self.prefix+self.counter.to_bytes(8, "big")).digest(self.block_size))
            self.counter += 1
        out = bytes(self.buffer[:n])
        del self.buffer[:n]
        return out


def finite_online_nonspherical(sampler, *, max_states=20000):
    """QA only: ideal accepted-kernel PMF; not postselected vector success law."""
    law, coefficients, visited = {}, [0]*sampler.dimension, 0

    def visit(i, probability):
        nonlocal visited
        if i < 0:
            law[tuple(coefficients)] = probability
            return
        center = sampler.center(i, coefficients[i+1:])
        scalar_law = sampler.scalar.finite_distribution(1/sampler.norm_squared[i], center)
        for value, p in scalar_law.items():
            visited += 1
            if visited > max_states:
                raise ValueError("Audit enumeration exceeds max_states")
            coefficients[i] = value
            visit(i-1, probability*p)
    visit(sampler.dimension-1, QQ(1))
    assert sum(law.values(), QQ(0)) == 1
    return law


def non_spherical_comparison():
    covariance = matrix(QQ, [[9, 3], [3, 6]])
    online = OnlineNonSphericalSampler(covariance, OnlineScalarGaussian(3, 12))
    law = finite_online_nonspherical(online)
    old = NonSphericalGaussianSampler(covariance)
    old_law = finite_nonspherical_distribution(old)
    old_distance = sum((abs(law.get(x, 0)-old_law.get(x, 0)) for x in set(law)|set(old_law)), QQ(0))/2
    field = RealIntervalField(256)
    # Exact quadratic factorization: x2 width^2=6; x1 center=x2/2,
    # width^2=15/2. Infinite mass splits over the parity of x2.
    options = {"tail_bits": 128, "mass_bits": 192, "precision_bits": 256}
    even = build_gaussian_table_squared(6, step=2, residue=0, **options).normalizer
    odd = build_gaussian_table_squared(6, step=2, residue=1, **options).normalizer
    c0 = build_gaussian_table_squared(QQ(15)/2, 0, **options).normalizer
    ch = build_gaussian_table_squared(QQ(15)/2, QQ(1)/2, **options).normalizer
    normalizer = field(even*c0+odd*ch)
    inside, differences = field(0), field(0)
    for x, probability in law.items():
        v = vector(QQ, x)
        target = (-field.pi()*field(v*online.inverse*v)).exp()/normalizer
        inside += target
        differences += abs(field(probability)-target)
    outside = 1-inside
    distance = (differences+outside)/2
    return {"covariance": [[9, 3], [3, 6]], "online_support_points": len(law),
        "exact_total_probability": "1", "online_to_old_CDF_TV": str(old_distance),
        "infinite_target_normalizer": interval_record(normalizer),
        "infinite_target_outside_online_support": interval_record(outside),
        "online_to_infinite_target_TV": interval_record(distance),
        "online_certificate": online.certificate(), "old_certificate": old.certificate(),
        "method": "complete finite accepted-kernel PMF plus independent factored infinite partition masses",
        "security_claim": "none"}


def public_generation_bias(generator):
    """Unfiltered, unconditional TV LOWER bound, scalar parent only.

    Public event: every extension column equals G_j, G_j+a, or G_j-a.
    It holds whenever all R0 entries lie in {-1,0,1}; no quality filter.
    """
    if (generator.n, generator.m_bar) != (1, 1):
        raise ValueError("Public event proof requires n=m_bar=1")
    law = generator.scalar.finite_distribution(generator.width_squared)
    small = sum((p for x, p in law.items() if abs(x) <= 1), QQ(0))
    error = generator.w*generator.scalar.abort_upper+QQ(1)/2**generator.scalar.options.max_uniform_trials
    q, w = generator.q, generator.w
    generated_event_lower = max(QQ(0), small**w-error)
    uniform_event = QQ(1)/q*(QQ(1)/q)**w+QQ(q-1)/q*(QQ(3)/q)**w
    lower = max(QQ(0), generated_event_lower-uniform_event)
    return {"event": "for each j, A[j+1] in {G[j]-A[0],G[j],G[j]+A[0]} mod q",
        "single_R0_small_probability": str(small), "generation_abort_upper": str(error),
        "unconditional_generated_event_probability_lower": str(generated_event_lower),
        "uniform_public_event_probability": str(uniform_event),
        "public_to_uniform_TV_lower": str(lower), "TV_lower_approx": float(lower),
        "master_quality_filter_applied": False, "near_uniform_gate_passed": False,
        "security_claim": "none"}


def recover_debug_master_trapdoor(public, q):
    """Public-only negative control for the n=m_bar=1 debug generator.

    With nonzero a, recover R0 modulo q and center-lift; Gaussian support in
    this debug instance is much smaller than q/2. a=0 admits the zero trapdoor.
    This is not an attack on correctly parameterized Foo-Li.
    """
    row = [int(x) for x in public.row(0)]
    a, w = row[0], len(row)-1
    if a == 0:
        recovered = [0]*w
    else:
        inv = pow(a, -1, q)
        recovered = [(((1 << j)-row[j+1])*inv) % q for j in range(w)]
        recovered = [x-q if x > q//2 else x for x in recovered]
    r = matrix(ZZ, [recovered])
    gadget = matrix(ZZ, [[(1 << j) % q for j in range(w)]])
    valid = (public*r.stack(identity_matrix(ZZ, w))-gadget).apply_map(lambda x: x % q).is_zero()
    return r, bool(valid)


def audit_report(*, attempts=3, user_prefix=1, samples_per_syndrome=32, progress=None):
    attempts = exact_integer(attempts, "attempts", minimum=1, maximum=16)
    user_prefix = exact_integer(user_prefix, "public user prefix", maximum=min(attempts, 4))
    samples_per_syndrome = exact_integer(samples_per_syndrome, "sample count", minimum=1, maximum=4096)
    gadgets = []
    for q, count in ((257, 257), (65537, 256)):
        sampler = OnlineGadgetSampler(q, 45)
        rng = AuditRandom(f"round10-gadget-{q}".encode())
        errors, aborts = 0, 0
        for j in range(count):
            target = j if q == 257 else draw_uniform_integer(rng, q)
            try:
                x = sampler.sample((target,), rng=rng)
            except SamplingAbort:
                aborts += 1
                continue
            errors += sum((1 << i)*v for i, v in enumerate(x)) % q != target
        gadgets.append({"q": q, "draws": count, "all_syndromes_covered": q == 257,
            "equation_errors": errors, "aborts": aborts, "certificate": sampler.certificate()})
    wide = OnlineScalarGaussian(10**12, 10**12)
    wide_rng = AuditRandom(b"round10-wide-scalar")
    values = [wide.sample(10**12, QQ(1)/10**100, rng=wide_rng) for _ in range(1024)]
    mean = sum(values)/len(values)
    variance = sum((x-mean)**2 for x in values)/len(values)
    q = 2147483659
    generator = OnlineGaussianGenTrap(q, 1, 1)
    w, master_quality = generator.w, 64
    master_dimension = 1+w
    s_squared = 9*7*(master_quality+1)
    user_quality = w*master_dimension*s_squared
    user_dimension = master_dimension+w
    _, master_stage = quality_stage(master_dimension, master_quality)
    _, user_stage = quality_stage(user_dimension, user_quality)
    counts = {x: 0 for x in ("generation_abort", "master_quality_rejected", "delegation_abort",
        "user_quality_rejected", "qualified_users", "materialized_users", "user_sample_attempts",
        "user_sample_abort", "user_equation_errors")}
    rows, certificates = [], []
    for i in range(attempts):
        prefix = f"ibme-round10:attempt:{i}".encode()
        row = {"attempt": i, "materialization_requested_by_public_prefix": i < user_prefix}
        try:
            generated = generator.generate(rng=AuditRandom(prefix+b":setup"))
        except SamplingAbort:
            counts["generation_abort"] += 1
            row["status"] = "generation_abort"
            rows.append(row)
            continue
        master_profile, parent = sampler_for_quality(q, generated.a_bar, generated.trapdoor, master_quality)
        row.update({"A": [[int(x) for x in generated.public.row(0)]],
            "R0": [[int(x) for x in generated.trapdoor.row(0)]], "master_norm_squared": generated.norm_squared})
        recovered, valid = recover_debug_master_trapdoor(generated.public, q)
        row.update({"debug_public_master_trapdoor_recovery_valid": valid,
            "recovered_norm_squared": sum(int(x)**2 for x in recovered.list()),
            "public_recovery_matches_generated_R0": recovered == generated.trapdoor})
        if parent is None:
            counts["master_quality_rejected"] += 1
            row["status"] = "master_quality_rejected"
            rows.append(row)
            continue
        erng = AuditRandom(prefix+b":extension")
        extension = [[draw_uniform_integer(erng, q) for _ in range(w)]]
        try:
            delegated, hashes = delegate_stream(parent, extension, rng=AuditRandom(prefix+b":delegation"))
        except SamplingAbort:
            counts["delegation_abort"] += 1
            row["status"] = "delegation_abort"
            rows.append(row)
            continue
        row.update({"extension": extension, "delegated_R": [[int(x) for x in r] for r in delegated.trapdoor.rows()],
            "delegated_norm_squared": delegated.norm_squared, "delegation_band_sha256": hashes,
            "delegation_public_total_tape_bytes": w*parent.random_tape_bytes})
        if delegated.norm_squared > user_quality:
            counts["user_quality_rejected"] += 1
            row["status"] = "user_quality_rejected"
            rows.append(row)
            continue
        counts["qualified_users"] += 1
        row["status"] = "qualified"
        if i < user_prefix:
            profile, user = sampler_for_quality(q, generated.public, delegated.trapdoor, user_quality)
            assert user is not None and profile["status"] == "admitted"
            assert user.public_matrix() == generated.public.augment(delegated.extension)
            counts["materialized_users"] += 1
            certificates.append({"attempt": i, "master": parent.certificate(), "user": user.certificate()})
            first = []
            for syndrome in (0, q-1):
                srng = AuditRandom(prefix+f":user:{syndrome}".encode())
                for j in range(samples_per_syndrome):
                    counts["user_sample_attempts"] += 1
                    try:
                        x = user.sample((syndrome,), rng=srng)
                    except SamplingAbort:
                        counts["user_sample_abort"] += 1
                        continue
                    counts["user_equation_errors"] += int((user.public_matrix()*vector(ZZ, x))[0]) % q != syndrome
                    if j < 2:
                        first.append({"syndrome": syndrome, "x": list(x)})
            tape = AuditRandom(prefix+b":user-tape").read(user.random_tape_bytes)
            x = user.sample_from_tape((12345,), tape)
            row.update({"first_user_outputs": first, "user_tape_sha256": sha256(tape).hexdigest(),
                "user_replay_equal": x == user.sample_from_tape((12345,), tape), "user_replay_output": list(x)})
        rows.append(row)
        if progress:
            progress(f"Connected attempt {i+1}/{attempts}: {row['status']}, norm^2={delegated.norm_squared}")
    t_squared = QQ(user_stage["scalar"]["squared_width_class"][1])
    beta_squared = 4*t_squared*user_dimension*(user_quality+1)
    source = Path("papers/2011_lattice_trapdoors_micciancio.pdf")
    return {"schema_version": 1, "research_round": 10, "checked_on": "2026-10-05",
        "security_claim": "none", "parameter_source": "hand-selected stress/debug instances, not security parameters",
        "environment": {"python": sys.version.split()[0], "sage": sage_version, "platform": platform.platform()},
        "sources": {"MP12_url": "https://eprint.iacr.org/2011/501", "pdf_sha256": sha256(source.read_bytes()).hexdigest(),
            "locations": ["section 2 discrete Gaussians, PDF 11-13", "section 4.2 general gadget, PDF 18-19", "Algorithms 1/3/4, PDF 24/27/29"],
            "rounding": "https://doc.sagemath.org/html/en/reference/spkg/mpfi.html"},
        "ROM_use": "none in experiments; planned Foo-Li proof is classical ROM",
        "identity_length_bytes": None, "message_length_bytes": None,
        "production_keys_or_IBS_signatures_generated": 0,
        "test_stream": {"domain_ascii": "IBME-ROUND10-TEST-STREAM", "block_size": AuditRandom.block_size,
            "definition": "SHAKE256(domain||u32be(seed_length)||seed||u64be(block_index),65536), concatenated; test only"},
        "gadget_experiments": gadgets,
        "wide_scalar_experiment": {"samples": len(values), "center": "1/10^100", "mean": mean,
            "variance": variance, "certificate": wide.certificate()},
        "non_spherical_distribution_comparison": non_spherical_comparison(),
        "connected": {"q": q, "n": 1, "m_bar": 1, "w": w, "master_dimension": master_dimension,
            "user_dimension": user_dimension, "master_quality_squared": master_quality, "user_quality_squared": user_quality,
            "attempts": attempts, "user_public_prefix": user_prefix, "samples_per_user_per_syndrome": samples_per_syndrome,
            "counts": counts, "all_attempts": rows, "materialized_certificates": certificates,
            "master_stage": master_stage, "user_stage": user_stage,
            "generation_public_distribution": public_generation_bias(generator),
            "SIS_norm_gate": {"beta_reduction_squared": str(beta_squared), "q_squared": q*q,
                "passed": beta_squared < q*q, "security_level_estimated": False},
            "failed_attempts_discarded_or_retried": False,
            "delegation_stream_semantics": "w disjoint full bands; peak tape retention B not w*B; full band hashes include unused suffix"},
        "limitations": ["Dense exact geometry capped at dimension 128 and q <=2^32; no production dimensions",
            "n=1,m_bar=1 debug generation is provably far from uniform, despite the SIS norm interval passing",
            "Scalar width ratios/rational bits/finite tape budgets can cause public class admission rejection",
            "No practical full parameter/security estimate, formal Foo-Li lifecycle/encoding or production IBS/HIBE backend",
            "Legacy forgery and ciphertext tamper remain pending backend/wrapper replacement",
            "Correct rounding and numerical-budget derivation need independent proof review; variable-time sampler"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--user-prefix", type=int, default=1)
    parser.add_argument("--samples-per-syndrome", type=int, default=32)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    progress = (lambda message: print(message, file=sys.stderr, flush=True)) if args.output else None
    result = audit_report(attempts=args.attempts, user_prefix=args.user_prefix,
        samples_per_syndrome=args.samples_per_syndrome, progress=progress)
    data = json.dumps(result, ensure_ascii=False, indent=2)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(data, encoding="utf-8", newline="\n")
    else:
        print(data, end="")


if __name__ == "__main__":
    main()
