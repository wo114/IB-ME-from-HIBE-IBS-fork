"""Same-input public CHKP chain and phase diagnostics; NOT a HIBE backend.

Uses delivered GenBasis/ExtBasis/GPV/RandBasis/fixed-leaf cache unchanged.
Installed Sage LLL remains an independently checked diagnostic, without a
uniform runtime/failure certificate. Default admissions and raw leaf failures
are retained. Explicit finite-error options trade error budget for tape size;
no dimension/scalar/tape/cache hardcap is overridden. H/G are NOT implemented.
"""

import argparse
from dataclasses import asdict
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path
import platform
import time

from sage.all import QQ, ZZ, matrix, vector
from sage.env import SAGE_VERSION

from .chkp_basis import ModMatrixReference, ext_basis
from .chkp_genbasis import AP09Parameters, gen_basis, genbasis_certificate
from .chkp_gpv import CHKPGPVSampler
from .chkp_randbasis import CHKPRandBasis
from .chkp_leaf_cache import FixedLeafCache
from .chkp_leaf_cache_types import CacheScope, LeafPlan
from .chkp_leaf_reference import LeafAdmissionError, sample_leaf_preimages
from .gaussian_reference import SamplingAbort, draw_uniform_integer
from .online_gaussian_reference import OnlineOptions
from .ibme_root_sampler_audit import CountingRandom, checked_sage_lll, geometry
from .ibme_joint_parameters import evaluate_noise, smoothing_factor
from .ibme_noise_budget import RoundedNoiseParams, attach_finite_noise_budget
from .ibme_rounded_noise import build_rounded_noise


EPSILON_BITS = 32
LEAF_BITS = 32
PHASE_REPETITIONS = 3
EXPLICIT_OPTIONS = dict(tail_bits=64, mass_bits=96, precision_bits=160,
                        gaussian_abort_bits=32, max_uniform_trials=48)
CONFIGURATIONS = ((17, 6, 22, 9), (257, 10, 38, 10))
SEED_INDICES = (0, 1)


class NoEntropy:
    def read(self, count):
        raise AssertionError("cache reuse or admission control consumed entropy")


def _required_width(dimension, gs_upper):
    return 4 * gs_upper * smoothing_factor(dimension, EPSILON_BITS)


def _digest_public(public):
    encoded = json.dumps(dict(q=public.q, rows=public.rows),
                         separators=(",", ":")).encode()
    return sha256(encoded).hexdigest()


def _block(params, width, source):
    return ModMatrixReference(tuple(tuple(draw_uniform_integer(source, params.q)
        for _ in range(width)) for _ in range(params.n)), params.q)


def _geometry_record(basis):
    lengths, _ = geometry(basis)
    return dict(dimension=basis.public.ncols, gs_squared_min=str(min(lengths)),
                gs_squared_max=str(max(lengths)))


def _sampler_record(sampler):
    cert = sampler.certificate()
    widths = [QQ(profile["squared_width_class"][0])
              for profile in cert["per_coordinate_profiles"]]
    return dict(dimension=sampler.dimension, width_squared=str(sampler.width_squared),
                tv_upper_including_abort=cert["tv_upper_including_abort"],
                public_random_tape_bytes=sampler.random_tape_bytes,
                scalar_width_squared_min=str(min(widths)),
                scalar_width_squared_max=str(max(widths)),
                path_resources=cert["path_resources"])


def _admission_probe(basis, width, options, *, randomizer=False):
    """Constructor-only probe: neither sampler execution nor fallback."""
    try:
        sampler = CHKPGPVSampler(basis, width, epsilon_bits=EPSILON_BITS, options=options)
        result = dict(status="admitted", sampler=_sampler_record(sampler), entropy_bytes=0)
        if randomizer:
            count = sampler.dimension + 32
            result["randbasis_worst_tape_bytes"] = count * sampler.random_tape_bytes
            rb = CHKPRandBasis(sampler, max_vectors=count)
            result["randbasis_certificate"] = rb.certificate()
        return result
    except ValueError as exc:
        result = locals().get("result", dict(entropy_bytes=0))
        result.update(status="admission_rejected", reason=str(exc))
        return result


def decode_phase(phase, q):
    """Original nearest mod-q centres; ties go to one, including odd q."""
    value = int(phase) % q
    distance_zero = min(value, q-value)
    offset = (value-q//2) % q
    distance_one = min(offset, q-offset)
    return int(distance_zero >= distance_one)


def phase_probe(batch, source, noise):
    """Check public-test bit equations, not H/G, a wire or authenticated KEM.

    q*alpha=1 is deliberately NOT a valid full-chain correctness profile.
    Honest-noise failures stay visible; the noiseless algebra control is
    computed separately and cannot be relabelled a successful noisy decrypt.
    """
    a = matrix(ZZ, batch.public.rows)
    q, dimension, count = batch.public.q, batch.public.ncols, len(batch.targets)
    secret = vector(ZZ, [draw_uniform_integer(source, q) for _ in range(a.nrows())])
    errors = noise.sample_vector(dimension+count, rng=source, mod_q=False)
    eta = vector(ZZ, errors[:dimension])
    b = a.transpose()*secret + eta
    exact = decoded = clean = 0
    for i, (target, preimage) in enumerate(zip(batch.targets, batch.preimages)):
        x, y, bit = vector(ZZ, preimage), vector(ZZ, target), i % 2
        c = y.dot_product(secret) + bit*(q//2) + errors[dimension+i]
        phase = int(c-x.dot_product(b)) % q
        expected = int(bit*(q//2) + errors[dimension+i]-x.dot_product(eta)) % q
        exact += int(phase == expected)
        decoded += int(decode_phase(phase, q) == bit)
        clean_phase = int(y.dot_product(secret)+bit*(q//2)
                          -x.dot_product(a.transpose()*secret)) % q
        clean += int(decode_phase(clean_phase, q) == bit)
    if exact != count or clean != count:
        raise ArithmeticError("public-test phase or noiseless algebra identity failed")
    return dict(bits=count, phase_equations_exact=exact, noiseless_control_correct=clean,
                honest_rounded_noise_correct=decoded, honest_rounded_noise_failed=count-decoded,
                nonzero_noise_coordinates=sum(x != 0 for x in errors),
                scalar_noise_calls=dimension+count, entropy_bytes=source.bytes_used,
                noise_profile_is_full_chain_correctness_candidate=False)


def run_chain(params, seed, *, leaf_bits=LEAF_BITS):
    if not isinstance(params, AP09Parameters) or type(seed) is not bytes or not seed:
        raise ValueError("validated AP09 config and nonempty explicit test seed required")
    if type(leaf_bits) is not int or not 1 <= leaf_bits <= LEAF_BITS:
        raise ValueError("diagnostic leaf count must stay within the delivered 32-bit cap")
    started = time.perf_counter()
    cfg_cert = genbasis_certificate(params)
    record = dict(seed=seed.decode("ascii"), attempts=1, genbasis_certificate=cfg_cert,
                  stages={}, outcome="not_started", security_claim="none", backend_admitted=False,
                  parameters_are_formal=False, ideal_H_or_G_implemented=False,
                  diagnostic_lll_uniform_resources_admitted=False)
    stage = "GenBasis"
    try:
        source = CountingRandom(seed+b":root")
        root = gen_basis(params, rng=source).basis
        record["stages"][stage] = dict(**_geometry_record(root), entropy_bytes=source.bytes_used,
                                       public_matrix_sha256=_digest_public(root.public))
        stage = "root_diagnostic_LLL"
        reduced_root = checked_sage_lll(root, params.gs_squared_bound)
        record["stages"][stage] = _geometry_record(reduced_root)
        width = params.m1+params.m2
        source = CountingRandom(seed+b":parent-block")
        parent_block = _block(params, width, source)
        raw_parent = ext_basis(root, parent_block)
        parent = ext_basis(reduced_root, parent_block)
        parent_width = _required_width(2*width, params.gs_squared_bound)
        options = OnlineOptions(**EXPLICIT_OPTIONS)
        stage = "parent_admission"
        record["stages"][stage] = dict(block_entropy_bytes=source.bytes_used,
            raw_basis_default=_admission_probe(raw_parent, parent_width, OnlineOptions(), randomizer=True),
            reduced_basis_default=_admission_probe(parent, parent_width, OnlineOptions(), randomizer=True),
            explicit_options=asdict(options))
        # This is a predeclared second input profile, not a retry after a random
        # sampling failure. No entropy was consumed by either default probe.
        sampler = CHKPGPVSampler(parent, parent_width, epsilon_bits=EPSILON_BITS, options=options)
        randomizer = CHKPRandBasis(sampler, max_vectors=sampler.dimension+32)
        record["stages"][stage]["explicit_sampler"] = _sampler_record(sampler)
        record["stages"][stage]["explicit_randbasis"] = randomizer.certificate()
        stage = "parent_RandBasis"
        source = CountingRandom(seed+b":parent-randbasis")
        randomized = randomizer.sample(rng=source)
        record["stages"][stage] = dict(**_geometry_record(randomized.basis),
            entropy_bytes=source.bytes_used, gaussian_vectors_used=randomized.draws_used,
            public_gs_squared_upper=str(parent_width*sampler.dimension))
        parent_bound = parent_width*sampler.dimension
        source = CountingRandom(seed+b":leaf-block")
        leaf_block = _block(params, width, source)
        raw_leaf = ext_basis(randomized.basis, leaf_block)
        leaf_width = _required_width(3*width, parent_bound)
        stage = "raw_terminal_leaf_admission"
        record["stages"][stage] = _admission_probe(raw_leaf, leaf_width, options)
        stage = "parent_diagnostic_LLL"
        reduced_parent = checked_sage_lll(randomized.basis, parent_bound)
        record["stages"][stage] = _geometry_record(reduced_parent)
        # CHKP maximum-depth extraction uses the extended parent basis; no
        # second RandBasis or randomized leaf basis is introduced here.
        leaf = ext_basis(reduced_parent, leaf_block)
        stage = "terminal_leaf_admission"
        leaf_sampler = CHKPGPVSampler(leaf, leaf_width, epsilon_bits=EPSILON_BITS, options=options)
        record["stages"][stage] = dict(**_geometry_record(leaf), sampler=_sampler_record(leaf_sampler),
            target_bits=leaf_bits, public_batch_tape_bytes=leaf_bits*leaf_sampler.random_tape_bytes,
            second_RandBasis_used=False)
        stage = "fixed_leaf_cache"
        source = CountingRandom(seed+b":targets")
        targets = tuple(tuple(draw_uniform_integer(source, params.q) for _ in range(params.n))
                        for _ in range(leaf_bits))
        plan = LeafPlan.from_sampler(leaf_sampler, targets)
        scope = CacheScope(b"IBME/SAME-INPUT-CHAIN/1:"+_digest_public(leaf.public).encode(),
                           b"rcv-test", leaf_bits)
        cache = FixedLeafCache(scope)
        source = CountingRandom(seed+b":leaf-preimages")
        batch = cache.resolve(b"phi-test", plan, sampler=leaf_sampler, rng=source)
        bound = leaf_width*leaf.public.ncols
        norm_values = [sum(ZZ(x)**2 for x in preimage) for preimage in batch.preimages]
        wire = cache.to_bytes()  # Sensitive plaintext: stays in memory, never exported.
        restored = FixedLeafCache.from_bytes(wire, expected_scope=scope)
        hit = cache.resolve(b"phi-test", plan, rng=NoEntropy())
        reloaded_hit = restored.resolve(b"phi-test", plan, rng=NoEntropy())
        if hit.preimages != batch.preimages or reloaded_hit.preimages != batch.preimages:
            raise ArithmeticError("fixed address was resampled or changed during restore")
        if restored.to_bytes() != wire:
            raise ArithmeticError("restored snapshot is not canonical")
        record["stages"][stage] = dict(preimages=leaf_bits, equations_exact=leaf_bits,
            entropy_bytes=source.bytes_used, norm_squared_min=str(min(norm_values)),
            norm_squared_max=str(max(norm_values)), assumed_norm_squared_upper=str(bound),
            norms_within_budget=sum(x <= bound for x in norm_values),
            snapshot_bytes=len(wire), snapshot_written_to_disk=False,
            cache_hit_entropy_bytes=0, restore_hit_entropy_bytes=0, restored_vectors_identical=True,
            public_context_and_receiver_bound=True, real_identity_H_or_G=False,
            identities_are_test_labels=True, receiver_bytes=8, sender_bytes=8)
        stage = "256_bit_capacity_control"
        try:
            sample_leaf_preimages(leaf_sampler, (targets[0],)*256, rng=NoEntropy())
        except LeafAdmissionError as exc:
            record["stages"][stage] = dict(status="admission_rejected", reason=str(exc),
                                           entropy_bytes=0, hybrid_seed_bytes=32,
                                           required_seed_bits=256, capacity_met=False)
        else:
            raise ArithmeticError("delivered target cap was silently bypassed")
        stage = "rounded_noise_phase_probe"
        noise = build_rounded_noise(RoundedNoiseParams(q=params.q, alpha=Fraction(1, params.q)))
        probes = [phase_probe(batch, CountingRandom(seed+b":phase:"+str(i).encode()), noise)
                  for i in range(PHASE_REPETITIONS)]
        ideal = evaluate_noise(q=params.q, dimension=leaf.public.ncols,
            width_squared=int(leaf_width), alpha=Fraction(1, params.q), seed_bits=leaf_bits,
            encapsulations=PHASE_REPETITIONS)
        record["stages"][stage] = dict(noise_certificate=noise.certificate(), repetitions=probes,
            conditional_budget=attach_finite_noise_budget(ideal, noise.certificate()),
            negative_noise_control=True, full_KEM_or_HIBE_implemented=False)
        conditional_failure = min(QQ(1), randomizer.failure_upper+leaf_bits*leaf_sampler.tv_upper)
        record.update(outcome="parent_and_fixed_terminal_preimages_completed",
            randbasis_and_leaf_sampling_terms_upper=str(conditional_failure),
            omitted_from_selected_terms=["leaf preimage norm-tail probability", "GenBasis distribution",
                "preprocessing failure/resources", "noise decode failures"],
            local_budget_condition="given successful preprocessing and fixed public diagnostic bases",
            preprocessing_abort_or_resource_upper=None,
            full_joint_failure_upper=None, public_genbasis_tv_nonvacuous=cfg_cert["near_uniform_bound_nonvacuous"])
    except SamplingAbort as exc:
        record.update(outcome="explicit_abort", stopped_at=stage, reason=str(exc))
    except ValueError as exc:
        record.update(outcome="admission_rejected", stopped_at=stage, reason=str(exc))
    except ArithmeticError as exc:
        record.update(outcome="invariant_failed", stopped_at=stage, reason=str(exc))
    except Exception as exc:
        record.update(outcome="execution_failed", stopped_at=stage,
                      error_type=type(exc).__name__, reason=str(exc))
    record["diagnostic_seconds_not_benchmark"] = round(time.perf_counter()-started, 6)
    return record


def build_report():
    attempts = []
    for q, d, m2, scale in CONFIGURATIONS:
        params = AP09Parameters(n=1, q=q, random_rows=d, m1=d, m2=m2, hadamard_scale=scale)
        for index in SEED_INDICES:
            seed = f"ibme-same-input-q{q}-{index}".encode()
            print(seed.decode(), "started", flush=True)
            result = run_chain(params, seed)
            attempts.append(result)
            print(seed.decode(), result["outcome"], result.get("stopped_at", ""), flush=True)
    root = Path(__file__).resolve().parents[2]
    paths = ["experiments/research/"+name+".py" for name in (
        "ibme_chain_audit", "ibme_root_sampler_audit", "ibme_joint_parameters",
        "ibme_noise_budget", "ibme_rounded_noise", "chkp_basis", "chkp_genbasis",
        "chkp_gpv", "chkp_randbasis", "chkp_tobasis", "online_gaussian_reference",
        "chkp_leaf_reference", "chkp_leaf_cache", "chkp_leaf_cache_types", "chkp_leaf_cache_wire")]
    hashes = {path: sha256((root/path).read_text(encoding="utf-8").replace("\r\n", "\n").encode()).hexdigest()
              for path in paths}
    return dict(schema="IBME/SAME-INPUT-CHAIN-AUDIT/1", security_claim="none", backend_admitted=False,
        parameters_are_formal=False, epsilon_bits_not_security_bits=EPSILON_BITS,
        explicit_options=EXPLICIT_OPTIONS, default_options_changed=False,
        hardcaps_changed=False, seed_search_or_retry=False, declared_attempt_count=4,
        environment=dict(python=platform.python_version(), sage=str(SAGE_VERSION), platform=platform.platform()),
        attempts=attempts, all_diagnostic_chains_completed=all(x["outcome"]==
        "parent_and_fixed_terminal_preimages_completed" for x in attempts), source_sha256_lf=hashes,
        not_implemented=["real H/G and two-level anonymous HIBE", "256-bit fixed-address wire/state",
            "valid full-chain noisy KEM parameters", "uniform preprocessing/resource bound",
            "full IBME composition or attacks", "LWE cost estimate/security level"],
        source_version="CHKP author 2011-06-14, section 5.1 bit equations and 5.2 terminal leaf",
        timing_scope="single diagnostic per fixed seed; includes exact audit/serialization overhead",
        randomness_scope="explicit deterministic PUBLIC TEST streams, not independent physical repetitions")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
    return 0 if report["all_diagnostic_chains_completed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
