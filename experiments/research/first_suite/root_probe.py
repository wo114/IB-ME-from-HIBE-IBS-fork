"""CSPRNG root, public two-layer plan and private master-only restore pilot.

No parent/leaf generation, seven-method HIBE or security grade is claimed.
The n=1 diagnostic explicitly demonstrates public-only seed recovery; root
regularity is a distribution condition, not a substitute for LWE difficulty.
Private full bases stay in an ignored, newly-created test-results directory.
"""

import argparse
from dataclasses import asdict
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import time

from .delegation_state import DelegationScope, MasterTreeState
from .identity import ROHIBEContext, checked_int
from .root_generation import MP12RootParams, MP12RootGenerator

ROOT = Path(__file__).resolve().parents[3]
PARENT_PROFILE = b"FIRST-SUITE-FINITE-RANDBASIS/1; epsilon128; canonical ToBasis"
LEAF_PROFILE = b"FIRST-SUITE-FINITE-GPV/1; epsilon128; fixed 256 addresses"


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def chain_plan(generator, *, epsilon_bits=128):
    """Public-only bounds; actual parent/leaf geometry/resources are pending."""
    from experiments.research.ibme_joint_parameters import smoothing_factor, evaluate_noise
    checked_int(epsilon_bits, "chain epsilon bits", 2, 128)
    p, scalar = generator.params, generator.scalar
    m = p.dimension
    root_dimension_cap = min(1024, 192//2, 256//3)
    root_bound = 10 * (1 + p.m_bar * p.n * p.k * scalar.radius**2)
    s1 = 4 * root_bound * smoothing_factor(2*m, epsilon_bits)
    parent_bound = s1 * 2*m
    s2 = 4 * parent_bound * smoothing_factor(3*m, epsilon_bits)
    return dict(parameters=asdict(p), dimensions=[m, 2*m, 3*m],
                root_gs_squared_bound=root_bound, parent_width_squared=s1,
                parent_gs_squared_bound=parent_bound, leaf_width_squared=s2,
                epsilon_bits=epsilon_bits,
                selected_modulus_sufficient=p.q**2 >= 16*s2*(3*m+1)**2,
                conditional_noise=evaluate_noise(q=p.q, dimension=3*m, width_squared=s2,
                    alpha=Fraction(4, p.q), error_bits=64, seed_bits=256, encapsulations=2**20),
                resource_dimensions=dict(parent_tobasis=2*m <= 192, leaf_finite_gpv=3*m <= 256),
                capacity_obstruction=dict(current_root_dimension_ceiling=root_dimension_cap,
                    max_n_from_gadget_before_random_columns=(root_dimension_cap-1)//p.k,
                    only_dimension_not_a_security_estimate=True),
                actual_parent_leaf_profiles_checked=False,
                actual_parent_or_leaf_generated=False,
                finite_chain_execution_budget=None,
                root_regularity_upper_conditional=str(generator.regularity),
                primitive_sampler_error_is_not_security_strength=True,
                parameters_are_formal=False, security_claim="none", backend_admitted=False)


def scope_for(oracle, plan):
    p = plan["parameters"]
    if (oracle.n, oracle.q, oracle.m) != (p["n"], p["q"], plan["dimensions"][0]):
        raise ValueError("root plan differs from public context parameters")
    return DelegationScope(oracle, Fraction(plan["root_gs_squared_bound"]),
                           Fraction(plan["parent_width_squared"]),
                           Fraction(plan["leaf_width_squared"]), PARENT_PROFILE, LEAF_PROFILE,
                           epsilon_bits=plan["epsilon_bits"])


def restore_only(manifest_path):
    path = Path(manifest_path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    oracle = ROHIBEContext.from_bytes(bytes.fromhex(manifest["oracle_hex"]))
    scope = scope_for(oracle, manifest["chain_plan"])
    raw = (path.parent / "master-tree.bin").read_bytes()
    restored = MasterTreeState.from_bytes(raw, expected_scope=scope)
    return dict(master_byte_equal=restored.to_bytes() == raw,
                epsilon_bits=scope.epsilon_bits, public_context_bound=True,
                new_root_generations=0, new_parent_generations=0, new_leaf_generations=0,
                private_basis_in_public_report=False, security_claim="none", backend_admitted=False)


def public_n1_seed_attack(oracle, receiver, sender, capsule, noise):
    """Diagnostic ciphertext-only attack for n=1, not a general LWE solver.

    Enumerate the bounded first rounded error, deduce s modulo prime q, then
    filter using ALL public preamble equations. No basis or actual s is read.
    Returns candidate recovered seeds privately, for a probe to compare.
    """
    from .seed_kem import decode_phase
    if oracle.n != 1:
        raise ValueError("explicit dimension-one diagnostic only")
    if (capsule.context != oracle.context or capsule.q != oracle.q
            or len(capsule.preamble) != oracle.leaf_dimension or noise.params.q != oracle.q):
        raise ValueError("dimension-one public attack input context mismatch")
    rows = oracle.leaf_rows(receiver, sender)
    coefficients = rows[0]
    j = next(i for i, a in enumerate(coefficients) if a % oracle.q)
    q = oracle.q
    inverse = pow(coefficients[j], -1, q)
    support_low, support_high = -noise.radius, noise.radius
    candidates, seeds = [], []
    for error in range(support_low, support_high + 1):
        s = (capsule.preamble[j] - error) * inverse % q
        residuals = tuple((b - a*s) % q for a, b in zip(coefficients, capsule.preamble))
        centered = tuple(e if e <= q//2 else e-q for e in residuals)
        if not all(support_low <= e <= support_high for e in centered):
            continue
        bits = []
        for target, value in zip(oracle.targets(receiver, sender), capsule.terminals):
            phase = (value - target[0]*s) % q
            bits.append(decode_phase(phase, q))
        candidates.append(s)
        seeds.append(bytes(sum(bits[8*i+j] << (7-j) for j in range(8)) for i in range(32)))
    return len(range(support_low, support_high + 1)), candidates, seeds


def public_attack_fixture(oracle, receiver, sender, capsule, noise, seed):
    """Only public encryption inputs/ciphertext and a verification hash."""
    return dict(schema="FIRST-SUITE/PUBLIC-N1-ATTACK/1", oracle_hex=oracle.to_bytes().hex(),
                receiver_hex=receiver.hex(), sender_hex=sender.hex(), capsule_hex=capsule.to_bytes().hex(),
                noise_parameters=noise.params.to_record(), expected_seed_sha256=sha256(seed).hexdigest(),
                private_basis_actual_secret_or_seed_in_fixture=False,
                security_claim="none", backend_admitted=False)


def attack_only(fixture):
    from experiments.research.ibme_noise_budget import RoundedNoiseParams
    from experiments.research.ibme_rounded_noise import build_rounded_noise
    from .seed_kem import SeedCapsule
    if fixture["schema"] != "FIRST-SUITE/PUBLIC-N1-ATTACK/1":
        raise ValueError("unknown public attack fixture")
    oracle = ROHIBEContext.from_bytes(bytes.fromhex(fixture["oracle_hex"]))
    capsule = SeedCapsule.from_bytes(bytes.fromhex(fixture["capsule_hex"]))
    p = fixture["noise_parameters"]
    noise = build_rounded_noise(RoundedNoiseParams(p["q"], Fraction(p["alpha"]),
        tail_bits=p["tail_bits"], mass_bits=p["mass_bits"], precision_bits=p["precision_bits"],
        max_radius=p["max_radius"]))
    count, candidates, seeds = public_n1_seed_attack(oracle, bytes.fromhex(fixture["receiver_hex"]),
        bytes.fromhex(fixture["sender_hex"]), capsule, noise)
    hashes = [sha256(seed).hexdigest() for seed in seeds]
    return dict(enumerated_first_error_candidates=count, surviving_candidates=len(candidates),
                recovered_seed_sha256=hashes,
                unique_seed_hash_matches=len(hashes) == 1 and hashes[0] == fixture["expected_seed_sha256"],
                private_state_loaded=False, private_generation_or_entropy_used=False,
                security_claim="none", backend_admitted=False)


def one_probe(binary, private_directory):
    from ibme.core.randomness import SecureRandom
    from ibme.protocol.hybrid_hibe import HybridLimits, encoded_identity
    from experiments.research.ibme_noise_budget import RoundedNoiseParams
    from experiments.research.ibme_rounded_noise import build_rounded_noise
    from .seed_kem import encapsulate_seed, SeedCapsule

    directory = Path(private_directory).resolve()
    allowed = (ROOT / "test-results").resolve()
    if not directory.is_relative_to(allowed) or directory == allowed:
        raise ValueError("explicit new test-results private directory required")
    # Fail before entropy if a previous root lifetime exists. No overwrites.
    directory.mkdir(parents=True, exist_ok=False)
    pending = directory / "generation.pending"
    pending.write_bytes(b"MP12 root lifetime reserved; do not restart here\n")
    started = time.monotonic()
    p = MP12RootParams(1, 35184372088891, 37, 1024)
    generator = MP12RootGenerator(p, binary)
    plan = chain_plan(generator)
    root = generator.generate()
    noise_params = RoundedNoiseParams(p.q, Fraction(4, p.q), tail_bits=64, mass_bits=96, precision_bits=160)
    public_configuration = canonical_json(dict(
        version="FIRST-SUITE/CSPRNG-ROOT/1", parameters=asdict(p),
        root_gs_squared_bound=plan["root_gs_squared_bound"],
        parent_width_squared=plan["parent_width_squared"],
        leaf_width_squared=plan["leaf_width_squared"], epsilon_bits=plan["epsilon_bits"],
        parent_profile=PARENT_PROFILE.decode(), leaf_profile=LEAF_PROFILE.decode(),
        root_finite_options=asdict(generator.scalar.options), noise=noise_params.to_record(),
        parameters_are_formal=False, security_claim="none", backend_admitted=False))
    oracle = ROHIBEContext(p.n, p.dimension, p.q, root.basis.public.rows, public_configuration)
    tree = MasterTreeState(scope_for(oracle, plan), root.basis)
    raw = tree.to_bytes()
    with (directory / "master-tree.bin").open("xb") as stream:
        stream.write(raw)
    manifest = dict(version="FIRST-SUITE/CSPRNG-ROOT-RESTORE/1",
                    oracle_hex=oracle.to_bytes().hex(), chain_plan=plan)
    manifest_path = directory / "public-restore-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2)+"\n", encoding="utf-8")
    # Capture the completed root before observation in the fresh interpreter.
    certificate = root.public_generation_certificate
    (directory / "public-generation-receipt.json").write_text(
        json.dumps(certificate, indent=2)+"\n", encoding="utf-8")
    child = subprocess.run([sys.executable, "-m", "experiments.research.first_suite.root_probe",
                            "--restore-only", str(manifest_path)], cwd=ROOT,
                           capture_output=True, text=True, timeout=60)
    if child.returncode:
        raise RuntimeError("private master restore failed; diagnostics withheld")
    fresh = json.loads(child.stdout)
    limits = HybridLimits(backend_id=b"chkp-first-research")
    receiver, sender = encoded_identity(b"Bob", limits, b"P"), encoded_identity(b"Alice", limits, b"C")
    source, noise = SecureRandom(), build_rounded_noise(noise_params)
    seed = source.read(32)
    capsule = encapsulate_seed(oracle, receiver, sender, seed, noise, rng=source)
    parsed = SeedCapsule.from_bytes(capsule.to_bytes())
    enumerated, candidates, recovered = public_n1_seed_attack(oracle, receiver, sender, parsed, noise)
    attack = dict(type="n=1 bounded-error enumeration from public ciphertext",
                  inputs="public oracle/context, receiver/sender, capsule and public finite noise support",
                  private_basis_or_actual_lwe_secret_read=False,
                  enumerated_first_error_candidates=enumerated, surviving_candidates=len(candidates),
                  original_seed_recovered=seed in recovered,
                  unique_seed_recovered=len(recovered) == 1 and recovered[0] == seed,
                  seed_bits=256, conclusion="teaching parameter has no LWE security claim")
    report = dict(root_generation=certificate, chain_plan=plan,
                  source_binary_sha256=sha256(Path(binary).read_bytes()).hexdigest(),
                  master_only_snapshot_bytes=len(raw), fresh_process=fresh,
                  n1_public_attack=attack, raw_kem_wire_bytes=len(capsule.to_bytes()),
                  public_attack_fixture=public_attack_fixture(oracle, receiver, sender, parsed, noise, seed),
                  original_identity_bytes=[3, 5], encoded_identity_bytes=86, seed_bytes=32,
                  repetitions=dict(root_generation=1, fresh_master_restore=1, public_attack=1),
                  total_diagnostic_seconds=time.monotonic()-started,
                  parent_leaf_generated=False, seven_method_hibe_implemented=False,
                  full_ibme_implemented=False, parameters_are_formal=False,
                  security_claim="none", backend_admitted=False)
    pending.unlink()
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "test-results/qfall-target/release/ibme-qfall-private-root")
    parser.add_argument("--private-directory", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--restore-only", type=Path)
    parser.add_argument("--attack-only", type=Path)
    args = parser.parse_args(argv)
    if args.attack_only is not None:
        print(canonical_json(attack_only(json.loads(args.attack_only.read_text(encoding="utf-8")))).decode())
        return 0
    if args.restore_only is not None:
        print(canonical_json(restore_only(args.restore_only)).decode())
        return 0
    if args.private_directory is None or args.output is None:
        parser.error("explicit private/output paths required")
    output, private = args.output.resolve(), args.private_directory.resolve()
    allowed = (ROOT / "test-results").resolve()
    if (not output.is_relative_to(allowed) or output == allowed
            or output.is_relative_to(private) or output.exists()):
        raise ValueError("new public output in test-results, outside the private directory, required")
    report = one_probe(args.binary, args.private_directory)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(report, indent=2)+"\n")
    print(canonical_json(dict(root_regular_upper=report["root_generation"]["root_regular_distance_upper_conditional"],
          fresh_master_restored=report["fresh_process"]["master_byte_equal"],
          n1_public_seed_recovered=report["n1_public_attack"]["unique_seed_recovered"],
          security_claim="none")).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
