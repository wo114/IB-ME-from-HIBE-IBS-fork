"""Real qFALL/CHKP master -> parent -> fixed leaf -> private restore pilot.

Uses exactly the seed-lifecycle public context/configuration and predeclared
test streams, now through owned master/parent objects. Native seeded sampling
and diagnostic LLL remain unadmitted; no production or full HIBE is claimed.
"""

import argparse
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from ibme.core.errors import InvalidParameterError
from ibme.core.hashing import shake256
from ibme.protocol.hybrid_hibe import HybridLimits, encoded_identity

from .delegation_state import DelegationScope, MasterTreeState, ParentAddressBlocked, ReceiverState
from .identity import ROHIBEContext
from .leaf_state import SeedAddressBlocked
from .lifecycle_probe import CONFIGS, CountedTestRandom, EPSILON_BITS, canonical_json
from .seed_kem import SeedCapsule, decapsulate_seed, encapsulate_seed

PARENT_PROFILE = b"SAGE-DGS-PUBLIC-COMPARISON/1; epsilon32/MPFR192/tau12; parent RandBasis + checked diagnostic LLL"
LEAF_PROFILE = b"SAGE-DGS-PUBLIC-COMPARISON/1; epsilon32/MPFR192/tau12; extended-parent SampleD256"


def no_generation(plan):
    raise RuntimeError("restored/cached tree attempted private generation")


def restore_only(path):
    path = Path(path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    oracle = ROHIBEContext.from_bytes(bytes.fromhex(manifest["oracle_hex"]))
    scope = DelegationScope(oracle, Fraction(manifest["root_bound"]), Fraction(manifest["parent_width"]),
                            Fraction(manifest["leaf_width"]), PARENT_PROFILE, LEAF_PROFILE)
    master_raw = (path.parent / "master-tree.bin").read_bytes()
    receiver_raw = (path.parent / "receiver-key.bin").read_bytes()
    tree = MasterTreeState.from_bytes(master_raw, expected_scope=scope)
    receiver = bytes.fromhex(manifest["receiver_hex"])
    sender = bytes.fromhex(manifest["sender_hex"])
    parent = tree.issue(receiver, no_generation)
    key = parent.derive(sender, no_generation)
    standalone = ReceiverState.from_bytes(receiver_raw, expected_scope=scope, expected_identity=receiver)
    equal = standalone.derive(sender, no_generation).preimages == key.preimages
    capsule = SeedCapsule.from_bytes((path.parent / "capsule.bin").read_bytes())
    seed = decapsulate_seed(key, capsule)
    blocked_parent = blocked_leaf = False
    try: tree.issue(bytes.fromhex(manifest["failed_receiver_hex"]), no_generation)
    except ParentAddressBlocked: blocked_parent = True
    try: parent.derive(bytes.fromhex(manifest["failed_sender_hex"]), no_generation)
    except SeedAddressBlocked: blocked_leaf = True
    return dict(master_snapshot_byte_equal=tree.to_bytes() == master_raw,
                receiver_snapshot_byte_equal=parent.to_bytes() == receiver_raw,
                standalone_receiver_vectors_equal=equal, fixed_positions=len(key.preimages),
                recovered_seed_sha256=sha256(seed).hexdigest(),
                seed_hash_matches=sha256(seed).hexdigest() == manifest["seed_sha256"],
                new_parent_generations=0, new_leaf_generations=0,
                parent_failure_tombstone_blocked=blocked_parent, leaf_failure_tombstone_blocked=blocked_leaf,
                native_sampler_module_loaded="experiments.research.reuse.sage_native_gpv" in sys.modules,
                security_claim="none", backend_admitted=False)


def one_probe(q, m_bar, binary, private_directory):
    from experiments.research.chkp_basis import ModMatrixReference, ext_basis
    from experiments.research.ibme_joint_parameters import smoothing_factor
    from experiments.research.ibme_root_sampler_audit import checked_sage_lll
    from experiments.research.ibme_noise_budget import RoundedNoiseParams
    from experiments.research.ibme_rounded_noise import build_rounded_noise
    from experiments.research.reuse.qfall_bridge import QFALL_REV, public_fixture, run_fixture, validate_root
    from experiments.research.reuse.sage_native_gpv import NativePublicGPV

    if (q, m_bar) not in CONFIGS:
        raise InvalidParameterError("predeclared public teaching configuration required")
    started = time.monotonic()
    private_directory = Path(private_directory)
    private_directory.mkdir(parents=True, exist_ok=True)
    label = f"first-suite-real-hg-q{q}-bar{m_bar}".encode()
    fixture = public_fixture(1, q, m_bar, seed=label)
    root = validate_root(fixture, run_fixture(fixture, binary))
    m, k = root.public.ncols, (q - 1).bit_length()
    root_bound = 10 * (1 + m_bar * k)
    parent_width = 4 * root_bound * smoothing_factor(2 * m, EPSILON_BITS)
    leaf_width = 4 * parent_width * 2 * m * smoothing_factor(3 * m, EPSILON_BITS)
    noise_params = RoundedNoiseParams(q, Fraction(4, q), tail_bits=64, mass_bits=96, precision_bits=160)
    public_config = canonical_json(dict(
        version="FIRST-SUITE/PUBLIC-LIFECYCLE/1", depth=2, n=1, m=m, q=q,
        root_gs_squared_bound=root_bound, parent_width_squared=parent_width,
        leaf_width_squared=leaf_width, gpv_epsilon_bits=EPSILON_BITS,
        native_profile="SAGE-DGS-PUBLIC-COMPARISON/1", qfall_revision=QFALL_REV,
        noise=noise_params.to_record(), public_test_fixture=True,
        security_claim="none", backend_admitted=False, parameters_are_formal=False))
    oracle = ROHIBEContext(1, m, q, root.public.rows, public_config)
    scope = DelegationScope(oracle, Fraction(root_bound), Fraction(parent_width), Fraction(leaf_width),
                            PARENT_PROFILE, LEAF_PROFILE)
    tree = MasterTreeState(scope, root)
    limits = HybridLimits(backend_id=b"chkp-first-research")
    receiver, sender = encoded_identity(b"Bob", limits, b"P"), encoded_identity(b"Alice", limits, b"C")
    parent_calls, leaf_calls, profiles = [], [], {}

    def parent_generate(plan):
        raw = ext_basis(plan.root_basis, ModMatrixReference(plan.scope.oracle.h((plan.receiver,)), q))
        sampler = NativePublicGPV(raw, parent_width, public_test_fixture=True)
        randomized, draws = sampler.randomize_public_basis(test_seed=101, max_vectors=2 * m + 32)
        parent_calls.append(draws)
        profiles["parent"] = sampler.certificate()
        return checked_sage_lll(randomized, parent_width * 2 * m)

    def leaf_generate(plan):
        p = plan.seed_plan
        raw = ext_basis(plan.parent_basis, ModMatrixReference(p.scope.oracle.h((p.scope.receiver, p.sender)), q))
        if raw.public.rows != p.public_rows or p.scope.width_squared != leaf_width:
            raise InvalidParameterError("leaf plan differs from actual H/G and width")
        raw = checked_sage_lll(raw, parent_width * 2 * m)
        sampler = NativePublicGPV(raw, leaf_width, public_test_fixture=True)
        leaf_calls.append(1)
        profiles["leaf"] = sampler.certificate()
        return sampler.sample_batch(p.targets, test_seed=202).preimages

    print(canonical_json(dict(stage="owned_parent", q=q, dimension=2 * m)).decode(), flush=True)
    parent = tree.issue(receiver, parent_generate)
    tree.issue(receiver, no_generation)
    print(canonical_json(dict(stage="owned_leaf256", q=q, dimension=3 * m)).decode(), flush=True)
    key = parent.derive(sender, leaf_generate)
    parent.derive(sender, no_generation)
    failed_receiver = encoded_identity(b"FailedR", limits, b"P")
    failed_sender = encoded_identity(b"FailedS", limits, b"C")
    def interrupt(plan): raise KeyboardInterrupt("forced private generation interruption")
    try: tree.issue(failed_receiver, interrupt)
    except KeyboardInterrupt: pass
    try: parent.derive(failed_sender, interrupt)
    except KeyboardInterrupt: pass
    master_raw, receiver_raw = tree.to_bytes(), parent.to_bytes()
    reloaded = MasterTreeState.from_bytes(master_raw, expected_scope=scope)
    recovered_key = reloaded.issue(receiver, no_generation).derive(sender, no_generation)
    if recovered_key.preimages != key.preimages:
        raise ArithmeticError("master restore changed fixed child vectors")
    seed = shake256(b"FIRST-SUITE/SEED-FIXTURE/1", label, 32)
    noise = build_rounded_noise(noise_params)
    source = CountedTestRandom(label + b":encapsulation:" + b"\x02")
    capsule = encapsulate_seed(oracle, receiver, sender, seed, noise, rng=source)
    recovered_seed = decapsulate_seed(recovered_key, SeedCapsule.from_bytes(capsule.to_bytes()))
    bit_errors = sum((a ^ b).bit_count() for a, b in zip(seed, recovered_seed))
    (private_directory / "master-tree.bin").write_bytes(master_raw)
    (private_directory / "receiver-key.bin").write_bytes(receiver_raw)
    (private_directory / "capsule.bin").write_bytes(capsule.to_bytes())
    manifest = dict(oracle_hex=oracle.to_bytes().hex(), receiver_hex=receiver.hex(), sender_hex=sender.hex(),
                    failed_receiver_hex=failed_receiver.hex(), failed_sender_hex=failed_sender.hex(),
                    root_bound=str(root_bound), parent_width=str(parent_width), leaf_width=str(leaf_width),
                    seed_sha256=sha256(seed).hexdigest(), public_test_fixture=True)
    manifest_path = private_directory / "public-restore-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    # Preserve completed generation evidence before the separate restore job.
    # If observation/restore fails, inspect these snapshots rather than draw
    # another parent/leaf key or silently rerun the generator.
    receipt = dict(q=q, n=1, dimensions=[m, 2 * m, 3 * m], parent_generations=len(parent_calls),
                   parent_native_draws=parent_calls, leaf_generations=len(leaf_calls),
                   fixed_leaf_vectors=len(key.preimages), seed_bit_errors=bit_errors,
                   whole_master_snapshot_bytes=len(master_raw), receiver_snapshot_bytes=len(receiver_raw),
                   master_snapshot_sha256=sha256(master_raw).hexdigest(),
                   receiver_snapshot_sha256=sha256(receiver_raw).hexdigest(),
                   sampler_profiles=profiles, generation_and_in_process_restore_seconds=time.monotonic() - started,
                   security_claim="none", backend_admitted=False, parameters_are_formal=False)
    (private_directory / "public-generation-receipt.json").write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    child = subprocess.run([sys.executable, "-m", "experiments.research.first_suite.tree_probe",
                            "--restore-only", str(manifest_path)], cwd=ROOT,
                           capture_output=True, text=True, timeout=60)
    if child.returncode: raise RuntimeError("fresh master/receiver restore failed: " + child.stderr[:500])
    fresh = json.loads(child.stdout)
    return dict(q=q, n=1, m_bar=m_bar, dimensions=[m, 2 * m, 3 * m],
                original_identity_bytes=[3, 5], encoded_identity_bytes=86, seed_bits=256,
                parent_generations=len(parent_calls), parent_native_draws=parent_calls,
                leaf_generations=len(leaf_calls), fixed_leaf_vectors=len(key.preimages),
                parent_gs_squared_public_bound=str(scope.parent_gs_squared_bound),
                whole_master_snapshot_bytes=len(master_raw), receiver_snapshot_bytes=len(receiver_raw),
                master_snapshot_sha256=sha256(master_raw).hexdigest(), receiver_snapshot_sha256=sha256(receiver_raw).hexdigest(),
                raw_kem_wire_bytes=len(capsule.to_bytes()), seed_bit_errors=bit_errors,
                recovered_seed_sha256=sha256(recovered_seed).hexdigest(), fresh_process=fresh,
                actual_noise_calls=source.read_sizes.count(noise.draw_bytes), expected_noise_calls=3 * m + 256,
                sampler_profiles=profiles, rounded_noise=noise.certificate(),
                total_diagnostic_seconds=time.monotonic() - started,
                security_claim="none", backend_admitted=False, parameters_are_formal=False,
                seven_method_hibe_implemented=False, full_ibme_implemented=False,
                unresolved=["real difficulty/root regularity and same-parameter admission", "native production RNG/error/resources",
                            "unique disk owner/publication and rollback model", "HIBE byte/public-key objects/interface and protocol integration"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "test-results/qfall-target/release/ibme-qfall-public-fixture")
    parser.add_argument("--only-q", type=int, default=1073741827)
    parser.add_argument("--private-directory", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--restore-only", type=Path)
    args = parser.parse_args(argv)
    if args.restore_only is not None:
        print(canonical_json(restore_only(args.restore_only)).decode())
        return 0
    config = next((row for row in CONFIGS if row[0] == args.only_q), None)
    if config is None or args.output is None or args.private_directory is None:
        parser.error("predeclared q and explicit private/output paths required")
    report = one_probe(*config, args.binary, args.private_directory)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(canonical_json(dict(q=report["q"], seed_bit_errors=report["seed_bit_errors"],
                             total_diagnostic_seconds=report["total_diagnostic_seconds"])).decode(), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
