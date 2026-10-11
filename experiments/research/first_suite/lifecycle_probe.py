"""Real H/G -> RandBasis -> durable 256-position key -> noisy seed wire pilot.

Public seeded teaching inputs only. Native Sage GPV and diagnostic LLL keep
their existing unadmitted status. Private snapshots/capsules are written only
to an explicit local directory; the public report stores counts and hashes.
This closes the fixed-seed lifecycle prerequisite, not the full HIBE/IBME.
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

from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.core.hashing import shake256
from ibme.core.randomness import DeterministicRandom
from ibme.protocol.hybrid_hibe import HybridLimits, encoded_identity

from .identity import ROHIBEContext, SEED_BITS
from .leaf_state import FixedSeedState, SeedAddressBlocked, SeedScope
from .seed_kem import SeedCapsule, decapsulate_seed, encapsulate_seed

EPSILON_BITS = 32
CONFIGS = ((17, 8), (257, 16), (1073741827, 48))


class CountedTestRandom:
    def __init__(self, label):
        self.source = DeterministicRandom(label)
        self.read_sizes = []

    def read(self, count):
        self.read_sizes.append(count)
        return self.source.read(count)


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def restore_only(manifest_path):
    manifest_path = Path(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    oracle = ROHIBEContext.from_bytes(bytes.fromhex(manifest["oracle_public_hex"]))
    scope = SeedScope(oracle, bytes.fromhex(manifest["receiver_hex"]),
                      Fraction(manifest["width_squared"]), bytes.fromhex(manifest["profile_hex"]))
    snapshot = (manifest_path.parent / manifest["snapshot_file"]).read_bytes()
    loaded = FixedSeedState.from_bytes(snapshot, expected_scope=scope)
    def no_sampling(_):
        raise RuntimeError("fresh-process restore attempted new private sampling")
    sender = bytes.fromhex(manifest["sender_hex"])
    key = loaded.resolve(sender, no_sampling)
    decoded = []
    for record in manifest["capsules"]:
        capsule = SeedCapsule.from_bytes((manifest_path.parent / record["file"]).read_bytes())
        seed = decapsulate_seed(key, capsule)
        decoded.append(dict(seed_hash_matches=sha256(seed).hexdigest() == record["expected_seed_sha256"],
                            recovered_seed_sha256=sha256(seed).hexdigest()))
    return dict(fixed_positions=len(key.preimages), new_private_draws=0,
                private_snapshot_byte_equal=loaded.to_bytes() == snapshot, recovered=decoded,
                native_sampler_loaded=False, security_claim="none", backend_admitted=False)


def one_probe(q, m_bar, binary, private_directory):
    from experiments.research.chkp_basis import ModMatrixReference, ext_basis
    from experiments.research.ibme_root_sampler_audit import checked_sage_lll, geometry
    from experiments.research.ibme_joint_parameters import evaluate_noise, smoothing_factor
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
    root_lengths, _ = geometry(root)
    if max(root_lengths) > root_bound:
        raise ArithmeticError("MP12 full-basis root GS bound failed")
    parent_width = 4 * root_bound * smoothing_factor(2 * m, EPSILON_BITS)
    leaf_width = 4 * parent_width * 2 * m * smoothing_factor(3 * m, EPSILON_BITS)
    noise_params = RoundedNoiseParams(q, Fraction(4, q), tail_bits=64, mass_bits=96, precision_bits=160)
    public_configuration = canonical_json(dict(
        version="FIRST-SUITE/PUBLIC-LIFECYCLE/1", depth=2, n=1, m=m, q=q,
        root_gs_squared_bound=root_bound, parent_width_squared=parent_width,
        leaf_width_squared=leaf_width, gpv_epsilon_bits=EPSILON_BITS,
        native_profile="SAGE-DGS-PUBLIC-COMPARISON/1", qfall_revision=QFALL_REV,
        noise=noise_params.to_record(), public_test_fixture=True,
        security_claim="none", backend_admitted=False, parameters_are_formal=False))
    oracle = ROHIBEContext(1, m, q, root.public.rows, public_configuration)
    limits = HybridLimits(backend_id=b"chkp-first-research")
    receiver = encoded_identity(b"Bob", limits, b"P")
    sender = encoded_identity(b"Alice", limits, b"C")

    print(canonical_json(dict(stage="parent_RandBasis", q=q, dimension=2 * m)).decode(), flush=True)
    parent_raw = ext_basis(root, ModMatrixReference(oracle.h((receiver,)), q))
    parent_sampler = NativePublicGPV(parent_raw, parent_width, public_test_fixture=True)
    parent, draws = parent_sampler.randomize_public_basis(test_seed=101, max_vectors=2 * m + 32)
    parent = checked_sage_lll(parent, parent_width * 2 * m)
    leaf = ext_basis(parent, ModMatrixReference(oracle.h((receiver, sender)), q))
    leaf = checked_sage_lll(leaf, parent_width * 2 * m)
    native = NativePublicGPV(leaf, leaf_width, public_test_fixture=True)
    profile = canonical_json(native.certificate())
    scope = SeedScope(oracle, receiver, Fraction(leaf_width), profile)
    state, generated = FixedSeedState(scope), []

    def generate(plan):
        if (plan.public_rows != leaf.public.rows or plan.scope.width_squared != leaf_width
                or plan.scope.sampler_profile != profile):
            raise InvalidParameterError("actual H/G plan differs from native sampler input")
        generated.append(1)
        return native.sample_batch(plan.targets, test_seed=202).preimages

    print(canonical_json(dict(stage="fixed_256_positions", q=q, dimension=3 * m)).decode(), flush=True)
    key = state.resolve(sender, generate)
    # Repeated issue is required to preserve all existing vectors and consume no
    # new entropy; the full snapshot is independently validated on restore.
    state.resolve(sender, lambda _: (_ for _ in ()).throw(AssertionError("repeat sampled")))
    snapshot = state.to_bytes()
    (private_directory / "private-seed-state.bin").write_bytes(snapshot)
    restored = FixedSeedState.from_bytes(snapshot, expected_scope=scope)
    if restored.lookup(sender).preimages != key.preimages:
        raise ArithmeticError("private fixed vectors changed after canonical restore")

    noise = build_rounded_noise(noise_params)
    seeds = (b"\0" * 32, b"\xff" * 32, shake256(b"FIRST-SUITE/SEED-FIXTURE/1", label, 32))
    records, capsules = [], []
    for index, seed in enumerate(seeds):
        source = CountedTestRandom(label + b":encapsulation:" + bytes([index]))
        capsule = encapsulate_seed(oracle, receiver, sender, seed, noise, rng=source)
        raw = capsule.to_bytes()
        reloaded_capsule = SeedCapsule.from_bytes(raw)
        recovered = decapsulate_seed(restored.lookup(sender), reloaded_capsule)
        recovered_bits = sum((a ^ b).bit_count() for a, b in zip(seed, recovered))
        records.append(dict(seed_sha256=sha256(seed).hexdigest(), bit_errors=recovered_bits,
                            correct=recovered == seed, ciphertext_bytes=len(raw),
                            expected_noise_scalar_calls=3 * m + SEED_BITS,
                            counted_noise_scalar_calls=source.read_sizes.count(noise.draw_bytes),
                            entropy_bytes=sum(source.read_sizes)))
        filename = f"capsule-{index}.bin"
        (private_directory / filename).write_bytes(raw)
        capsules.append(dict(file=filename, expected_seed_sha256=sha256(seed).hexdigest()))
    wrong = []
    for rcv, snd in ((b"Carol", b"Alice"), (b"Bob", b"Mallory"), (b"Carol", b"Mallory")):
        wrong_capsule = encapsulate_seed(oracle, encoded_identity(rcv, limits, b"P"),
                         encoded_identity(snd, limits, b"C"), seeds[2], noise,
                         rng=CountedTestRandom(label + b":wrong:" + rcv + b":" + snd))
        wrong.append(dict(receiver_matches=rcv == b"Bob", sender_matches=snd == b"Alice",
                          raw_seed_differs=decapsulate_seed(key, wrong_capsule) != seeds[2],
                          raw_kem_returns_bottom=False))

    rejected = 0
    for malformed in (raw[:-1], raw + b"\0", b"X" + raw[1:]):
        try:
            SeedCapsule.from_bytes(malformed)
        except SerializationError:
            rejected += 1
    # Isolated forced interruption of a second identity, without drawing another
    # real native key; this is a lifecycle test, not a sampling failure estimate.
    failed_sender = encoded_identity(b"Failed", limits, b"C")
    def interrupt(_):
        raise KeyboardInterrupt("forced address interruption")
    try:
        state.resolve(failed_sender, interrupt)
    except KeyboardInterrupt:
        pass
    failed_snapshot = state.to_bytes()
    resumed = FixedSeedState.from_bytes(failed_snapshot, expected_scope=scope)
    tombstone_blocks = False
    try:
        resumed.resolve(failed_sender, lambda _: (_ for _ in ()).throw(AssertionError("failure retried")))
    except SeedAddressBlocked:
        tombstone_blocks = True

    manifest = dict(oracle_public_hex=oracle.to_bytes().hex(), receiver_hex=receiver.hex(),
                    sender_hex=sender.hex(), width_squared=str(leaf_width), profile_hex=profile.hex(),
                    snapshot_file="private-seed-state.bin", capsules=capsules, public_test_fixture=True)
    manifest_path = private_directory / "public-restore-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    child = subprocess.run([sys.executable, "-m", "experiments.research.first_suite.lifecycle_probe",
                            "--restore-only", str(manifest_path)], cwd=ROOT,
                           capture_output=True, text=True, timeout=60)
    if child.returncode:
        raise RuntimeError("fresh-process private restore failed: " + child.stderr[:500])
    fresh = json.loads(child.stdout)
    conditional_noise = evaluate_noise(q=q, dimension=3 * m, width_squared=leaf_width,
                                       alpha=Fraction(4, q), error_bits=32,
                                       seed_bits=SEED_BITS, encapsulations=len(seeds))
    return dict(q=q, n=1, m_bar=m_bar, k=k, dimensions=dict(root=m, parent=2 * m, leaf=3 * m),
                public_test_seed=label.decode(), public_configuration_sha256=sha256(public_configuration).hexdigest(),
                parent_width_squared=parent_width, leaf_width_squared=leaf_width,
                parent_native_vectors=draws, terminal_second_randbasis=False,
                real_H_G_used=True, ordered_identity_bytes=[len(receiver), len(sender)],
                original_identity_bytes=[3, 5], fixed_positions=SEED_BITS,
                distinct_syndrome_values=len(set(key.plan.targets)),
                private_generations=len(generated), native_private_vectors=native.draws,
                canonical_private_snapshot_bytes=len(snapshot),
                private_snapshot_sha256=sha256(snapshot).hexdigest(), failure_tombstone_recovered=tombstone_blocks,
                fresh_process=fresh, capsules=records, wrong_identity_raw_kem=wrong,
                malformed_capsules_rejected=rejected, total_bit_errors=sum(r["bit_errors"] for r in records),
                rounded_noise=noise.certificate(), conditional_noise=conditional_noise,
                native_sampler=native.certificate(), diagnostic_total_seconds=time.monotonic() - started,
                security_claim="none", backend_admitted=False, parameters_are_formal=False,
                full_hibe_backend_implemented=False, full_ibme_combination_implemented=False,
                outstanding=["formal dimension/LWE cost and root near-uniformity", "production native RNG and finite-error/resource admission",
                             "master/parent issuance and complete seven-method HIBE", "byte framing/AEAD/IBS/BYTEAUTH integration and full attacks"])


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
        parser.error("predeclared q, explicit output and local private directory required")
    report = one_probe(*config, args.binary, args.private_directory)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(canonical_json(dict(q=report["q"], fixed_positions=report["fixed_positions"],
                             total_bit_errors=report["total_bit_errors"],
                             diagnostic_total_seconds=report["diagnostic_total_seconds"])).decode(), flush=True)
    # Small q runs are explicit negative correctness controls, not failed jobs
    # disguised as positive systems. All actual counts remain in the report.
    return 0 if report["failure_tombstone_recovered"] and report["fresh_process"]["new_private_draws"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
