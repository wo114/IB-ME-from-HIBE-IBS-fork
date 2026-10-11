"""Actual 237-dimension finite/CSPRNG leaf comparison on saved public fixture.

Reuses the existing explicit public-test parent, never redraws it. New leaf
samples use independent OS bytes with finite error/tape certificates. The
input parent/root still have their earlier unadmitted provenance; this is not
a full production CHKP/IBME claim. Private outputs stay in test-results.
"""

import argparse
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from sage.all import QQ
from ibme.core.randomness import SecureRandom
from experiments.research.chkp_basis import ModMatrixReference, ext_basis
from experiments.research.ibme_root_sampler_audit import checked_sage_lll
from experiments.research.ibme_noise_budget import RoundedNoiseParams
from experiments.research.ibme_rounded_noise import build_rounded_noise

from .identity import Reader, ROHIBEContext
from .delegation_state import DelegationScope, ReceiverState, PARENT_MAGIC, _load_basis
from .tree_probe import PARENT_PROFILE, LEAF_PROFILE
from .leaf_state import SeedScope, FixedSeedState
from .seed_kem import encapsulate_seed, decapsulate_seed
from .finite_gpv import FirstFiniteGPV
from .finite_gaussian import FirstFiniteOptions


class CountedOS:
    def __init__(self):
        self.source, self.bytes_used, self.calls = SecureRandom(), 0, 0
    def read(self, count):
        data = self.source.read(count)
        self.bytes_used += count
        self.calls += 1
        return data


def probe(manifest_path, output_directory):
    started = time.monotonic()
    manifest_path, output_directory = Path(manifest_path), Path(output_directory)
    m = json.loads(manifest_path.read_text(encoding="utf-8"))
    if m.get("public_test_fixture") is not True:
        raise ValueError("only the prior explicit public-test fixture may be published")
    o = ROHIBEContext.from_bytes(bytes.fromhex(m["oracle_hex"]))
    receiver, sender = bytes.fromhex(m["receiver_hex"]), bytes.fromhex(m["sender_hex"])
    scope = DelegationScope(o, Fraction(m["root_bound"]), Fraction(m["parent_width"]),
                            Fraction(m["leaf_width"]), PARENT_PROFILE, LEAF_PROFILE)
    parent_raw = (manifest_path.parent / "receiver-key.bin").read_bytes()
    ReceiverState.from_bytes(parent_raw, expected_scope=scope, expected_identity=receiver)
    # Primitive-side extraction of our own mathematical private format. The
    # protocol layer never accesses these integer matrices.
    r = Reader(parent_raw)
    r.take(len(PARENT_MAGIC)); r.blob(16 * 2**20); r.blob(256)
    parent = _load_basis(r.blob(16 * 2**20), o.parent_rows(receiver), o.q)
    r.blob(16 * 2**20); r.finish()
    leaf = ext_basis(parent, ModMatrixReference(o.h((receiver, sender)), o.q))
    leaf = checked_sage_lll(leaf, QQ(m["parent_width"]) * parent.public.ncols)
    print(json.dumps(dict(stage="finite_constructor", dimension=leaf.public.ncols)), flush=True)
    sampler = FirstFiniteGPV(leaf, QQ(m["leaf_width"]), epsilon_bits=128)
    cert = sampler.certificate()
    # All 256 outputs share one explicit finite whole-batch entropy bound.
    batch_tape = sampler.random_tape_bytes * 256
    if batch_tape > 2**40:
        raise ValueError("whole finite leaf batch exceeds the explicit 1TiB worst-byte bound")
    source = CountedOS()
    profile = json.dumps(dict(profile=cert["profile"], epsilon_bits=128,
                               options=FirstFiniteOptions().__dict__), sort_keys=True).encode()
    state = FixedSeedState(SeedScope(o, receiver, Fraction(m["leaf_width"]), profile))
    def generate(plan):
        if plan.public_rows != leaf.public.rows:
            raise ValueError("real H/G plan differs from finite sampler matrix")
        return tuple(sampler.sample(target, rng=source) for target in plan.targets)
    print(json.dumps(dict(stage="finite_256_samples", vector_tape=sampler.random_tape_bytes,
                          batch_tape=batch_tape)), flush=True)
    key = state.resolve(sender, generate)
    noise = build_rounded_noise(RoundedNoiseParams(o.q, Fraction(4, o.q), tail_bits=64, mass_bits=96, precision_bits=160))
    cases = []
    for _ in range(2):
        seed_source = CountedOS()
        seed = seed_source.read(32)
        capsule = encapsulate_seed(o, receiver, sender, seed, noise, rng=seed_source)
        recovered = decapsulate_seed(key, capsule)
        cases.append(dict(bit_errors=sum((a ^ b).bit_count() for a, b in zip(seed, recovered)),
                          seed_sha256=sha256(seed).hexdigest(), recovered_sha256=sha256(recovered).hexdigest(),
                          source_bytes=seed_source.bytes_used, ciphertext_bytes=len(capsule.to_bytes())))
    snapshot = state.to_bytes()
    restored = FixedSeedState.from_bytes(snapshot, expected_scope=state.scope)
    def no_sampling(plan): raise RuntimeError("finite key restore attempted resampling")
    assert restored.resolve(sender, no_sampling).preimages == key.preimages
    output_directory.mkdir(parents=True, exist_ok=True)
    (output_directory / "private-finite-leaf-state.bin").write_bytes(snapshot)
    certificate_path = output_directory / "public-fixture-finite-certificate.json"
    certificate_path.write_text(json.dumps(cert, indent=2) + "\n", encoding="utf-8")
    widths = [QQ(p["squared_width_class"][0]) for p in cert["per_coordinate_profiles"]]
    return dict(n=o.n, q=o.q, dimension=leaf.public.ncols, width_squared=m["leaf_width"],
                source_parent_snapshot_sha256=sha256(parent_raw).hexdigest(),
                new_parent_generations=0, new_leaf_samples=len(key.preimages),
                scalar_width_squared_min=str(min(widths)), scalar_width_squared_max=str(max(widths)),
                native_Sage_rng_used=False, randomness="OS CSPRNG; no test seed supplied to finite sampler",
                finite_profile=cert["profile"], epsilon_bits=128,
                geometry_tv_upper=cert["geometry_tv_upper"], scalar_tv_upper_sum=cert["scalar_tv_upper_sum"],
                per_vector_tv_including_abort=cert["tv_upper_including_abort"],
                batch_tv_including_abort=str(min(QQ(1), 256 * QQ(cert["tv_upper_including_abort"]))),
                worst_vector_entropy_bytes=sampler.random_tape_bytes, worst_batch_entropy_bytes=batch_tape,
                actual_entropy_bytes=source.bytes_used, actual_entropy_calls=source.calls,
                fixed_state_snapshot_bytes=len(snapshot), fixed_state_restore_vector_equal=True,
                certificate_sha256=sha256(certificate_path.read_bytes()).hexdigest(),
                honest_rounded_noise=cases, whole_runtime_seconds=time.monotonic() - started,
                parent_is_prior_public_test_native_fixture=True, full_hibe_or_ibme_admitted=False,
                security_claim="none", backend_admitted=False, parameters_are_formal=False,
                unclosed=["root/parent generation and regularity", "full formal parameter/LWE and resource chain",
                          "HIBE seven-method/byte/CLI and full composition", "side-channel/constant-time implementation"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--private-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    result = probe(args.manifest, args.private_directory)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key:result[key] for key in ["dimension", "new_leaf_samples", "actual_entropy_bytes", "whole_runtime_seconds"]}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
