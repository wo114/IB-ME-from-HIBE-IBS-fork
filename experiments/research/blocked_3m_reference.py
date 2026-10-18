"""Unchanged exact-Schur/JSON 3m comparator at the SAME executable n2/q40 group.

Measures only root/parent/fixed leaf, as does blocked_3m_probe. This is not
old-IBME vs new-IBME timing. Uses its own fresh CSPRNG state and one attempt.
"""

import argparse
from pathlib import Path
import json
from unittest.mock import patch

from ibme.core.randomness import SecureRandom
from ibme.hibe.mp12_structured.blocked_prototype import PrototypeParams, canonical
from ibme.lattice.matrix_sampling.mp12_structured import generate_structured_root, StructuredTrapdoor
from ibme.lattice.matrix_sampling.mp12_extension import delegate_extension, StructuredLeftSampler
from ibme.lattice.chkp.identity import ROHIBEContext
from ibme.lattice.chkp.leaf_state import SeedScope, FixedSeedState
from ibme.lattice.chkp.entropy import CheckedEntropy
from .blocked_3m_probe import CountedSystem, save, RECEIVER, SENDER, providers
from .runtime_metrics import measured_phase, environment


def run(directory, source_commit):
    directory.mkdir(parents=True, exist_ok=False)
    p = PrototypeParams(q=1099511627689)
    phases, source = [], CountedSystem()
    report = dict(schema="MP12-3M-EXACT-SCHUR-REFERENCE/1", status="started", source_commit=source_commit,
        parameters=p.record(), environment=environment(), phases=phases, repetitions=1,
        scope="unchanged exact Schur/JSON root-parent-leaf tool path, not full KEM or IBME",
        identity_bytes=86, payload_seed_bytes=32, uses_ROM=True, system_randomness=True,
        security_claim="none", backend_admitted=False, parameters_are_formal=False)
    stage = "root"
    try:
        save(directory/"generation.pending", b"one attempt; no retry on failure\n")
        before = source.bytes
        with measured_phase("root-generation", phases) as row:
            root = generate_structured_root(p.n, p.q, p.root_r_squared, options=p.options(), rng=source)
            row["entropy_bytes"] = source.bytes-before
        context = ROHIBEContext(p.n, p.m, p.q, root.public.rows, canonical(p.record()), identity_bytes=86)
        with measured_phase("root-persistence", phases):
            save(directory/"root.bin", root.to_bytes())
            save(directory/"context.bin", context.to_bytes())
        stage = "parent"; before = source.bytes
        with measured_phase("parent-delegation", phases) as row:
            parent = delegate_extension(root, context.h((RECEIVER,)), options=p.options(),
                epsilon_bits=p.epsilon_bits, rng=source)
            row["entropy_bytes"] = source.bytes-before
        with measured_phase("parent-persistence", phases): save(directory/"parent.bin", parent.to_bytes())
        print("reference parent passed", flush=True)
        stage = "leaf"
        with measured_phase("leaf-sampler-preparation", phases):
            sampler = StructuredLeftSampler(parent, context.h((RECEIVER, SENDER)),
                options=p.options(), epsilon_bits=p.epsilon_bits)
            assert sampler.dimension == 3*p.m and sampler.output_squared == p.leaf_width_squared
        state = FixedSeedState(SeedScope(context, RECEIVER, p.leaf_width_squared, canonical(p.record()), max_children=1))
        before = source.bytes
        with measured_phase("leaf-256-sampling", phases) as row:
            entropy = CheckedEntropy(source, p.entropy_cap_bytes)
            state.resolve(SENDER, lambda plan: tuple(sampler.sample(target, rng=entropy) for target in plan.targets))
            row["entropy_bytes"] = source.bytes-before
        with measured_phase("leaf-persistence", phases): save(directory/"leaf.bin", state.to_bytes())
        with measured_phase("strict-object-restore", phases):
            def forbidden(*args, **kwargs): raise AssertionError("reference restore consumed entropy")
            with patch.object(SecureRandom, "read", forbidden):
                restored = FixedSeedState.from_bytes((directory/"leaf.bin").read_bytes())
                assert restored.to_bytes() == state.to_bytes()
                assert StructuredTrapdoor.from_bytes(root.to_bytes()).to_bytes() == root.to_bytes()
                assert StructuredTrapdoor.from_bytes(parent.to_bytes()).to_bytes() == parent.to_bytes()
        report.update(status="passed", entropy_bytes=source.bytes,
            source_providers=providers(), sampler=sampler.public_certificate(),
            sizes={name:(directory/name).stat().st_size for name in ("root.bin", "parent.bin", "leaf.bin", "context.bin")},
            leaf_schur_dimension=sampler.inner.trapdoor.prefix,
            parent_R_json_decimal_bytes=len(json.dumps(parent.r, separators=(",", ":")).encode("ascii")))
        save(directory/"receipt.json", report)
        (directory/"generation.pending").rename(directory/"generation.done")
        print("reference fixed leaf and restore passed", flush=True)
        return report
    except BaseException as exc:
        report.update(status="failed", failure_stage=stage, exception_type=type(exc).__name__, pending_preserved=True)
        save(directory/"failure.json", report)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-directory", type=Path, required=True)
    parser.add_argument("--source-commit", default="development")
    args = parser.parse_args()
    run(args.private_directory, args.source_commit)


if __name__ == "__main__": main()
