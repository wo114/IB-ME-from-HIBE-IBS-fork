"""Unchanged exact-Schur/JSON 3m comparator at the SAME executable n2/q40 group.

Measures only root/parent/fixed leaf, as does blocked_3m_probe. This is not
old-IBME vs new-IBME timing. Uses its own fresh CSPRNG state and one attempt.
"""

import argparse
from pathlib import Path
import json
import hashlib
from unittest.mock import patch

from ibme.core.randomness import SecureRandom
from ibme.hibe.mp12_structured.blocked_prototype import PrototypeParams, canonical, read_record
from ibme.lattice.matrix_sampling.mp12_structured import generate_structured_root, StructuredTrapdoor
from ibme.lattice.matrix_sampling.mp12_extension import delegate_extension, StructuredLeftSampler
from ibme.lattice.chkp.identity import ROHIBEContext
from ibme.lattice.chkp.leaf_state import SeedScope, FixedSeedState
from ibme.lattice.chkp.entropy import CheckedEntropy
from .blocked_3m_probe import CountedSystem, save, RECEIVER, SENDER, providers
from .runtime_metrics import measured_phase, environment


def restore(directory):
    """Read-only continuation after a probe failure; never reissue its slot."""
    files = [directory/name for name in ("context.bin", "root.bin", "parent.bin", "leaf.bin")]
    before = [hashlib.sha256(path.read_bytes()).digest() for path in files]
    calls = 0
    def forbidden(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("reference restore attempted entropy")
    with patch.object(SecureRandom, "read", forbidden):
        context = ROHIBEContext.from_bytes(files[0].read_bytes())
        p = PrototypeParams(**read_record(context.public_configuration)["parameters"])
        scope = SeedScope(context, RECEIVER, p.leaf_width_squared, canonical(p.record()), max_children=1)
        root = StructuredTrapdoor.from_bytes(files[1].read_bytes())
        parent = StructuredTrapdoor.from_bytes(files[2].read_bytes())
        leaf = FixedSeedState.from_bytes(files[3].read_bytes(), expected_scope=scope)
        if root.public.rows != context.root_rows or parent.public.rows != context.parent_rows(RECEIVER):
            raise ValueError("reference restored public binding")
        if leaf.to_bytes() != files[3].read_bytes(): raise ValueError("reference noncanonical leaf state")
    if before != [hashlib.sha256(path.read_bytes()).digest() for path in files]:
        raise ValueError("reference restore modified original state")
    return dict(status="passed", entropy_reads=calls, new_roots=0, new_parents=0,
                new_preimages=0, fixed_preimages_checked=256, original_state_unchanged=True)


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
            restored = restore(directory)
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
    parser.add_argument("--restore-only", action="store_true")
    args = parser.parse_args()
    if args.restore_only:
        phases = []
        with measured_phase("strict-object-restore", phases): result = restore(args.private_directory)
        result.update(schema="MP12-3M-REFERENCE-RESTORE-CONTINUATION/1", source_commit=args.source_commit,
            phases=phases, source_providers=providers(), pending_state_preserved=True)
        save(args.private_directory/"restore-receipt.json", result)
        print(json.dumps(dict(status=result["status"], new_preimages=0, entropy_reads=result["entropy_reads"])), flush=True)
    else:
        run(args.private_directory, args.source_commit)


if __name__ == "__main__": main()
