"""Real wide-q CHKP 3m root -> parent -> fixed 256-target leaf measurements.

Explicit NEW ignored private directory, system CSPRNG, one occupied attempt.
Only the receipt is public. Restore-only forbids generation and entropy and
checks the existing independently serialized root, parent and fixed leaf.
"""

import argparse
from dataclasses import asdict
import hashlib
import json
from math import isqrt
import os
from pathlib import Path
import sys
import time
from unittest.mock import patch

from ibme.core.randomness import SecureRandom
from ibme.lattice.chkp.entropy import CheckedEntropy
from ibme.lattice.matrix_sampling.packed import PackedMatrix
from ibme.lattice.matrix_sampling.mp12_blocked import generate_root, delegate, BlockedPreimageSampler
from ibme.hibe.mp12_structured.blocked_prototype import (
    PrototypeParams, PrototypeContext, dump_trapdoor, load_trapdoor, dump_leaf, load_leaf,
)
from .runtime_metrics import measured_phase, environment

RECEIVER, SENDER = b"B"*86, b"A"*86


class CountedSystem:
    def __init__(self): self.source, self.bytes, self.reads = SecureRandom(), 0, 0
    def read(self, count):
        raw = self.source.read(count)
        self.bytes += len(raw); self.reads += 1
        return raw


def save(path, raw):
    if type(raw) is not bytes: raw = (json.dumps(raw, indent=2, sort_keys=True)+"\n").encode("utf-8")
    temp = path.with_name(path.name+".writing")
    with temp.open("xb") as stream:
        os.chmod(temp, 0o600)
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    os.replace(temp, path)
    fd = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)


def restore(directory, *, packing=None):
    packing = {} if packing is None else packing
    paths = [directory/name for name in ("context.bin", "root.bin", "parent.bin", "leaf.bin")]
    before = [hashlib.sha256(p.read_bytes()).digest() for p in paths]
    calls = 0
    def forbidden(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("blocked restore attempted generation or entropy")
    with patch.object(SecureRandom, "read", forbidden), patch.object(BlockedPreimageSampler, "sample", forbidden):
        context = PrototypeContext.from_bytes(paths[0].read_bytes())
        root = load_trapdoor(paths[1].read_bytes(), context, **packing)
        parent = load_trapdoor(paths[2].read_bytes(), context, RECEIVER, **packing)
        leaf = load_leaf(paths[3].read_bytes(), context, RECEIVER, SENDER, **packing)
        assert root.dimension == context.m and parent.dimension == 2*context.m
        assert leaf.nrows == 3*context.m and leaf.ncols == 256
    assert before == [hashlib.sha256(p.read_bytes()).digest() for p in paths]
    return dict(status="passed", entropy_reads=calls, new_roots=0, new_parents=0,
                new_preimages=0, fixed_preimages_checked=256, state_unchanged=True)


def providers():
    result = {}
    for name, module in list(sys.modules.items()):
        path = getattr(module, "__file__", None)
        if path and path.endswith(".py") and name.startswith(("ibme.", "experiments.research.")):
            p = Path(path).resolve()
            result[name] = dict(path=str(p), sha256=hashlib.sha256(p.read_bytes()).hexdigest())
    return result


def run(directory, params, *, source_commit="development", block_columns=32, cache_bytes=16*2**20):
    directory.mkdir(parents=True, exist_ok=False)
    os.chmod(directory, 0o700)
    packing = dict(block_columns=block_columns, cache_bytes=cache_bytes)
    phases, source, stage = [], CountedSystem(), "before-root"
    report = dict(schema="MP12-BLOCKED-3M-FEASIBILITY/1", status="started",
        source_commit=source_commit, parameters=params.record(), environment=environment(),
        identities_bytes=86, payload_seed_bytes=32, fixed_preimages=256, repetitions=1,
        uses_ROM=True, system_randomness=True, packing=packing, phases=phases,
        scope="real independent root, full-H parent, full 3m 256-target leaf and private-object restore; no big-q KEM/IBME execution",
        security_claim="none", backend_admitted=False, parameters_are_formal=False)
    def pending(name):
        nonlocal stage
        stage = name
        save(directory/(name+".pending"), b"occupied one-attempt address; do not regenerate\n")
    def done(name):
        os.replace(directory/(name+".pending"), directory/(name+".done"))
        save(directory/"progress.json", dict(stage=name, phases=phases))
        print(name+" passed", flush=True)
    try:
        pending("root")
        before = source.bytes
        with measured_phase("root-generation", phases) as row:
            root = generate_root(params.n, params.q, params.root_r_squared,
                options=params.options(), rng=source, **packing)
            row["entropy_bytes"] = source.bytes-before
        context = PrototypeContext.create(params, root.public)
        with measured_phase("root-persistence", phases):
            save(directory/"context.bin", context.to_bytes())
            save(directory/"root.bin", dump_trapdoor(context, root))
        done("root")

        h1 = PackedMatrix.from_rows(context.h((RECEIVER,)), params.q-1, False, **packing)
        pending("parent"); before = source.bytes
        with measured_phase("parent-delegation", phases) as row:
            parent = delegate(root, h1, options=params.options(), epsilon_bits=params.epsilon_bits,
                rng=source, entropy_budget=params.entropy_cap_bytes, **packing)
            row["entropy_bytes"] = source.bytes-before
        with measured_phase("parent-persistence", phases):
            save(directory/"parent.bin", dump_trapdoor(context, parent, RECEIVER))
        done("parent")

        h2 = PackedMatrix.from_rows(context.h((RECEIVER, SENDER)), params.q-1, False, **packing)
        pending("leaf"); before = source.bytes
        with measured_phase("leaf-sampler-preparation", phases):
            sampler = BlockedPreimageSampler(parent, h2, options=params.options(), epsilon_bits=params.epsilon_bits)
            assert sampler.dimension == 3*params.m and sampler.output_squared == params.leaf_width_squared
        targets = context.targets(RECEIVER, SENDER)
        with measured_phase("leaf-256-sampling", phases) as row:
            source_leaf = CheckedEntropy(source, params.entropy_cap_bytes)
            limit = 3*params.m*params.leaf_width_squared
            def samples():
                for target in targets:
                    col = sampler.sample(target, rng=source_leaf)
                    if sum(x*x for x in col) > limit:
                        raise ValueError("blocked fixed leaf norm event; no retry")
                    yield col
            leaf = PackedMatrix.from_columns(3*params.m, 256, isqrt(limit), True, samples(), **packing)
            row["entropy_bytes"] = source.bytes-before
        with measured_phase("leaf-persistence", phases):
            save(directory/"leaf.bin", dump_leaf(context, RECEIVER, SENDER, leaf))
        done("leaf")
        with measured_phase("strict-object-restore", phases):
            restored = restore(directory, packing=packing)

        # Exact decimal-token size of the same fully sampled R in compact JSON;
        # no JSON private matrix or private geometry is placed in the receipt.
        json_r_bytes = sum(len(str(x)) for col in parent.r.columns() for x in col)+parent.r.nrows*(parent.r.ncols+2)+1
        report.update(status="passed", restore=restored, noise_condition=params.noise_budget(),
            sampler=sampler.public_certificate(), source_providers=providers(),
            entropy_bytes=source.bytes, entropy_reads=source.reads,
            sizes={name:(directory/name).stat().st_size for name in ("context.bin", "root.bin", "parent.bin", "leaf.bin")},
            parent_R_json_decimal_bytes=json_r_bytes, parent_R_packed_bytes=len(parent.r.to_bytes()),
            parent_R_json_to_packed_ratio=json_r_bytes/len(parent.r.to_bytes()),
            limits=dict(packed_backing_resident=True, max_matrix_entries=2**24,
                operation_entropy_cap_bytes=params.entropy_cap_bytes,
                entropy_cap_exhaustion_probability_certified=False,
                constant_time=False, high_dimension_target_executed=False))
        save(directory/"receipt.json", report)
        save(directory/"completed", b"passed; use restore-only, never reissue\n")
        print(json.dumps(dict(status="passed", n=params.n, phases=len(phases), entropy_bytes=source.bytes)), flush=True)
        return report
    except BaseException as exc:
        report.update(status="failed", failure_stage=stage, exception_type=type(exc).__name__,
                      entropy_bytes=source.bytes, pending_preserved=True, no_outer_retry=True)
        save(directory/"failure.json", report)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-directory", type=Path, required=True)
    parser.add_argument("--n", type=int, default=2)
    parser.add_argument("--q", type=int, default=PrototypeParams.q)
    parser.add_argument("--root-r-squared", type=int)
    parser.add_argument("--block-columns", type=int, default=32)
    parser.add_argument("--cache-bytes", type=int, default=16*2**20)
    parser.add_argument("--restore-only", action="store_true")
    parser.add_argument("--source-commit", default="development")
    args = parser.parse_args()
    if args.restore_only:
        if not (args.private_directory/"completed").is_file(): raise ValueError("completed original state required")
        print(json.dumps(restore(args.private_directory)), flush=True)
    else:
        params = PrototypeParams(args.n, args.q, args.root_r_squared or 8*args.n)
        run(args.private_directory, params, source_commit=args.source_commit,
            block_columns=args.block_columns, cache_bytes=args.cache_bytes)


if __name__ == "__main__": main()
