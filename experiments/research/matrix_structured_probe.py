"""Real CSPRNG MP12 structured SampleD/DelTrap probe; private outputs ignored.

This is a primitive consumer, not a HIBE, noisy encryption or IBME receipt.
Restore mode reuses the same real keys and checks saved equations in a new
process with SecureRandom.read forbidden. No failed address is regenerated.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import sys
import tempfile
import time
import traceback
from unittest.mock import patch

from sage.version import version as sage_version
from ibme.core.randomness import SecureRandom
from ibme.lattice.matrix_sampling import mp12_structured as tool
from experiments.research.gaussian_reference import draw_uniform_integer

PARENT, CHILD = b"R"*86, b"S"*86


class CountedSystem:
    def __init__(self):
        self.source, self.bytes = SecureRandom(), 0
    def read(self, count):
        value = self.source.read(count)
        self.bytes += len(value)
        return value


def save(path, value):
    raw = value if type(value) is bytes else (json.dumps(value, indent=2)+"\n").encode()
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".structured-", delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(raw)
    os.replace(temporary, path)


def sources():
    base = Path(__file__).resolve().parents[2]
    paths = ["experiments/research/matrix_structured_probe.py",
        "src/ibme/lattice/matrix_sampling/mp12_structured.py",
        "src/ibme/lattice/matrix_sampling/scalar.py",
        "src/ibme/lattice/matrix_sampling/gpv.py",
        "src/ibme/lattice/chkp/joint_parameters.py"]
    return {p: hashlib.sha256((base/p).read_bytes()).hexdigest() for p in paths}


def check_samples(key, records):
    if type(records) is not list or not 1 <= len(records) <= 32:
        raise ValueError("nonempty bounded saved sample batch required")
    for record in records:
        if type(record) is not dict or set(record) != {"target", "sample"}:
            raise ValueError("saved structured sample fields")
        target, sample = record["target"], record["sample"]
        if (len(sample) != key.dimension or len(target) != key.n or
                any(type(v) is not int or not 0 <= v < key.q for v in target) or
                any(type(v) is not int or abs(v).bit_length() > 4096 for v in sample)):
            raise ValueError("saved structured sample dimension")
        if any(sum(a*b for a, b in zip(row, sample)) % key.q != u for row, u in zip(key.public.rows, target)):
            raise ValueError("saved structured sample equation")


def restore(directory):
    calls = 0
    def forbidden(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("restoration attempted fresh entropy")
    with patch.object(SecureRandom, "read", forbidden):
        root_raw = (directory/"root.bin").read_bytes()
        root = tool.StructuredTrapdoor.from_bytes(root_raw)
        assert root.to_bytes() == root_raw
        check_samples(root, json.loads((directory/"root-samples.json").read_bytes()))
        levels = 0
        if (directory/"root-state.bin").exists():
            raw = (directory/"root-state.bin").read_bytes()
            state = tool.StructuredDelegator.from_bytes(raw)
            tail = json.loads((directory/"tail1.json").read_bytes())
            parent = state.issue(PARENT, tail, rng=type("NoEntropy", (), {"read": forbidden})())
            assert state.to_bytes() == raw and parent.to_bytes() == (directory/"parent.bin").read_bytes()
            raw = (directory/"parent-state.bin").read_bytes()
            state = tool.StructuredDelegator.from_bytes(raw)
            tail = json.loads((directory/"tail2.json").read_bytes())
            leaf = state.issue(CHILD, tail, rng=type("NoEntropy", (), {"read": forbidden})())
            assert state.to_bytes() == raw and leaf.to_bytes() == (directory/"leaf.bin").read_bytes()
            check_samples(leaf, json.loads((directory/"leaf-samples.json").read_bytes()))
            levels = 2
    if calls:
        raise AssertionError("restore consumed entropy")
    return dict(status="passed", fresh_process=True, entropy_calls=calls, reused_delegated_levels=levels)


def run(args):
    directory = args.private_directory
    if args.restore_only:
        print(json.dumps(restore(directory)))
        return 0
    if not 2 <= args.n <= 128 or not 1 <= args.samples <= 32:
        raise ValueError("bounded explicit structured probe dimensions/count required")
    # An existing run is observed/restored, never overwritten or restarted.
    directory.mkdir(parents=True, mode=0o700)
    source = CountedSystem()
    report = dict(schema="MP12-STRUCTURED-REAL-PROBE/1", status="started",
        baseline_commit=args.baseline_commit, n=args.n, q=args.q, root_R_squared=args.root_squared,
        samples_per_selected_level=args.samples, repetitions=1,
        address_bytes_per_level=86 if args.delegate else None,
        RNG="default system CSPRNG through explicit byte counter; no deterministic source",
        source_sha256_before=sources(), stages=[],
        environment=dict(python=sys.version.split()[0], sage=sage_version, platform=platform.platform()),
        full_HIBE_backend=False, message_or_seed_encryption=False,
        security_claim="none", backend_admitted=False, parameters_are_formal=False)
    start = time.monotonic()
    def stage(name, operation):
        report["current_stage"] = name
        save(directory/"receipt.json", report)
        before, entropy = time.monotonic(), source.bytes
        result = operation()
        report["stages"].append(dict(name=name, seconds=time.monotonic()-before,
            system_entropy_bytes=source.bytes-entropy))
        save(directory/"receipt.json", report)
        print(json.dumps(report["stages"][-1]), flush=True)
        return result
    try:
        root = stage("structured-computational-root", lambda: tool.generate_structured_root(
            args.n, args.q, args.root_squared, rng=source))
        save(directory/"root.bin", root.to_bytes())
        sampler = stage("root-SampleD-preparation", lambda: tool.StructuredPreimageSampler(root))
        report["root_sampler"] = sampler.public_certificate()
        def sample_batch(key, sampler, name):
            records, trials = [], []
            for j in range(args.samples):
                target = tuple((13*i+7*j) % key.q for i in range(key.n))
                records.append(dict(target=target, sample=sampler.sample(target, rng=source)))
                trials.append(sampler.last_trace["perturbation_trials"])
            check_samples(key, records)
            save(directory/(name+"-samples.json"), records)
            report[name+"_sample_count"] = len(records)
            report[name+"_perturbation_trials"] = trials
        stage("root-fresh-preimages", lambda: sample_batch(root, sampler, "root"))
        if args.delegate:
            def tail_for(key):
                return tuple(tuple(draw_uniform_integer(source, key.q, max_trials=192)
                    for _ in range(key.w)) for _ in range(key.n))
            first = stage("uniform-public-first-extension", lambda: tail_for(root))
            save(directory/"tail1.json", first)
            state = tool.StructuredDelegator(root,
                persist_pending=lambda s: save(directory/"root-state.bin", s.to_bytes()))
            parent = stage("Algorithm4-root-to-parent", lambda: state.issue(PARENT, first, rng=source))
            save(directory/"parent.bin", parent.to_bytes())
            save(directory/"root-state.bin", state.to_bytes())
            second = stage("uniform-public-second-extension", lambda: tail_for(parent))
            save(directory/"tail2.json", second)
            state = tool.StructuredDelegator(parent,
                persist_pending=lambda s: save(directory/"parent-state.bin", s.to_bytes()))
            leaf = stage("Algorithm4-parent-to-leaf", lambda: state.issue(CHILD, second, rng=source))
            save(directory/"leaf.bin", leaf.to_bytes())
            save(directory/"parent-state.bin", state.to_bytes())
            leaf_sampler = stage("leaf-SampleD-preparation", lambda: tool.StructuredPreimageSampler(leaf))
            report["leaf_sampler"] = leaf_sampler.public_certificate()
            stage("leaf-fresh-preimages", lambda: sample_batch(leaf, leaf_sampler, "leaf"))
        def fresh_restore():
            result = subprocess.run([sys.executable, "-m", "experiments.research.matrix_structured_probe",
                "--private-directory", str(directory.resolve()), "--restore-only"],
                capture_output=True, timeout=60)
            if result.returncode:
                # Traceback may contain private state; keep it in private storage.
                save(directory/"restore-error.txt", result.stderr)
                raise ValueError("fresh-process structured restore failed")
            report["restore"] = json.loads(result.stdout)
        stage("fresh-process-zero-entropy-restore", fresh_restore)
        report.update(status="passed", root_generations=1,
            expanded_full_kernel_bases=0, levels_delegated=2 if args.delegate else 0,
            private_state_files_excluded_from_public_delivery=True)
    except Exception as exc:
        report.update(status="failed", error_type=type(exc).__name__, automatic_retry=False)
        save(directory/"private-error.txt", traceback.format_exc().encode())
        raise
    finally:
        report.update(seconds=time.monotonic()-start, system_entropy_bytes=source.bytes,
            peak_process_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            source_sha256_after=sources())
        report["source_unchanged_during_execution"] = report["source_sha256_before"] == report["source_sha256_after"]
        save(directory/"receipt.json", report)
    if not report["source_unchanged_during_execution"]:
        report.update(status="failed", error_type="SourceChanged", automatic_retry=False)
        save(directory/"receipt.json", report)
        raise RuntimeError("structured probe source changed; receipt cannot pass")
    (directory/"completed").write_bytes(b"passed\n")
    print(json.dumps(dict(status=report["status"], seconds=report["seconds"],
        peak_process_rss_kib=report["peak_process_rss_kib"])), flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-directory", type=Path, required=True)
    parser.add_argument("--baseline-commit")
    parser.add_argument("--n", type=int, default=2)
    parser.add_argument("--q", type=int, default=257)
    parser.add_argument("--root-squared", type=int, default=16)
    parser.add_argument("--samples", type=int, default=8)
    parser.add_argument("--delegate", action="store_true")
    parser.add_argument("--restore-only", action="store_true")
    args = parser.parse_args()
    if not args.restore_only and not args.baseline_commit:
        parser.error("explicit frozen Git source commit required")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
