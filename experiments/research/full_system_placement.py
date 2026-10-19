"""Same-wheel source/Windows-wheel/WSL-wheel complete IB-ME placement ablation.

Three fresh states are generated once and shared across placements. Each state
uses six fresh worker processes in a balanced order, with five complete fresh
encryptions/decryptions per block. Setup, imports, restoration and diagnostics
are separate from steady-state API timings. No failed state is regenerated.
"""

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time
from unittest.mock import patch

from .full_system_benchmark import source_providers, summarize, write
from .runtime_metrics import environment
from .wsl_wheel_runtime import prepare, verify_runtime, wheel_manifest

SUITE_NAME = "latte3-hybrid-cert-ml-dsa-ml-dsa-44-reference-byteauth-v1"


def worker(directory, output, samples):
    from ibme.assembly import SuiteConfig, build_runtime
    from ibme.core.randomness import SecureRandom
    from ibme.protocol.baseline import PublicKey, ReceiverKey, SenderKey

    started = time.perf_counter()
    inputs = json.loads((directory / "inputs.json").read_bytes())
    config = SuiteConfig.from_json((directory / "suite.json").read_bytes())
    protected = [directory / name for name in ("public.bin", "sender.bin", "receiver.bin", "ciphertext.bin")]
    snapshot = [hashlib.sha256(path.read_bytes()).digest() for path in protected]
    def forbidden(*_args, **_kwargs):
        raise AssertionError("restoration attempted fresh entropy")
    with patch.object(SecureRandom, "read", forbidden):
        runtime = build_runtime(config)
        d = runtime.decoders
        public = PublicKey.from_bytes(protected[0].read_bytes(), d["hpk"], d["ipk"])
        sender = SenderKey.from_bytes(protected[1].read_bytes(), d["sk"])
        receiver = ReceiverKey.from_bytes(protected[2].read_bytes(), d["sk1"])
        message = (bytes(range(256)) * ((inputs["message_bytes"] + 255) // 256))[:inputs["message_bytes"]]
        original_wire = protected[3].read_bytes()
        if runtime.proto.decrypt(public, receiver, sender.identity, original_wire) != message:
            raise AssertionError("zero-entropy cross-placement restore failed")
    restore_seconds = time.perf_counter() - started
    fixed_receiver = receiver.to_bytes()
    times = {"encrypt": [], "decrypt": []}
    sizes = []
    for _ in range(samples):
        start = time.perf_counter()
        wire = runtime.proto.encrypt(public, sender, receiver.identity, message).to_bytes()
        times["encrypt"].append(time.perf_counter() - start)
        start = time.perf_counter()
        recovered = runtime.proto.decrypt(public, receiver, sender.identity, wire)
        times["decrypt"].append(time.perf_counter() - start)
        if recovered != message:
            raise AssertionError("complete decrypt mismatch")
        sizes.append(len(wire))
    # A separate untimed diagnostic retains operation/entropy evidence without
    # wrapping any function used by the actual timing observations above.
    native_calls, source_checks, entropy = {}, {}, dict(reads=0, bytes=0)
    original_read = SecureRandom.read
    def counted(self, count):
        entropy["reads"] += 1
        entropy["bytes"] += count
        return original_read(self, count)
    def counted_native(family, original_call):
        def call(self, operation, *args, **kwargs):
            key = family + ":" + operation
            native_calls[key] = native_calls.get(key, 0) + 1
            return original_call(self, operation, *args, **kwargs)
        return call
    def counted_source(family, original_check):
        def check():
            source_checks[family] = source_checks.get(family, 0) + 1
            return original_check()
        return check
    with ExitStack() as stack:
        stack.enter_context(patch.object(SecureRandom, "read", counted))
        for module_name, class_name, method, family in (
                ("ibme.hibe.latte.engine", "Native", "call", "latte"),
                ("ibme.ibs.certified.mldsa", "MLDSA", "_run", "mldsa")):
            cls = getattr(sys.modules[module_name], class_name)
            stack.enter_context(patch.object(cls, method, counted_native(family, getattr(cls, method))))
            module = sys.modules["ibme.hibe.latte.native.build" if family == "latte" else module_name]
            stack.enter_context(patch.object(module, "source_id", counted_source(family, module.source_id)))
        wire = runtime.proto.encrypt(public, sender, receiver.identity, message).to_bytes()
        if runtime.proto.decrypt(public, receiver, sender.identity, wire) != message:
            raise AssertionError("diagnostic decrypt mismatch")
    if (receiver.to_bytes() != fixed_receiver
            or snapshot != [hashlib.sha256(path.read_bytes()).digest() for path in protected]):
        raise AssertionError("shared fixed state changed")
    provider_hashes = {name: value["sha256"] for name, value in source_providers().items()}
    result = dict(status="passed", suite=config.to_dict(), suite_digest=config.digest,
        identity_bytes=len(sender.identity), message_bytes=len(message), samples=samples,
        seconds=times, full_ciphertext_bytes=sizes, zero_entropy_restore=True,
        restore_and_build_seconds_excluding_process_import=restore_seconds,
        fixed_state_unchanged=True, diagnostic_native_calls=native_calls,
        diagnostic_source_validation_calls=source_checks, diagnostic_entropy=entropy,
        loaded_module_sha256=provider_hashes,
        self_kernel_lifetime_peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
        completed_children_lifetime_peak_rss_bytes=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * 1024)
    write(output, result)


def child(command, *, root, log, timeout=900):
    environment = dict(os.environ, PYTHONPATH=str(root))
    start = time.perf_counter()
    with log.open("xb") as stream:
        process = subprocess.run(command, cwd=root, env=environment, stdout=stream, stderr=stream, timeout=timeout)
    if process.returncode:
        raise RuntimeError("child failed; private log/state retained; no outer retry")
    return time.perf_counter() - start


def compare(source_root, wheel, windows_runtime, private, source_commit, samples, existing_generated=None):
    private.mkdir(parents=True, exist_ok=False, mode=0o700)
    prepared = prepare(wheel)
    linux_root = Path(prepared["runtime_root"])
    if not str(windows_runtime.resolve()).startswith("/mnt/"):
        raise ValueError("the wheel ablation must remain on the Windows mount")
    if windows_runtime.exists():
        raise ValueError("use a new Windows-wheel ablation directory")
    subprocess.run([sys.executable, "-m", "pip", "install", "--no-deps", "--no-index", "--no-compile",
                    "--target", str(windows_runtime), str(wheel)], check=True)
    expected = wheel_manifest(wheel)
    verify_runtime(windows_runtime, expected)
    # All public packaged files in the original source tree must match the
    # same wheel too. No private directory, Git metadata or build output enters it.
    for name, digest in expected.items():
        if name.startswith(("ibme/", "experiments/")):
            source = source_root / ("src/" + name if name.startswith("ibme/") else name)
            if hashlib.sha256(source.read_bytes()).hexdigest() != digest:
                raise AssertionError("wheel/source mismatch: " + name)
    roots = dict(source=source_root, windows_wheel=windows_runtime, wsl_wheel=linux_root)
    generated = private / "generated" if existing_generated is None else existing_generated.resolve()
    generation_seconds = None
    if existing_generated is None:
        generation_seconds = child([sys.executable, "-m", "experiments.research.full_system_benchmark",
            "--private-directory", str(generated), "--suite-file", str(source_root / "ci/c-combinations.json"),
            "--suite-name", SUITE_NAME, "--source-commit", source_commit, "--repetitions", "3",
            "--warm-repetitions", "3", "--identity-bytes", "64", "--message-bytes", "32",
            "--security-group", "same-frozen-latte-mldsa44-placement"],
            root=linux_root, log=private / "generation.private-log")
    generation = json.loads((generated / "receipt.json").read_bytes())
    if (generation["status"] != "passed" or generation["repetitions"] != 3
            or generation["identity_bytes"] != 64 or generation["message_bytes"] != 32):
        raise ValueError("expected three completed honest generation/restore states")
    for record in generation["records"]:
        if record["generation"]["status"] != "passed" or record["restore"]["status"] != "passed":
            raise ValueError("failed/partial states cannot be silently replaced or reused")
        for name, value in record["generation"]["source_providers"].items():
            # A measurement-only harness fix can reuse completed states;
            # every primitive/protocol/provider byte must still be identical.
            relative = name.replace(".", "/")
            candidates = (relative + ".py", relative + "/__init__.py")
            if not any(expected.get(path) == value["sha256"] for path in candidates):
                raise ValueError("completed-state provider differs from wheel: " + name)
    rows = []
    variants = list(roots)
    for state_index in range(3):
        order = variants[state_index:] + variants[:state_index]
        order = order + list(reversed(order))
        for block_index, variant in enumerate(order):
            output = private / f"state-{state_index}-block-{block_index}.json"
            root = roots[variant]
            path_value = str(root / "src") + os.pathsep + str(root) if variant == "source" else str(root)
            # Source runtime has src/ibme; installed wheels have ibme at root.
            start = time.perf_counter()
            with (private / f"state-{state_index}-block-{block_index}.private-log").open("xb") as stream:
                process = subprocess.run([sys.executable, "-m", "experiments.research.full_system_placement",
                    "--worker-directory", str(generated / f"repetition-{state_index}"),
                    "--output", str(output), "--samples", str(samples)], cwd=root,
                    env=dict(os.environ, PYTHONPATH=path_value), stdout=stream, stderr=stream, timeout=300)
            if process.returncode:
                raise RuntimeError("paired worker failed; no outer retry; private outputs retained")
            row = json.loads(output.read_bytes())
            row.update(variant=variant, state_index=state_index, block_index=block_index,
                       whole_fresh_process_seconds=time.perf_counter() - start)
            rows.append(row)
        print(f"shared state {state_index+1}/3: all six balanced blocks passed", flush=True)
    reference = rows[0]
    for row in rows:
        for field in ("suite_digest", "loaded_module_sha256", "diagnostic_native_calls",
                      "diagnostic_source_validation_calls", "diagnostic_entropy"):
            if row[field] != reference[field]:
                raise AssertionError("placement changed semantics/provenance: " + field)
    summary = {variant: {op: summarize([value for row in rows if row["variant"] == variant
                         for value in row["seconds"][op]]) for op in ("encrypt", "decrypt")}
               for variant in variants}
    per_state = {variant: {op: [summarize([value for row in rows if row["variant"] == variant
                and row["state_index"] == index for value in row["seconds"][op]])["median"]
                for index in range(3)] for op in ("encrypt", "decrypt")} for variant in variants}
    report = dict(schema="FULL-IBME-PLACEMENT/1", status="passed", source_commit=source_commit,
        prepared_runtime=prepared, suite=reference["suite"], suite_digest=reference["suite_digest"],
        environment=environment(), independent_roots=3, blocks_per_state_per_variant=2,
        samples_per_block=samples, identity_bytes=64, message_bytes=32, records=rows,
        generation_source_commit=generation["source_commit"],
        reused_completed_states=existing_generated is not None,
        timing_seconds=summary, per_state_median_seconds=per_state, fresh_generation_seconds=generation_seconds,
        unchanged_native_checks=True, security_claim="none", backend_admitted=False, parameters_are_formal=False,
        uses_ROM=True, no_outer_retry=True, cross_security_group_ranking=False,
        timing_scope="unprofiled full public API incl. input/key validation, wrappers, wire encode/decode, native launches; imports/setup/restore outside steady-state samples",
        placement_scope="identical wheel bytes and loaded provider hashes; built native binaries on WSL filesystem in all arms; source/installed code placement only",
        uncertainty="three independent roots; repeated observations share their root; OS caches retained; single machine; no cryptographic algorithm speedup claim",
        memory_scope="per-worker Linux lifetime high water incl. imports/restoration; not phase-specific peaks")
    write(private / "receipt.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker-directory", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--windows-runtime", type=Path)
    parser.add_argument("--private-directory", type=Path)
    parser.add_argument("--source-commit")
    parser.add_argument("--existing-generated", type=Path,
                        help="reuse three completed generation/restore states; verify all original provider hashes")
    parser.add_argument("--samples", type=int, default=5)
    args = parser.parse_args()
    if not 3 <= args.samples <= 31:
        parser.error("use 3..31 samples per block")
    if args.worker_directory:
        if not args.output:
            parser.error("worker needs --output")
        worker(args.worker_directory, args.output, args.samples)
    else:
        if not all((args.source_root, args.wheel, args.windows_runtime, args.private_directory, args.source_commit)):
            parser.error("provide source, wheel, Windows ablation root, new private directory and exact source commit")
        result = compare(args.source_root.resolve(), args.wheel.resolve(), args.windows_runtime.resolve(),
                         args.private_directory.resolve(), args.source_commit, args.samples, args.existing_generated)
        print(json.dumps(result["timing_seconds"], sort_keys=True))


if __name__ == "__main__":
    main()
