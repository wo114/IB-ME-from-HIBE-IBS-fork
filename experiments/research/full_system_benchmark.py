"""Repeated full IB-ME benchmark through SuiteConfig and public protocol APIs.

Fresh-process setup/key issuance/first decrypt, cached encrypt/decrypt, and a
separate fresh-process zero-entropy restoration are recorded independently.
Each cold repetition creates one new private state; failures are not retried.
OS caches are retained. Native process launches, protocol validation, complete
wire encoding/loading and the chosen Hybrid/BYTEAUTH wrappers are timed.
Parameter/security groups are metadata, never automatic cross-group rankings.
"""

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
import signal
from pathlib import Path
import statistics
import subprocess
import sys
import time
from unittest.mock import patch

from .runtime_metrics import measured_phase, environment


def write(path, raw):
    if type(raw) is not bytes: raw = (json.dumps(raw, indent=2, sort_keys=True)+"\n").encode("utf-8")
    with path.open("xb") as stream:
        os.chmod(path, 0o600)
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)


def summarize(values):
    if not values: raise ValueError("cannot summarize zero completed measurements")
    return dict(count=len(values), minimum=min(values), median=statistics.median(values),
                maximum=max(values), mean=statistics.mean(values),
                sample_stdev=statistics.stdev(values) if len(values) > 1 else None,
                observations=values)


def source_providers():
    result = {}
    for name, module in list(sys.modules.items()):
        path = getattr(module, "__file__", None)
        if path and path.endswith(".py") and name.startswith(("ibme.", "experiments.research.")):
            p = Path(path).resolve()
            result[name] = dict(path=str(p), sha256=hashlib.sha256(p.read_bytes()).hexdigest())
    return result


def worker(directory, *, restore=False):
    rows = []
    inputs = json.loads((directory/"inputs.json").read_bytes())
    report = dict(schema="FULL-IBME-BENCHMARK-WORKER/1", status="started", phases=rows,
        mode="fresh-process-restore" if restore else "fresh-process-generation-and-warm",
        environment=environment(), source_commit=inputs["source_commit"],
        identity_bytes=inputs["identity_bytes"], message_bytes=inputs["message_bytes"],
        security_group=inputs["security_group"], security_claim="none",
        backend_admitted=False, parameters_are_formal=False)
    stage = "imports"
    entropy = dict(bytes=0, reads=0)
    entropy_patch = None
    try:
        with measured_phase("import-and-build-runtime", rows):
            from ibme.assembly import SuiteConfig, build_runtime
            from ibme.core.randomness import SecureRandom
            from ibme.protocol.baseline import PublicKey, SenderKey, ReceiverKey
            original = SecureRandom.read
            def counted(self, count):
                entropy["reads"] += 1
                entropy["bytes"] += count
                if restore: raise AssertionError("cached restoration attempted new entropy")
                return original(self, count)
            entropy_patch = patch.object(SecureRandom, "read", counted)
            entropy_patch.start()
            config = SuiteConfig.from_json((directory/"suite.json").read_bytes())
            runtime = build_runtime(config)
            proto = runtime.proto
        # Count every use of the common system source, including IBS/OTS
        # sources constructed by the factories. Never retain entropy bytes.
        identity_bytes = inputs["identity_bytes"]
        sender_id, receiver_id = b"A"*identity_bytes, b"B"*identity_bytes
        message = (bytes(range(256))*((inputs["message_bytes"]+255)//256))[:inputs["message_bytes"]]
        if identity_bytes > runtime.capacity["identity_bytes"] or len(message) > runtime.capacity["max_application_bytes"]:
            raise ValueError("benchmark inputs exceed the public capacity")
        with ExitStack() as stack:
            native_calls = {}
            def guard(family, original_call):
                def call(self, operation, *args, **kwargs):
                    key = family+":"+operation
                    native_calls[key] = native_calls.get(key, 0)+1
                    prohibited = {"setup", "delegate", "extract"} if family == "latte" else {"keypair", "sign"}
                    if restore and operation in prohibited:
                        raise AssertionError("restore attempted native generation")
                    return original_call(self, operation, *args, **kwargs)
                return call
            for module_name, class_name, method, family in (
                    ("ibme.hibe.latte.engine", "Native", "call", "latte"),
                    ("ibme.ibs.certified.mldsa", "MLDSA", "_run", "mldsa"),
                    ("ibme.ibs.certified.falcon", "Falcon", "_run", "falcon")):
                module = sys.modules.get(module_name)
                if module is not None:
                    cls = getattr(module, class_name)
                    stack.enter_context(patch.object(cls, method, guard(family, getattr(cls, method))))
            if restore:
                # Public methods are guarded in addition to entropy. A
                # deterministic native key generation must not pass as replay.
                def forbidden(*args, **kwargs): raise AssertionError("restore attempted key generation or signing")
                stack.enter_context(patch.object(runtime.ibs, "setup", forbidden))
                stack.enter_context(patch.object(runtime.ibs, "key_extract", forbidden))
                stack.enter_context(patch.object(runtime.ibs, "sign", forbidden))
                stage = "restore-objects"
                protected = [directory/x for x in ("public.bin", "receiver.bin", "ciphertext.bin")]
                before = [hashlib.sha256(p.read_bytes()).digest() for p in protected]
                with measured_phase("restore-objects", rows):
                    d = runtime.decoders
                    public = PublicKey.from_bytes(protected[0].read_bytes(), d["hpk"], d["ipk"])
                    receiver = ReceiverKey.from_bytes(protected[1].read_bytes(), d["sk1"])
                    wire = protected[2].read_bytes()
                    runtime.validate_receiver(public, receiver)
                for index in range(inputs["warm_repetitions"]):
                    stage = "restored-decrypt"
                    with measured_phase("restored-decrypt", rows):
                        recovered = proto.decrypt(public, receiver, sender_id, wire)
                        if recovered != message: raise AssertionError("restored decrypt mismatch")
                if receiver.to_bytes() != protected[1].read_bytes():
                    raise AssertionError("restored receiver changed; a cached fixed leaf was not reused")
                if before != [hashlib.sha256(p.read_bytes()).digest() for p in protected]:
                    raise AssertionError("restoration modified original state")
                report.update(state_unchanged=True, entropy_bytes=entropy["bytes"], entropy_reads=entropy["reads"])
            else:
                # Address is occupied durably before any generation. Failure
                # keeps this marker and any partial objects; no outer retry.
                write(directory/"generation.pending", b"one attempt; preserve on every failure\n")
                stage = "setup"
                with measured_phase("setup", rows):
                    public, master = proto.setup(runtime.hibe_params, ibs_params=runtime.ibs_params)
                stage = "sender-key"
                with measured_phase("sender-key", rows): sender = proto.skgen(master, sender_id)
                stage = "receiver-key"
                with measured_phase("receiver-key", rows): receiver = proto.rkgen(master, receiver_id)
                stage = "cold-encrypt"
                with measured_phase("cold-encrypt", rows): wire = proto.encrypt(public, sender, receiver_id, message).to_bytes()
                stage = "first-decrypt-with-leaf-generation"
                with measured_phase("first-decrypt-with-leaf-generation", rows):
                    if proto.decrypt(public, receiver, sender_id, wire) != message:
                        raise AssertionError("first decrypt mismatch")
                with measured_phase("persist-state", rows):
                    write(directory/"public.bin", public.to_bytes())
                    write(directory/"master.bin", master.to_bytes())
                    write(directory/"sender.bin", sender.to_bytes())
                    write(directory/"receiver.bin", receiver.to_bytes())
                    write(directory/"ciphertext.bin", wire)
                sizes = {p.name:p.stat().st_size for p in directory.glob("*.bin")}
                ciphertext_sizes = [len(wire)]
                fixed_receiver = receiver.to_bytes()
                for index in range(inputs["warm_repetitions"]):
                    stage = "warm-encrypt"
                    with measured_phase("warm-encrypt", rows):
                        wire = proto.encrypt(public, sender, receiver_id, message).to_bytes()
                        ciphertext_sizes.append(len(wire))
                    stage = "warm-decrypt"
                    with measured_phase("warm-decrypt", rows):
                        if proto.decrypt(public, receiver, sender_id, wire) != message:
                            raise AssertionError("warm decrypt mismatch")
                if receiver.to_bytes() != fixed_receiver:
                    raise AssertionError("warm operations changed fixed receiver state")
                os.replace(directory/"generation.pending", directory/"generation.done")
                report.update(sizes=sizes, full_ciphertext_bytes=ciphertext_sizes,
                    entropy_bytes=entropy["bytes"], entropy_reads=entropy["reads"], fixed_receiver_reused=True)
        report.update(status="passed", suite=config.to_dict(), runtime_metadata=runtime.metadata,
            source_providers=source_providers(), uses_ROM=True,
            native_operation_counts_after_runtime_build=native_calls,
            native_engine_rebuild=False, security_proofs_produced=0)
        write(directory/("restore-receipt.json" if restore else "generation-receipt.json"), report)
        print(json.dumps(dict(status="passed", mode=report["mode"], phases=len(rows))), flush=True)
        return report
    except BaseException as exc:
        report.update(status="failed", failure_stage=stage, exception_type=type(exc).__name__,
                      no_outer_retry=True, entropy=entropy)
        write(directory/("restore-failure.json" if restore else "generation-failure.json"), report)
        raise
    finally:
        if entropy_patch is not None: entropy_patch.stop()


def run_child(directory, *, restore=False, timeout_seconds=900):
    command = [sys.executable, "-m", "experiments.research.full_system_benchmark",
               "--worker-directory", str(directory)]
    if restore: command.append("--restore-worker")
    start = time.perf_counter()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        # Stop the worker's own process group, including a live native child.
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        write(directory/"worker-timeout.json", dict(status="failed", timeout_seconds=timeout_seconds, no_outer_retry=True))
        raise
    # Native stdout/exception details stay private. Public report is allowlisted.
    write(directory/("restore.private-log" if restore else "generation.private-log"), stdout+stderr)
    if process.returncode: raise RuntimeError("benchmark worker failed; occupied private state retained")
    report = json.loads((directory/("restore-receipt.json" if restore else "generation-receipt.json")).read_bytes())
    report["fresh_process_wall_seconds"] = time.perf_counter()-start
    return report


def run(directory, selection, *, repetitions, warm_repetitions, message_bytes,
        identity_bytes, security_group, source_commit):
    from ibme.assembly import make_suite, validate_suite
    if not 3 <= repetitions <= 31 or not 3 <= warm_repetitions <= 31:
        raise ValueError("use 3..31 cold and warm repetitions")
    if not 1 <= identity_bytes <= 86 or not 0 <= message_bytes <= 65536:
        raise ValueError("bounded benchmark message/identity lengths required")
    if selection.get("allow_mock"):
        raise ValueError("this full-system benchmark requires real backends")
    config = make_suite(**selection)
    preflight = validate_suite(config)
    if not preflight.ok: raise ValueError("benchmark public preflight failed: "+"; ".join(preflight.errors))
    if preflight.metadata.get("primitive_persistent_identity_cache", {}).get("hibe") is not True:
        raise ValueError("zero-entropy restore benchmark requires a declared persistent HIBE identity cache")
    directory.mkdir(parents=True, exist_ok=False); os.chmod(directory, 0o700)
    records = []
    for index in range(repetitions):
        case = directory/f"repetition-{index}"
        case.mkdir(mode=0o700)
        write(case/"suite.json", config.to_json().encode("ascii"))
        write(case/"inputs.json", dict(identity_bytes=identity_bytes, message_bytes=message_bytes,
            warm_repetitions=warm_repetitions, security_group=security_group, source_commit=source_commit))
        generated = run_child(case)
        restored = run_child(case, restore=True)
        records.append(dict(generation=generated, restore=restored))
        print(f"repetition {index+1}/{repetitions} generation, cached operations and zero-entropy restore passed", flush=True)
    timings = {}
    for record in records:
        for mode in ("generation", "restore"):
            for row in record[mode]["phases"]:
                timings.setdefault(row["name"], []).append(row["seconds"])
    report = dict(schema="FULL-IBME-BENCHMARK/1", status="passed", source_commit=source_commit,
        selection=selection, suite=config.to_dict(), security_group=security_group,
        cross_security_group_ranking=False, repetitions=repetitions, warm_repetitions_per_state=warm_repetitions,
        identity_bytes=identity_bytes, message_bytes=message_bytes, records=records,
        timing_seconds={name:summarize(values) for name, values in timings.items()},
        environment=environment(), uses_ROM=True, security_claim="none", backend_admitted=False,
        parameters_are_formal=False, randomness="system CSPRNG, no fixed seed and no outer retry",
        measurements_scope="public protocol APIs, wrappers, validation, wire encode/decode and native launches; new Python process per generation/restore; built engines and OS page caches retained",
        uncertainty="3 cold states are a small empirical sample; 10ms RSS sampling may miss spikes; warm observations share each state and are not independent roots")
    write(directory/"receipt.json", report)
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--private-directory", type=Path)
    p.add_argument("--suite-file", type=Path)
    p.add_argument("--suite-name")
    p.add_argument("--repetitions", type=int, default=3)
    p.add_argument("--warm-repetitions", type=int, default=3)
    p.add_argument("--message-bytes", type=int, default=32)
    p.add_argument("--identity-bytes", type=int, default=64)
    p.add_argument("--security-group", default="research-unranked")
    p.add_argument("--source-commit", default="development")
    p.add_argument("--worker-directory", type=Path)
    p.add_argument("--restore-worker", action="store_true")
    args = p.parse_args()
    if args.worker_directory:
        worker(args.worker_directory, restore=args.restore_worker)
        return
    if not args.private_directory or not args.suite_file or not args.suite_name:
        p.error("provide --private-directory, --suite-file and --suite-name")
    cases = json.loads(args.suite_file.read_bytes())
    matches = [case for case in cases if case["name"] == args.suite_name]
    if len(matches) != 1: raise ValueError("select exactly one existing named suite")
    run(args.private_directory, matches[0]["selection"], repetitions=args.repetitions,
        warm_repetitions=args.warm_repetitions, message_bytes=args.message_bytes,
        identity_bytes=args.identity_bytes, security_group=args.security_group, source_commit=args.source_commit)


if __name__ == "__main__": main()
