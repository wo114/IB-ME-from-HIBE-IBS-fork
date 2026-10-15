"""System-entropy structured H/G framework tree and common six-IBS replay.

The framework tree uses the unmodified Hybrid identity encoding. The separate
primitive probe's literal 86-byte identities are not passed off as these keys.
Only explicit restoration replaces Setup in the subsequent common driver;
the selected primitive factories and all acceptance checks remain unchanged.
"""

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import time
from unittest.mock import patch

from ibme.assembly import make_suite, build_runtime
from ibme.core.randomness import SecureRandom
from ibme.hibe.mp12_structured import (StructuredPublicKey, StructuredMasterSecret,
    StructuredMP12HIBE)
from ibme.ibs.luo_module_profiles import c64b_params
from ibme.protocol.baseline import PublicKey, MasterSecret, SenderKey, ReceiverKey
from ibme.protocol.hybrid_hibe import HybridPublicKey, HybridMasterSecret
from experiments.run_combination_matrix import run_case, summarize
from experiments.research.structured_hibe_probe import save, sources

RECEIVERS, SENDERS = (b"Bob", b"Carol"), (b"Alice", b"Charlie")
MESSAGE = bytes(range(32))


class NoEntropy:
    def __init__(self): self.calls = 0
    def read(self, count):
        self.calls += 1
        raise AssertionError("restored structured tree attempted new entropy")


def generate(directory, commit):
    directory.mkdir(parents=True, exist_ok=False)
    save(directory/"started", b"one system-random structured framework tree; no retry\n")
    start, events = time.perf_counter(), []
    def event(name):
        events.append(dict(name=name, elapsed_seconds=time.perf_counter()-start))
        save(directory/"progress.json", events)
        print(name, "passed", flush=True)
    try:
        config = make_suite(hibe="mp12-structured-hg", ibs="luo-module", ibs_params=c64b_params(),
            transport="hybrid", protocol="byteauth-v1", signature_format="compact")
        runtime = build_runtime(config)
        p = runtime.proto
        public, master = p.setup(runtime.hibe_params, ibs_params=runtime.ibs_params)
        event("real-setup")
        senders = [p.skgen(master, value) for value in SENDERS]
        receivers = [p.rkgen(master, value) for value in RECEIVERS]
        event("real-two-receivers")
        wires = []
        for i, receiver in enumerate(receivers):
            for j, sender in enumerate(senders):
                ct = p.encrypt(public, sender, RECEIVERS[i], MESSAGE)
                assert p.decrypt(public, receiver, SENDERS[j], ct) == MESSAGE
                save(directory/f"ciphertext-{i}-{j}.bin", ct.to_bytes())
                wires.append((i, j, ct.to_bytes()))
                event(f"real-leaf-{i}-{j}-and-noisy-roundtrip")
        save(directory/"suite.json", config.to_json().encode())
        for name, obj in (("public.bin", public), ("master.bin", master),
                          ("hibe-public.bin", public.hpk.inner), ("hibe-master.bin", master.hmsk.inner)):
            save(directory/name, obj.to_bytes())
        for i, value in enumerate(receivers): save(directory/f"receiver-{i}.bin", value.to_bytes())
        for i, value in enumerate(senders): save(directory/f"sender-{i}.bin", value.to_bytes())
        guard = NoEntropy()
        for i, j, wire in wires:
            for r, receiver in enumerate(receivers):
                for s, sender in enumerate(SENDERS):
                    if (r, s) != (i, j): assert p.decrypt(public, receiver, sender, wire, rng=guard) is None
        assert guard.calls == 0
        event("twelve-wrong-identity-paths")
        restored = restore(directory)
        report = dict(schema="A-STRUCTURED-DEFAULT-FRAMEWORK/1", status="passed", source_commit=commit,
            suite=config.to_dict(), events=events, receivers=2, fixed_leaves=4, matching_paths=4,
            wrong_identity_paths=12, message_bytes=32, raw_identity_bytes=[5,3,5,7], inner_identity_bytes=86,
            system_randomness=True, repetitions=1, new_hibe_roots=1,
            restored=restored, seconds=time.perf_counter()-start, providers=sources(),
            security_claim="none", backend_admitted=False, parameters_are_formal=False,
            limitations=["n2 public seed recovery applies", "system tree independent of primitive literal-identity witness",
                "no timing comparison with ABB or other schemes"])
        save(directory/"receipt.json", report); save(directory/"completed", b"passed\n")
        return report
    except Exception as exc:
        save(directory/"failure.json", dict(status="failed", exception=type(exc).__name__,
            last_event=events[-1]["name"] if events else "before Setup", retry_forbidden=True))
        raise


def restore(directory):
    from ibme.assembly import SuiteConfig
    config = SuiteConfig.from_json((directory/"suite.json").read_bytes())
    runtime = build_runtime(config); p = runtime.proto; d = runtime.decoders
    guard = NoEntropy()
    with patch.object(SecureRandom, "read", lambda *a, **k: guard.read(0)):
        public = PublicKey.from_bytes((directory/"public.bin").read_bytes(), d["hpk"], d["ipk"])
        master = MasterSecret.from_bytes((directory/"master.bin").read_bytes(), d["hmsk"], d["imsk"])
        runtime.validate_master(public, master)
        for i, name in enumerate(RECEIVERS):
            receiver = ReceiverKey.from_bytes((directory/f"receiver-{i}.bin").read_bytes(), d["sk1"])
            assert p.rkgen(master, name, rng=guard).to_bytes() == receiver.to_bytes()
            for j, sender in enumerate(SENDERS):
                assert p.decrypt(public, receiver, sender, (directory/f"ciphertext-{i}-{j}.bin").read_bytes(), rng=guard) == MESSAGE
        for j, name in enumerate(SENDERS):
            sender = SenderKey.from_bytes((directory/f"sender-{j}.bin").read_bytes(), d["sk"])
            assert p.skgen(master, name).to_bytes() == sender.to_bytes()
        assert master.to_bytes() == (directory/"master.bin").read_bytes()
    return dict(status="passed", entropy_reads=guard.calls, restored_matching_paths=4,
        new_hibe_roots=0, new_hibe_keys=0, new_ibs_keys=0, state_unchanged=True)


def matrix(directory, output, commit):
    if not (directory/"completed").is_file(): raise ValueError("completed original framework tree required")
    raw_public = (directory/"hibe-public.bin").read_bytes(); raw_master = (directory/"hibe-master.bin").read_bytes()
    cases = [
        ("luo-module-c64b-compact", "luo-module", asdict(c64b_params()), "compact"),
        ("luo-matrix", "luo-matrix", "research", "reference"),
        ("wang-pw", "wang-pw", "research", "reference"),
        ("srgg", "srgg2025", "research", "reference"),
        ("cert-ml-dsa", "cert-ml-dsa", "ml-dsa-44", "reference"),
        ("cert-falcon", "cert-falcon", "falcon-padded-512", "reference"),
    ]
    with output.open("x") as stream: stream.write('{"status":"running"}\n')
    guard, results = NoEntropy(), []
    def setup(runtime, rng):
        public = StructuredPublicKey.from_bytes(raw_public); master = StructuredMasterSecret.from_bytes(raw_master)
        assert public.to_bytes() == master.public_key.to_bytes()
        assert runtime.hibe_params.inner_params == public.params
        ipk, imsk = runtime.proto.ibs_backend.setup(runtime.ibs_params)
        hpk = HybridPublicKey(runtime.hibe_params.limits, public)
        return PublicKey(hpk, ipk), MasterSecret(HybridMasterSecret(hpk, master), imsk), dict(
            new_hibe_roots=0, new_hibe_keys=0, fresh_ibs_setup=True, original_completed_tree=True)
    def forbidden(*a, **k): raise AssertionError("matrix replay called new HIBE Setup")
    def cached(function):
        def call(self, *a, **k):
            k["rng"] = guard
            return function(self, *a, **k)
        return call
    with patch.object(StructuredMP12HIBE, "setup", forbidden),\
         patch.object(StructuredMP12HIBE, "extract", cached(StructuredMP12HIBE.extract)),\
         patch.object(StructuredMP12HIBE, "derive", cached(StructuredMP12HIBE.derive)):
        for label, route, params, fmt in cases:
            result = run_case("structured-saved-"+label, dict(hibe="mp12-structured-hg", ibs=route,
                ibs_params=params, transport="hybrid", protocol="byteauth-v1", signature_format=fmt),
                setup_callback=setup, identities=(b"Alice", b"Bob", b"Carol", b"Charlie"))
            results.append(result)
            report = summarize(results)
            report.update(source_commit=commit, new_hibe_roots=0, new_hibe_keys=0,
                issuance_entropy_reads=guard.calls, providers=sources())
            save(output, report)
            print(label, result["status"], result["executed_checks"], flush=True)
            if result["status"] != "pass": raise RuntimeError("structured common combination failed: "+label)
    assert raw_public == (directory/"hibe-public.bin").read_bytes() and raw_master == (directory/"hibe-master.bin").read_bytes()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-directory", required=True, type=Path)
    parser.add_argument("--source-commit", default="development")
    parser.add_argument("--restore-only", action="store_true")
    parser.add_argument("--matrix-output", type=Path)
    args = parser.parse_args()
    if args.restore_only: result = restore(args.private_directory)
    elif args.matrix_output: result = matrix(args.private_directory, args.matrix_output, args.source_commit)
    else: result = generate(args.private_directory, args.source_commit)
    print(json.dumps(dict(status=result["status"])), flush=True)


if __name__ == "__main__": main()
