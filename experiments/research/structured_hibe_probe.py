"""One real structured H/G root, two receivers, four fixed 256-target leaves.

All private outputs remain in the explicitly named NEW ignored directory.
Failure consumes that directory: never regenerate or retry a failed slot.
Restore-only checks the existing objects with every random byte forbidden.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import sys
import tempfile
import time
from unittest.mock import patch

from ibme.core.randomness import SecureRandom
from ibme.hibe.mp12_structured.backend import StructuredMP12HIBE, _noise
from ibme.hibe.mp12_structured.params import StructuredHIBEParams
from ibme.hibe.mp12_structured.objects import (StructuredPublicKey, StructuredMasterSecret,
    StructuredLevel1Key, StructuredLevel2Key, StructuredCiphertext)

RECEIVERS = (b"B"*86, b"C"*86)
SENDERS = (b"A"*86, b"D"*86)
PAYLOAD = bytes(range(32))


class CountedSystem:
    def __init__(self): self.source, self.bytes, self.reads = SecureRandom(), 0, 0
    def read(self, count):
        value = self.source.read(count)
        self.bytes += len(value); self.reads += 1
        return value


def save(path, value):
    raw = value if type(value) is bytes else (json.dumps(value, indent=2)+"\n").encode()
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".structured-hibe-", delete=False) as stream:
        tmp = Path(stream.name)
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    os.replace(tmp, path)


def sources():
    result = {}
    for name, module in list(sys.modules.items()):
        path = getattr(module, "__file__", None)
        if path and path.endswith(".py") and (name.startswith("ibme.") or name.startswith("experiments.research.")):
            p = Path(path).resolve()
            result[name] = dict(path=str(p), sha256=hashlib.sha256(p.read_bytes()).hexdigest())
    result[__name__] = dict(path=str(Path(__file__).resolve()), sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    return result


def restore(directory):
    calls = 0
    def forbidden(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("structured H/G restoration attempted entropy")
    backend = StructuredMP12HIBE()
    with patch.object(SecureRandom, "read", forbidden):
        public = StructuredPublicKey.from_bytes((directory/"public.bin").read_bytes())
        master = StructuredMasterSecret.from_bytes((directory/"master.bin").read_bytes())
        for index, receiver in enumerate(RECEIVERS):
            parent = backend.extract(master, receiver, rng=type("NoEntropy", (), {"read": forbidden})())
            assert parent.to_bytes() == (directory/f"parent-{index}.bin").read_bytes()
            for j, sender in enumerate(SENDERS):
                leaf = backend.derive(parent, sender, rng=type("NoEntropy", (), {"read": forbidden})())
                raw = (directory/f"leaf-{index}-{j}.bin").read_bytes()
                assert leaf.to_bytes() == raw
                leaf = StructuredLevel2Key.from_bytes(raw)
                ciphertext = StructuredCiphertext.from_bytes((directory/f"ciphertext-{index}-{j}.bin").read_bytes())
                assert backend.validate_key_binding(public, leaf)
                assert backend.decrypt(leaf, ciphertext) == PAYLOAD
        assert public.to_bytes() == (directory/"public.bin").read_bytes()
        assert master.to_bytes() == (directory/"master.bin").read_bytes()
    return dict(status="passed", entropy_reads=calls, new_roots=0, new_keys=0,
        matching_paths=4, object_kinds=5, state_unchanged=True)


def run(directory, commit):
    if len(PAYLOAD) != 32: raise AssertionError("exact 32-byte probe payload")
    directory.mkdir(parents=True, exist_ok=False)
    save(directory/"started", b"fixed one-attempt structured H/G probe\n")
    start, phases, system = time.perf_counter(), [], CountedSystem()
    params = StructuredHIBEParams()
    backend = StructuredMP12HIBE(persist_pending=lambda obj: save(directory/("master.bin" if isinstance(obj, StructuredMasterSecret) else f"parent-{RECEIVERS.index(obj.identity)}.bin"), obj.to_bytes()))
    def phase(name, operation):
        before, byte0, read0 = time.perf_counter(), system.bytes, system.reads
        result = operation()
        phases.append(dict(name=name, seconds=time.perf_counter()-before,
            entropy_bytes=system.bytes-byte0, entropy_reads=system.reads-read0))
        save(directory/"progress.json", dict(stage=name, phases=phases))
        print(name, "passed", flush=True)
        return result
    try:
        public, master = phase("setup", lambda: backend.setup(params, rng=system))
        save(directory/"public.bin", public.to_bytes()); save(directory/"master.bin", master.to_bytes())
        leaves, ciphertexts = [], []
        for i, receiver in enumerate(RECEIVERS):
            parent = phase(f"extract-{i}", lambda: backend.extract(master, receiver, rng=system))
            save(directory/f"parent-{i}.bin", parent.to_bytes()); save(directory/"master.bin", master.to_bytes())
            for j, sender in enumerate(SENDERS):
                leaf = phase(f"derive-{i}-{j}", lambda: backend.derive(parent, sender, rng=system))
                save(directory/f"leaf-{i}-{j}.bin", leaf.to_bytes())
                save(directory/f"parent-{i}.bin", parent.to_bytes()); save(directory/"master.bin", master.to_bytes())
                ct = phase(f"encrypt-{i}-{j}", lambda: backend.encrypt(public, receiver, sender, PAYLOAD, rng=system))
                assert backend.decrypt(leaf, ct) == PAYLOAD
                save(directory/f"ciphertext-{i}-{j}.bin", ct.to_bytes())
                leaves.append(leaf); ciphertexts.append(ct)
        wrong = sum(backend.decrypt(leaf, ct) != PAYLOAD for i, leaf in enumerate(leaves)
                    for j, ct in enumerate(ciphertexts) if i != j)
        assert wrong == 12
        # Existing public-only n2 attack: no master, R, preimages, RNG or saved
        # entropy is an input. This demonstrates the research parameters' gap.
        from experiments.attacks.chkp_small_dimension import recover_seed_hashes
        attack = recover_seed_hashes(public.oracle, RECEIVERS[0], SENDERS[0],
            ciphertexts[0].capsule, _noise(params).params.radius, max_candidates=100000)
        assert hashlib.sha256(PAYLOAD).hexdigest() in attack["recovered_seed_sha256"]
        report = dict(schema="MP12-STRUCTURED-FULL-HG-LIFECYCLE/1", status="passed",
            source_commit=commit, parameters=params.record(), noise_budget=params.noise_budget(),
            noise_certificate=_noise(params).certificate(), phases=phases,
            matching_paths=4, wrong_key_inequalities=wrong, receivers=2, fixed_leaves=4,
            actual_preimages=4*256, full_H_columns=params.m, expanded_full_kernel_bases=0,
            plaintext_bytes=32, identity_bytes=86, repetitions=1, uses_ROM=True,
            system_randomness=True, public_n2_attack=attack,
            seconds=time.perf_counter()-start, peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            environment=dict(python=platform.python_version(), platform=platform.platform(),
                processor=platform.processor(), OMP_NUM_THREADS=os.getenv("OMP_NUM_THREADS"),
                OPENBLAS_NUM_THREADS=os.getenv("OPENBLAS_NUM_THREADS")),
            providers=sources(), security_claim="none", backend_admitted=False, parameters_are_formal=False)
        save(directory/"receipt.json", report)
        save(directory/"completed", b"passed\n")
        print(json.dumps(dict(status="passed", seconds=report["seconds"], paths=4)), flush=True)
        return report
    except Exception as exc:
        save(directory/"failure.json", dict(status="failed", stage=phases[-1]["name"] if phases else "before setup",
            exception_type=type(exc).__name__, message=str(exc), retry_forbidden=True))
        raise


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--private-directory", required=True, type=Path)
    p.add_argument("--source-commit", default="development")
    p.add_argument("--restore-only", action="store_true")
    args = p.parse_args()
    if args.restore_only:
        if not (args.private_directory/"completed").is_file(): raise ValueError("completed original required")
        print(json.dumps(restore(args.private_directory)), flush=True)
    else: run(args.private_directory, args.source_commit)


if __name__ == "__main__": main()
