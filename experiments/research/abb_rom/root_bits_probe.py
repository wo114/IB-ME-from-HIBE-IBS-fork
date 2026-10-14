"""Generate one AP09 root and independently encrypt/decrypt eight real bits.

This is a root/bit consumer, NOT an Extract/Derive/Hybrid lifecycle. Private
root/actual ciphertexts remain beneath ignored test-results. No regeneration
on preparation, sampling or verification failure. Public receipts omit keys.
"""

import argparse
from dataclasses import asdict
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path
import platform
import re
import resource
import sys
from time import perf_counter

from ibme.core.randomness import SecureRandom
from ibme.hibe.abb_rom import ABBTrapGenParams, abb_trapgen, ABBBitPublic, ABBBitEncryptor, ABBBitDecryptor
from ibme.lattice.research import KernelBasis, ModMatrixReference
from experiments.research.gaussian_reference import draw_uniform_integer


class CountingEntropy:
    def __init__(self):
        self.source = SecureRandom()
        self.bytes_used = 0

    def read(self, size):
        raw = self.source.read(size)
        self.bytes_used += len(raw)
        return raw


def run(private_directory, baseline_commit, saved_private_directory=None):
    repo = Path(__file__).resolve().parents[3]
    private_directory = Path(private_directory).resolve()
    if not private_directory.is_relative_to((repo / "test-results").resolve()):
        raise ValueError("private outputs must remain beneath ignored test-results")
    if not isinstance(baseline_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", baseline_commit):
        raise ValueError("explicit host-verified baseline commit required before entropy")
    if private_directory.exists():
        raise FileExistsError("new private directory required; no overwrite or regeneration")
    private_directory.mkdir(parents=True)
    pending = private_directory / "pending"
    pending.write_text("AP09 setup\n", encoding="utf-8")
    params = ABBTrapGenParams(1, 549755813911, 56, 56, 192, hadamard_scale=32)
    entropy = CountingEntropy()
    receipt = {
        "profile": "ABB-AP09-ROOT-BITS-PROBE/1", "status": "running",
        "parameters": params.certificate(), "randomness": "system CSPRNG",
        "seeded_test": False, "message_bits": 8, "identity_bytes": None,
        "identities_not_applicable": "root bit experiment; no HIBE identity oracle or delegation",
        "root_generations": 0, "parent_generations": 0, "leaf_generations": 0,
        "ROM_instantiation_exercised": False, "formal_parameters": False,
        "security_claim": "none", "backend_admitted": False,
        "python": sys.version, "platform": platform.platform(), "stages": [],
        "baseline_commit": baseline_commit,
    }
    names = ["src/ibme/hibe/abb_rom/trapgen.py", "src/ibme/hibe/abb_rom/bit_encryption.py",
             "experiments/research/abb_rom/root_bits_probe.py"]
    receipt["source_sha256"] = {name: sha256((repo / name).read_bytes()).hexdigest() for name in names}
    def checkpoint():
        (private_directory / "public-progress.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    checkpoint()
    start = perf_counter()
    try:
        step = perf_counter()
        saved_ciphertexts = None
        if saved_private_directory is None:
            result = abb_trapgen(params, rng=entropy)
            basis = result.basis
            u0 = tuple(draw_uniform_integer(entropy, params.q, max_trials=params.uniform_trials)
                       for _ in range(params.n))
            public = ABBBitPublic(basis.public, u0)
            # Store a private snapshot before expensive/no-entropy preparation.
            (private_directory / "root-private.json").write_text(json.dumps({
                "schema": "ABB-AP09-PRIVATE-PROBE/1", "params": asdict(params),
                "a": basis.public.rows, "u0": u0, "basis": basis.basis_rows,
            }, separators=(",", ":")), encoding="utf-8")
            receipt["root_generations"] = 1
            name = "AP09 real root + independent uniform u0"
        else:
            saved = Path(saved_private_directory).resolve()
            if (not saved.is_relative_to((repo / "test-results").resolve()) or
                    not (saved / "completed").is_file() or (saved / "pending").exists()):
                raise ValueError("completed retained root/bit execution required")
            paths = [saved / "root-private.json", saved / "ciphertexts-private.json"]
            if any(not x.is_file() or x.stat().st_size > 16 * 2**20 for x in paths):
                raise ValueError("bounded retained private input required")
            data = json.loads(paths[0].read_text(encoding="utf-8"))
            if (set(data) != {"schema", "params", "a", "u0", "basis"}
                    or data["schema"] != "ABB-AP09-PRIVATE-PROBE/1" or data["params"] != asdict(params)):
                raise ValueError("retained root profile differs")
            if (len(data["a"]) != params.n or len(data["basis"]) != params.dimension
                    or any(len(row) != params.dimension for row in data["a"] + data["basis"])
                    or any(type(x) is not int or not 0 <= x < params.q for row in data["a"] for x in row)
                    or any(type(x) is not int or abs(x).bit_length() > 4096 for row in data["basis"] for x in row)):
                raise ValueError("retained root dimensions/coefficient limits differ")
            basis = KernelBasis(ModMatrixReference(data["a"], params.q), data["basis"])
            public = ABBBitPublic(basis.public, data["u0"])
            saved_ciphertexts = json.loads(paths[1].read_text(encoding="utf-8"))
            if not isinstance(saved_ciphertexts, list) or len(saved_ciphertexts) != 8:
                raise ValueError("eight retained independent bit ciphertexts required")
            receipt["retained_core_execution"] = True
            receipt["original_timings_and_entropy"] = None
            receipt["original_metadata_failure"] = "WSL git cannot resolve a Windows managed-worktree gitdir"
            receipt["new_encryptions"] = 0
            name = "restore retained real AP09 root and bit ciphertexts"
        receipt["stages"].append({"name": name, "status": "passed",
            "seconds": perf_counter() - step, "entropy_bytes": entropy.bytes_used,
            "complete_kernel_verified": True, "dimension": params.dimension})
        checkpoint()
        pending.write_text("GPV preparation\n", encoding="utf-8")
        before = entropy.bytes_used
        step = perf_counter()
        factor = (2 * params.dimension * (1 + 2**128) - 1).bit_length()
        tau_squared = 4 * params.gs_squared_bound * factor
        encryptor = ABBBitEncryptor(public, Fraction(4, params.q))
        decryptor = ABBBitDecryptor(public, basis, tau_squared, epsilon_bits=128)
        receipt["stages"].append({"name": "GPV and rounded-noise preparation", "status": "passed",
            "seconds": perf_counter() - step, "entropy_bytes": entropy.bytes_used - before,
            "tau_squared": str(tau_squared), "geometry_tv_upper": str(decryptor.sampler.geometry_tv),
            "C1_exec_and_scalar_resource_gates_verified": True,
            "basis_dependent_scalar_and_tape_diagnostics_published": False,
            "noise": encryptor.certificate()})
        checkpoint()
        ciphertexts = []
        for index, bit in enumerate([0, 1, 1, 0, 1, 0, 0, 1]):
            pending.write_text(f"bit {index}\n", encoding="utf-8")
            step = perf_counter()
            before = entropy.bytes_used
            if saved_ciphertexts is None:
                ct = encryptor.encrypt(bit, rng=entropy)
            else:
                from ibme.hibe.abb_rom import ABBBitCiphertext
                item = saved_ciphertexts[index]
                if not isinstance(item, dict) or set(item) != {"q", "c0", "c1"}:
                    raise ValueError("retained ciphertext fields differ")
                ct = ABBBitCiphertext(**item)
            recovered = decryptor.decrypt(ct, rng=entropy)
            ok = recovered == bit
            receipt["stages"].append({"name": f"independent bit {index}", "status": "passed" if ok else "failed",
                "seconds": perf_counter() - step, "entropy_bytes": entropy.bytes_used - before,
                "fresh_SamplePre": True, "honest_bit_matches": ok})
            checkpoint()
            ciphertexts.append(asdict(ct))
            if not ok:
                raise ArithmeticError("actual AP09-root bit decryption mismatch")
        (private_directory / "ciphertexts-private.json").write_text(
            json.dumps(ciphertexts, separators=(",", ":")), encoding="utf-8")
        receipt["status"] = "passed"
        pending.rename(private_directory / "completed")
    except Exception as exc:
        receipt["status"] = "failed"
        receipt["failure_type"] = type(exc).__name__
        receipt["failed_stage"] = pending.read_text(encoding="utf-8").strip()
        # Do not emit exception text containing private arithmetic diagnostics.
    receipt["seconds"] = perf_counter() - start
    receipt["entropy_bytes"] = entropy.bytes_used
    receipt["process_peak_rss_kib"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    receipt["full_HIBE_backend_tested"] = False
    receipt["not_covered"] = ["identity SampleR", "Extract/Derive", "key/ciphertext codec",
                              "Hybrid/IBME attacks", "matrix RO", "LWE hardness"]
    checkpoint()
    return receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--private-directory", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--baseline-commit", required=True)
    parser.add_argument("--saved-private-directory")
    args = parser.parse_args()
    output = Path(args.output)
    if output.exists():
        raise FileExistsError("new public receipt required")
    receipt = run(args.private_directory, args.baseline_commit, args.saved_private_directory)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"status": receipt["status"], "seconds": receipt["seconds"],
                      "root_generations": receipt["root_generations"], "stages": len(receipt["stages"])}))
    return 0 if receipt["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
