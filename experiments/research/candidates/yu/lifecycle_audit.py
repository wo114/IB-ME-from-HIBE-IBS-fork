"""Public-only evidence for real Yu lifecycles; never serialize sampled keys.

Run under the specified WSL Sage environment. All attempts, including failures,
are retained as counts/stages. There is no success-seeking retry loop.
"""

import argparse
import hashlib
import json
import platform
import statistics
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

from sage.env import SAGE_VERSION
from ibme.core.randomness import SecureRandom

from . import bpr
from .profiles import tiny_profile
from .standalone import setup, Authority, Signature, verify, verification_matrix

REPO = Path(__file__).resolve().parents[4]
PUBLIC_SOURCE_FILES = (
    "experiments/research/candidates/yu/circuits.py",
    "experiments/research/candidates/yu/bpr.py",
    "experiments/research/candidates/yu/evaluation.py",
    "experiments/research/candidates/yu/trapdoors.py",
    "experiments/research/candidates/yu/standalone.py",
    "experiments/research/candidates/yu/profiles.py",
    "experiments/research/candidates/yu/lifecycle_audit.py",
    "experiments/research/chkp_basis.py",
    "experiments/research/chkp_genbasis.py",
    "experiments/research/chkp_basis_reduce.py",
    "experiments/research/chkp_gpv.py",
    "experiments/research/chkp_randbasis.py",
    "experiments/research/chkp_tobasis.py",
    "experiments/research/gaussian_reference.py",
    "experiments/research/online_gaussian_reference.py",
    "experiments/research/mp12_sampled_reference.py",
    "experiments/research/general_gadget_reference.py",
    # Upstream promotes these kernels to src; hash their implementations as
    # well as the compatibility aliases above so receipts pin executed code.
    "src/ibme/lattice/chkp/basis.py",
    "src/ibme/lattice/chkp/tobasis.py",
    "src/ibme/lattice/chkp/gaussian.py",
    "src/ibme/core/randomness.py",
    "papers/2026_ibs_ibme_yu.pdf",
)


def _summary(values):
    return {"count": len(values), "seconds": values,
            "median_seconds": statistics.median(values) if values else None}


def run(attempts=3, *, source_revision=None):
    if type(attempts) is not int or not 1 <= attempts <= 20:
        raise ValueError("attempts must be in 1..20")
    if source_revision is not None and (len(source_revision) != 40 or
            any(x not in "0123456789abcdef" for x in source_revision)):
        raise ValueError("source_revision must be a full lowercase Git hash")
    # Windows-managed .git worktree pointers are not understood by WSL Git.
    # Accept an explicit verified Windows revision, and retain content hashes.
    if source_revision is None:
        for executable in ("git", "git.exe"):
            try:
                process = subprocess.run([executable, "rev-parse", "HEAD"], cwd=REPO,
                                         text=True, capture_output=True, timeout=10)
                value = process.stdout.strip()
                if process.returncode == 0 and len(value) == 40:
                    source_revision = value
                    break
            except (OSError, subprocess.TimeoutExpired):
                continue
    hashes = {name: hashlib.sha256((REPO/name).read_bytes()).hexdigest() for name in PUBLIC_SOURCE_FILES}
    p = tiny_profile()
    timings = {name: [] for name in ("setup", "keygen", "sign", "verify")}
    rows, honest, checks, lengths = [], 0, 0, []
    tamper_counts = {name: {"accepted": 0, "rejected": 0} for name in
                     ("wrong_identity", "wrong_message", "r_hat", "r_tilde", "salt")}
    toy_forgery_accepts = 0
    stage = "not_started"

    def timed(name, fn):
        start = time.perf_counter()
        result = fn()
        timings[name].append(time.perf_counter() - start)
        return result

    for number in range(attempts):
        completed_signatures = 0
        try:
            stage = "setup"
            public, master = timed("setup", lambda: setup(p, rng=SecureRandom()))
            authority = Authority(master, rng=SecureRandom())
            for identity in ((0, 1), (1, 0)):
                stage = "keygen"
                user = timed("keygen", lambda: authority.extract(identity))
                assert authority.extract(identity) is user
                for message in ((0, 0), (1, 1)):
                    stage = "sign"
                    signature = timed("sign", lambda: authority.sign(identity, message))
                    stage = "verify"
                    assert timed("verify", lambda: verify(public, identity, message, signature))
                    encoded = signature.to_bytes(p)
                    assert verify(public, identity, message, encoded)
                    assert Signature.from_bytes(encoded, p) == signature
                    lengths.append(len(encoded))
                    honest += 1
                    completed_signatures += 1
                    stage = "negative_checks"
                    assert not verify(public, identity, message, encoded[:-1])
                    assert not verify(public, identity, message, encoded+b"\x00")
                    assert not verify(public, identity, message,
                                      replace(signature, s=(0,) * p.signature_dimension))
                    assert not verify(public, identity, message,
                                      replace(signature, s=(10**10,) + signature.s[1:]))
                    checks += 4
                    matrix = verification_matrix(public, identity, message, signature)
                    column = next(j for j in range(p.evaluation.m) if any(row[j] for row in matrix))
                    changed = list(signature.s)
                    changed[column] += 1
                    assert not verify(public, identity, message, replace(signature, s=tuple(changed)))
                    checks += 1
                    for name in tamper_counts:
                        target_id, target_message, candidate = identity, message, signature
                        if name == "wrong_identity":
                            target_id = (1-identity[0],) + identity[1:]
                        elif name == "wrong_message":
                            target_message = (1-message[0],) + message[1:]
                        else:
                            value = getattr(signature, name)
                            candidate = replace(signature, **{name: (1-value[0],) + value[1:]})
                        different = verification_matrix(public, target_id, target_message, candidate)
                        expected = all(sum(a*b for a, b in zip(row, candidate.s)) % p.root.q == 0
                                       for row in different)
                        actual = verify(public, target_id, target_message, candidate)
                        assert actual == expected
                        tamper_counts[name]["accepted" if actual else "rejected"] += 1
                        checks += 1
                    forged = replace(signature, s=(p.root.q,) + (0,) * (p.signature_dimension-1))
                    assert verify(public, identity, message, forged)
                    toy_forgery_accepts += 1
            rows.append({"attempt": number+1, "status": "completed",
                         "honest_signatures": completed_signatures})
        except Exception as exc:
            # No exception text/traceback, sampled matrices, seed or geometry.
            rows.append({"attempt": number+1, "status": "failed", "stage": stage,
                         "exception_type": type(exc).__name__,
                         "honest_signatures_before_failure": completed_signatures})
    circuits = {}
    for name, spec in (("identity", p.identity_prf), ("signing", p.signing_prf)):
        # Public all-one inputs exercise every factor, independent of keys.
        circuit = bpr.compile_key_circuit(spec, (1,) * spec.params.input_bits)
        circuits[name] = {"input_bits": spec.params.input_bits,
                          "uniform_key_bits": spec.params.key_bits,
                          "output_bits": spec.params.output_bits,
                          "all_one_input_gate_count": len(circuit.gates),
                          "all_one_input_depth": circuit.depth,
                          "finite_key_distribution": spec.certificate()}
    if hashes != {name: hashlib.sha256((REPO/name).read_bytes()).hexdigest() for name in PUBLIC_SOURCE_FILES}:
        raise RuntimeError("source changed during lifecycle evidence collection")
    return {
        "schema": "IBME/YU2026/INDEPENDENT-LIFECYCLE/1",
        "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False,
        "scope": "real Figure5 research dataflow with finite Gaussian and explicit LLL adaptations",
        "source_revision": source_revision, "source_sha256": hashes,
        "source_identity_note": "content hashes identify executed files; Git revision alone does not include uncommitted files",
        "environment": {"os": platform.platform(), "python": sys.version.split()[0],
                        "sage": SAGE_VERSION, "machine": platform.machine(),
                        "processor": platform.processor(), "constant_time": False,
                        "hardware_acceleration": "none requested; Sage exact integer arithmetic"},
        "parameters": {"n": p.root.n, "q": p.root.q, "m": p.evaluation.m, "w": p.evaluation.w,
                       "signature_dimension": p.signature_dimension, "gamma_squared": p.gamma_squared,
                       "delta_squared": p.delta_squared, "max_vectors": p.max_vectors,
                       "epsilon_bits": p.epsilon_bits, "postprocess": "deterministic LLL",
                       "identity_bits": p.identity_bits, "message_bits": p.message_bits,
                       "salt_bits": p.salt_bits, "bpr_n": 2, "bpr_m": 2, "bpr_q": 32,
                       "bpr_p": 2, "bpr_gaussian_width": 2, "bpr_ticket_bits": 32},
        "randomness": "independent OS CSPRNG bytes; no seed exported; no ROM in algorithm",
        "attempts": rows, "honest_signatures": honest, "negative_or_differential_checks": checks,
        "context_mutation_results": tamper_counts,
        "public_q_times_e1_forgery_accepts": toy_forgery_accepts,
        "signature_encoding_bytes": sorted(set(lengths)),
        "timings": {name: _summary(values) for name, values in timings.items()},
        "circuits": circuits,
        "all_requested_attempts_completed": all(row["status"] == "completed" for row in rows),
        "limitations": [
            "Toy profile is publicly forgeable, and wrong-context signatures can be accepted.",
            "BPR parameter hardness, Yu key-input NC1 and Lemma7 spectral bound are not established.",
            "Finite Gaussian, bounded abort and deterministic LLL are explicit implementation adaptations.",
            "No shared backend, HIBE/IBME integration, formal security level or production timing claim.",
            "Timings include compilation and validation; tiny parameters cannot rank secure algorithms.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--source-revision", help="Optional full hash from the worktree's Windows Git")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = run(args.attempts, source_revision=args.source_revision)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"completed": receipt["all_requested_attempts_completed"],
                      "honest_signatures": receipt["honest_signatures"],
                      "checks": receipt["negative_or_differential_checks"],
                      "security_claim": "none"}))
    return 0 if receipt["all_requested_attempts_completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
