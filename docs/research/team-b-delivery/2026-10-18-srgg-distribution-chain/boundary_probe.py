"""Deterministic boundary probe for the SRGG good-root set.

The probe searches CBD1 witnesses whose Fourier operator norm is just below
the exact C-gate threshold T_C, then feeds the witness to the unchanged
``SourceSchurBackend.setup`` and to the complete distribution-chain gate set.
A root just below T_C has C just above 64 I: it is the worst case for the
good-root implication.

This is functional evidence for the interval implementation.  It is not a
probability estimate, a security proof or a random sample of the Setup law.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path

import numpy as np

from ibme.core.randomness import DeterministicRandom
from experiments.research.candidates.srgg.paper_distribution_chain import (
    SECURITY_FIELDS, good_root_constants, require_gates,
)
from experiments.research.candidates.srgg.paper_issuance_bridge import fixed_root_c_gate
from experiments.research.candidates.srgg.paper_parameters import PaperParams
from experiments.research.candidates.srgg.paper_schur_backend import SourceSchurBackend
from experiments.research.candidates.srgg.paper_source_issuance_bridge import (
    _source_key_guard_envelope,
)


class _FixedBytes:
    def __init__(self, data):
        self.data = bytearray(data)

    def read(self, count):
        if count < 0 or len(self.data) < count:
            raise ValueError("fixed boundary byte stream exhausted")
        result = bytes(self.data[:count])
        del self.data[:count]
        return result


def _lambda_max(coefficients):
    """max_frequency largest singular value squared of the ring matrix."""
    n = coefficients.shape[-1]
    twist = np.exp(1j * np.pi * np.arange(n) / n)
    spectrum = np.fft.fft(coefficients * twist, axis=-1)[..., : n // 2]
    matrices = spectrum.transpose(2, 0, 1)
    gram = np.einsum("fij,fkj->fik", matrices, matrices.conj())
    return float(np.linalg.eigvalsh(gram)[:, -1].max().real)


def _pack(coefficients):
    flat = coefficients.reshape(-1)
    data = bytearray(len(flat))
    for index, value in enumerate(flat):
        data[index] = 0 if value == 0 else (1 if value > 0 else 2)
    return bytes(data)


def _search(profile, interpretation, *, samples, seed, margin):
    params = PaperParams(profile, interpretation)
    constants = good_root_constants(profile, interpretation)
    threshold = float(Fraction(constants["threshold_C_gate_squared_exact"]))
    rows, columns, n = 2 * params.rank, params.digits * params.rank, params.degree
    rng = np.random.default_rng(seed)
    best = None
    examined = 0
    while examined < samples:
        count = min(2000, samples - examined)
        bits = rng.integers(0, 2, size=(count, rows, columns, n, 2),
                            dtype=np.int8)
        coefficients = bits[..., 0] - bits[..., 1]
        for index in range(count):
            value = _lambda_max(coefficients[index])
            examined += 1
            if value < threshold and (best is None or value > best[0]):
                best = (value, coefficients[index].copy())
        if best is not None and best[0] > threshold - margin:
            break
    if best is None:
        raise SystemExit("no C-accepting witness found; increase --samples")
    value, coefficients = best
    witness = _pack(coefficients)
    backend = SourceSchurBackend(
        rng=_FixedBytes(bytes(32) + witness), setup_max_attempts=1)
    public, master = backend.setup(params)
    plan = backend._master_plan(params, master.witness)
    gadget, _scalar = backend._components(params)
    audit, extras = require_gates(
        plan, params=params, gadget=gadget, root_phase=True)
    c_gate = fixed_root_c_gate(plan.geometry, lower_bound=64, precision_bits=192)
    envelope = _source_key_guard_envelope(params, plan, gadget)
    backend.rng = DeterministicRandom(
        ("boundary-extract-" + profile + "-" + interpretation).encode("ascii"))
    key = backend.key_extract(master, b"Alice")
    message = b"boundary probe message 32 bytes!"
    signature = backend.sign(key, message)
    verified = backend.verify(public, b"Alice", message, signature)
    return {
        "profile": profile,
        "interpretation": interpretation,
        "threshold_C_squared_exact": constants["threshold_C_gate_squared_exact"],
        "witness_lambda_max": value,
        "witness_gap_to_C": threshold - value,
        "witness_sha256": sha256(witness).hexdigest(),
        "samples_examined": examined,
        "search_seed": seed,
        "setup_attempts": backend.setup_attempts,
        "extract_calls": backend.extract_calls,
        "sign_attempts": backend.sign_attempts,
        "all_gates": {
            "setup_returned": True,
            "c_gate": c_gate["certified"],
            "master_audit": audit.public_certificate()[
                "all_ideal_schur_pivot_eigenvalues_at_least_64"],
            "object_envelope": envelope[
                "raw_and_key_within_256bit_object_guard"],
            "verify": verified,
        },
        "functional_pass": bool(c_gate["certified"] and verified),
        "scope": "one deterministic worst-case witness; not a probability or "
                 "security proof",
        **SECURITY_FIELDS,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("PARAM-I", "PARAM-II", "PARAM-III"),
                        required=True)
    parser.add_argument("--interpretation", choices=(
        "table-standard-deviation", "literal-density-width"),
        default="literal-density-width")
    parser.add_argument("--samples", type=int, default=20000)
    parser.add_argument("--seed", type=int, default=20261018)
    parser.add_argument("--margin", type=float, default=0.01)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("output path already exists")
    if not 1 <= args.samples <= 200000:
        raise SystemExit("--samples must be in [1, 200000]")
    result = _search(args.profile, args.interpretation,
                     samples=args.samples, seed=args.seed, margin=args.margin)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2),
                           encoding="utf-8")
    print(json.dumps({"output": str(args.output), "pass": result["functional_pass"],
                      "gap": result["witness_gap_to_C"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
