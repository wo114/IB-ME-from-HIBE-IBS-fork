"""Exact finite H1/XOF rejection budget for the original Table 4 rows.

This is conditional on independent uniform bytes at distinct ideal XOF
addresses. It is not a ROM/QROM proof for the concrete SHAKE-256 code.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

from .paper_profiles import SOURCE_PDF, SOURCE_SHA256, profiles


SCHEMA = "IBME/SRGG-PAPER-ORACLE-BUDGET/1"
ROOT = Path(__file__).resolve().parents[4]
SOURCE_FILES = (
    "experiments/research/candidates/srgg/paper_oracle_budget.py",
    "experiments/research/candidates/srgg/paper_algebra.py",
    "experiments/research/candidates/srgg/structured_execution.py",
    "experiments/research/candidates/wang_pw/hashing.py",
    "src/ibme/core/encoding.py",
    "experiments/research/candidates/srgg/paper_profiles.py",
)
MAX_TRIALS = 256
STREAM_BYTES_PER_COEFFICIENT = 4096


def row_budget(*, degree: int, rank: int, modulus: int, identity_addresses: int = 1) -> dict:
    for name, value in (("degree", degree), ("rank", rank),
                        ("modulus", modulus), ("identity_addresses", identity_addresses)):
        if type(value) is not int or value <= 0:
            raise ValueError(name + " must be a positive exact integer")
    if degree != 512 or rank not in (2, 3, 4) or modulus != 15744063:
        raise ValueError("only frozen original Table 4 rows are certified")
    if identity_addresses > 2**40:
        raise ValueError("finite query envelope required")

    width = ((modulus - 1).bit_length() + 7) // 8
    range_size = 1 << (8 * width)
    accepted_range = (range_size // modulus) * modulus
    rejected_range = range_size - accepted_range
    if not (width == 3 and accepted_range == modulus
            and 0 < rejected_range * 16 < range_size):
        raise AssertionError("published Q no longer has the checked 1/16 rejection bound")
    if width * MAX_TRIALS > STREAM_BYTES_PER_COEFFICIENT:
        raise AssertionError("actual XOF stream budget can precede trial cap")

    matrix_coefficients = rank * rank * degree
    identity_coefficients_per_address = rank * degree
    total_coefficients = matrix_coefficients + identity_addresses * identity_coefficients_per_address
    # Per coefficient: ((2^(8*width)-accepted_range)/2^(8*width))^256 < 2^-1024.
    # A union bound over the matrix and distinct identity XOF addresses is
    # strictly below 2^(-1024+ceil(log2(total_coefficients))).
    strict_union_bits = 1024 - (total_coefficients - 1).bit_length()
    if strict_union_bits <= 0:
        raise AssertionError("nontrivial ideal-byte rejection budget lost")
    return {
        "degree": degree, "rank": rank, "modulus": modulus,
        "candidate_width_bytes": width,
        "candidate_range_size": range_size,
        "accepted_range_size": accepted_range,
        "rejected_range_size": rejected_range,
        "one_candidate_rejection_probability_exact": f"{rejected_range}/{range_size}",
        "one_coefficient_exhaustion_probability_exact":
            f"({rejected_range}/{range_size})^{MAX_TRIALS}",
        "one_coefficient_exhaustion_strictly_below_2_negative": 1024,
        "max_trials_per_coefficient": MAX_TRIALS,
        "stream_budget_bytes_per_coefficient": STREAM_BYTES_PER_COEFFICIENT,
        "max_bytes_used_before_trial_cap_per_coefficient": width * MAX_TRIALS,
        "matrix_coefficients": matrix_coefficients,
        "identity_coefficients_per_distinct_address": identity_coefficients_per_address,
        "distinct_identity_addresses": identity_addresses,
        "union_coefficient_calls": total_coefficients,
        "joint_exhaustion_probability_strictly_below_2_negative": strict_union_bits,
        "bound_assumptions": (
            "one ideal independent uniform XOF byte stream per distinct framed address; "
            "the same address is memoized as one oracle value; no external faults"),
        "concrete_SHAKE_random_oracle_security_proved": False,
        "seeded_matrix_statistically_uniform_for_fixed_SHAKE_proved": False,
    }


def report() -> dict:
    pdf = ROOT / SOURCE_PDF
    if sha256(pdf.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("frozen paper checksum mismatch")
    rows = []
    for item in profiles:
        row = row_budget(degree=item.degree, rank=item.rank, modulus=item.Q)
        row["profile"] = item.name
        rows.append(row)
    return {
        "schema": SCHEMA,
        "paper": {"path": SOURCE_PDF, "sha256": SOURCE_SHA256,
                  "locations": "Table 4 PDF p.10; source algorithm hash inputs checked in code"},
        "source_sha256": {name: sha256((ROOT / name).read_bytes()).hexdigest()
                          for name in SOURCE_FILES},
        "rows": rows,
        "domain_separation": {
            "public_matrix_label": "matrix", "identity_target_label": "identity",
            "message_challenge_label": "message",
            "framing": "length-prefixed encode_bytes for every part",
            "matrix_input": "domain, label, canonical PaperParams record, 32-byte public seed",
            "identity_input": "domain, label, canonical PublicKey bytes, identity bytes",
            "message_input": "domain, label, canonical PublicKey bytes, canonical commitment, message bytes",
            "message_challenge_bits": 512,
            "message_challenge_rejection_sampling": False,
        },
        "scope": "finite rejection under ideal uniform XOF bytes; not an IBS security reduction",
        "full_RO_or_QROM_game_bound": None,
        "actual_SHAKE_distribution_to_ideal_RO_TV_upper": None,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("--output already exists")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report(), indent=2, sort_keys=True) + "\n",
                           encoding="utf-8", newline="\n")
    print(json.dumps({"status": "conditional-bound", "output": str(args.output)}))


if __name__ == "__main__":
    main()
