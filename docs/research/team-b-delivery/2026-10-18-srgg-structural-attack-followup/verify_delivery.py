"""Verify selected source/evidence bytes and the bounded public receipt.

This is a selected-file integrity check, not a full dependency closure or a
security proof. It deliberately does not import Sage or execute a signature.
"""
from __future__ import annotations

from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
PACKAGE = Path(__file__).resolve().parent
SOURCES = (
    "experiments/research/candidates/srgg/paper_structural_attack_followup.py",
    "experiments/research/candidates/srgg/paper_profiles.py",
    "experiments/research/candidates/srgg/paper_parameters.py",
    "experiments/research/candidates/srgg/paper_algebra.py",
    "experiments/research/candidates/srgg/paper_backend.py",
    "experiments/research/candidates/srgg/paper_schur_backend.py",
    "experiments/research/candidates/srgg/paper_objects.py",
    "experiments/research/candidates/srgg/structured_execution.py",
    "experiments/research/candidates/srgg/paper_hardness_preflight.py",
    "tests/test_srgg_paper_structural_attack_followup.py",
)
PREFIX = "docs/research/team-b-delivery/2026-10-18-srgg-structural-attack-followup/"
EVIDENCE = tuple(PREFIX + name for name in (
    "README.md", "README_zh-CN.md", "proof.md",
    "structural-attack-followup.json", "validation.json", "verify_delivery.py",
))
SELECTED = SOURCES + EVIDENCE


def check(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(path: Path) -> str:
    return sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def verify() -> dict:
    manifest = json.loads((PACKAGE / "MANIFEST.json").read_text(encoding="utf-8"))
    check(manifest.get("schema") == "IBME/SRGG-PAPER-STRUCTURAL-ATTACK-FOLLOWUP-MANIFEST/1",
          "manifest schema differs")
    files = manifest.get("files")
    check(type(files) is dict and set(files) == set(SELECTED), "selected files differ")
    for name in SELECTED:
        check(digest(ROOT / name) == files[name], "file digest differs: " + name)
    receipt = json.loads((PACKAGE / "structural-attack-followup.json").read_text(encoding="utf-8"))
    validation = json.loads((PACKAGE / "validation.json").read_text(encoding="utf-8"))
    check(receipt.get("schema") == "IBME/SRGG-PAPER-STRUCTURAL-ATTACK-FOLLOWUP/1",
          "receipt schema differs")
    check(receipt["paper"] == {"path": validation["source"]["path"],
                               "sha256": validation["source"]["sha256"],
                               "locations": "Table 4; Algorithms 7-8; Section 5.2 and Table 5"},
          "paper source differs")
    check(sha256((ROOT / receipt["paper"]["path"]).read_bytes()).hexdigest()
          == receipt["paper"]["sha256"], "frozen PDF differs")
    for name, expected in receipt["source_sha256"].items():
        check(name in SOURCES and digest(ROOT / name) == expected,
              "receipt source digest differs: " + name)
    rows = receipt["rows"]
    check(len(rows) == 3, "Table 4 row count differs")
    for row, name, rank in zip(rows, ("PARAM-I","PARAM-II","PARAM-III"), (2,3,4)):
        Q = row["Q"]
        gamma = Fraction(row["published_gamma"])
        cap = (gamma*gamma).numerator // (gamma*gamma).denominator
        check((row["profile"],row["n"],row["d"],row["w"],Q)
              == (name,512,rank,2,15744063), "original parameters differ")
        check(row["restricted_minimum_norm_squared"] == 2*Q*Q
              and row["published_norm_squared_cap"] == cap
              and row["witness_inside_single_signature_radius"] == (2*Q*Q <= cap),
              "kernel norm or published cap differs")
        check(row["universal_for_every_public_A_and_identity_h"] is True
              and row["explicit_construction_BKZ_calls"] == 0,
              "exact kernel scope differs")
        check([item["prime_power"] for item in row["CRT_component_lift_floors"]]
              == [3,961,43,127], "prime-power CRT changed")
        for item in row["CRT_component_lift_floors"]:
            check(item["nonzero_centered_coefficient_abs_lower"]
                  == Q//item["prime_power"]
                  and item["global_short_solution_or_attack_cost_inferred"] is False,
                  "CRT lift floor promoted")
        check(all(row[key] is None for key in (
            "full_ring_HNF_MSIS_attack_cost", "CRT_subfield_attack_cost",
            "successful_replacement_probability")), "unknown row cost promoted")
    actual = receipt["one_actual_signature_probe"]
    probe = actual["probe"]
    check(actual["profile"] == "PARAM-I" and actual["signature_queries"] == 1,
          "actual signature probe scope differs")
    check(all(probe[key] is True for key in (
        "valid_original_required_and_checked", "published_last_column_checked",
        "all_rows_kernel_checked", "canonical_alternative_object",
        "recovered_commitment_equal", "distinct_canonical_signature")),
        "actual public relation checks differ")
    check(probe["tested_pair_positions"] == 256
          and probe["eligible_pair_positions"] == 0
          and probe["best_shift_norm_squared"] > probe["signature_norm_squared_cap"]
          and probe["best_replacement_accepted"] is False
          and probe["success_probability"] is None,
          "actual norm-gate evidence promoted")
    check(all(route["actual_attack_cost"] is None for route in receipt["routes"]),
          "route cost promoted")
    check(all(receipt[key] is None for key in (
        "full_ring_HNF_MSIS_attack_cost", "CRT_subfield_attack_cost",
        "accepted_setup_root_structural_attack_cost")), "unknown attack cost promoted")
    for item in rows + [receipt, validation]:
        check(item["security_claim"] == "none"
              and item["backend_admitted"] is False
              and item["parameters_are_formal"] is False
              and item["nist_security_category"] is None,
              "security status promoted")
    return {"selected_files_verified": len(SELECTED),
            "profiles_verified": [row["profile"] for row in rows],
            "security_claim": "none"}


if __name__ == "__main__":
    print(json.dumps(verify(), sort_keys=True))
