"""Verify the SRGG random-key signing-law audit package and live six-row replay."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

from experiments.research.candidates.srgg.paper_random_key_sign_law import (
    SCHEMA, build_report, conditional_random_key_bound,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PREFIX = "docs/research/team-b-delivery/2026-10-18-srgg-random-key-sign-law/"
REQUIRED = {
    "experiments/research/candidates/srgg/paper_random_key_sign_law.py",
    "tests/test_srgg_paper_random_key_sign_law.py",
    PREFIX + "README.md", PREFIX + "README_zh-CN.md",
    PREFIX + "proof.md", PREFIX + "random-key-sign-law.json",
    PREFIX + "validation.json", PREFIX + "verify_delivery.py",
    "experiments/research/candidates/srgg/paper_distribution_guard.py",
    "experiments/research/candidates/srgg/paper_schur_backend.py",
    "src/ibme/ibs/srgg_paper_service.py",
    "tests/test_srgg_paper_distribution_guard.py",
    "tests/test_srgg_paper_service_default.py",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical_bytes(name):
    require(type(name) is str and name and "\\" not in name,
            "canonical package path required")
    relative = Path(name)
    require(not relative.is_absolute() and
            all(part not in ("", ".", "..") for part in relative.parts),
            "unsafe package path")
    path = (ROOT / relative).resolve()
    require(path.is_relative_to(ROOT) and path.is_file(),
            "package path escaped or missing")
    raw = path.read_bytes()
    require(raw.count(b"\r") == raw.count(b"\r\n"),
            "noncanonical text line ending")
    return raw.replace(b"\r\n", b"\n")


def main():
    manifest = json.loads((HERE / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest.get("entries")
    require(manifest.get("schema") == "IBME/SRGG-PAPER-RANDOM-KEY-SIGN-LAW-MANIFEST/1"
            and type(entries) is dict and set(entries) == REQUIRED,
            "manifest coverage or schema mismatch")
    for name, expected in entries.items():
        require(type(expected) is dict and set(expected) == {"bytes", "sha256"}
                and type(expected["bytes"]) is int and expected["bytes"] >= 0
                and type(expected["sha256"]) is str and len(expected["sha256"]) == 64,
                "manifest entry syntax")
        raw = canonical_bytes(name)
        require(len(raw) == expected["bytes"] and
                sha256(raw).hexdigest() == expected["sha256"],
                "manifest byte mismatch: " + name)
    validation = json.loads((HERE / "validation.json").read_text(encoding="utf-8"))
    require(validation.get("schema") == "IBME/SRGG-PAPER-RANDOM-KEY-SIGN-LAW-VALIDATION/1"
            and validation.get("targeted_tests", {}).get("passed") == 17
            and validation.get("targeted_tests", {}).get("failed") == 0
            and validation.get("report_generation", {}).get("rows") == 6
            and validation.get("report_generation", {}).get("full_random_key_history") is None
            and validation.get("report_generation", {}).get("replay_byte_equal_to_frozen") is True
            and validation.get("report_generation", {}).get("frozen_report_sha256") ==
                sha256((HERE / "random-key-sign-law.json").read_bytes()).hexdigest()
            and validation.get("security_claim") == "none",
            "validation claim exceeds evidence")
    report = json.loads((HERE / "random-key-sign-law.json").read_text(encoding="utf-8"))
    require(report.get("schema") == SCHEMA and len(report.get("rows", [])) == 6
            and report.get("full_random_issuance_signing_history_tv") is None
            and report.get("security_claim") == "none"
            and report.get("backend_admitted") is False
            and report.get("parameters_are_formal") is False
            and report.get("nist_security_category") is None,
            "report scope falsely promoted")
    expected_pairs = [(p, i) for p in ("PARAM-I", "PARAM-II", "PARAM-III")
                      for i in ("table-standard-deviation", "literal-density-width")]
    require([(r.get("profile"), r.get("interpretation")) for r in report["rows"]]
            == expected_pairs, "original Table 4 row order changed")
    expected_thresholds = {"PARAM-I": 268010, "PARAM-II": 331565,
                           "PARAM-III": 386948}
    for row in report["rows"]:
        require(row["obstruction"]["constant_coefficient"] ==
                expected_thresholds[row["profile"]]
                and row["canonical_replay"]["canonical_synthetic_key_roundtrip"] is True
                and row["canonical_replay"]["unchanged_source_sign_plan_rejects"] is True
                and row["obstruction_below_coarse_finite_envelope"] is True
                and row["bad_key_mass_under_mathematical_issuance_reference"] is None
                and row["uniform_good_key_sign_call_tv"] is None
                and row["one_random_issued_key_then_two_sign_calls_tv"] is None
                and row["actual_finite_issuance_mass_of_this_tail"] is None,
                "random-key result or null premises changed")
    require(conditional_random_key_bound(
        issuance_tv="1/100", bad_key_mass=None,
        good_key_sign_call_tv=None, sign_calls=2) is None,
        "missing bad-key or good-key premise silently accepted")
    require(build_report() == report, "live original-row replay differs from frozen receipt")
    print(json.dumps({"status": "verified", "entries": len(entries),
                      "rows": len(report["rows"]), "random_key_history": None,
                      "security_claim": "none"}, sort_keys=True))


if __name__ == "__main__":
    main()
