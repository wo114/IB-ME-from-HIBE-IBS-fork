"""Verify SRGG adaptive-history package bytes, one live replay, and claim limits."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

from experiments.research.candidates.srgg.paper_history_law_followup import (
    SCHEMA as HISTORY_SCHEMA, certificate,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PREFIX = "docs/research/team-b-delivery/2026-10-18-srgg-history-law-followup/"
SOURCE = "experiments/research/candidates/srgg/paper_history_law_followup.py"
TEST = "tests/test_srgg_paper_history_law_followup.py"
REQUIRED = {
    SOURCE, TEST, PREFIX + "README.md", PREFIX + "README_zh-CN.md",
    PREFIX + "proof.md", PREFIX + "history-law.json",
    PREFIX + "validation.json", PREFIX + "verify_delivery.py",
}


def require(value, message):
    if not value:
        raise ValueError(message)


def file_at(name):
    require(type(name) is str and name and "\\" not in name, "canonical path required")
    relative = Path(name)
    require(not relative.is_absolute() and
            all(part not in ("", ".", "..") for part in relative.parts),
            "unsafe package path")
    path = (ROOT / relative).resolve()
    require(path.is_relative_to(ROOT) and path.is_file(), "package file escaped or missing")
    return path


def delivery_bytes(name):
    raw = file_at(name).read_bytes()
    require(raw.count(b"\r") == raw.count(b"\r\n"), "noncanonical text line endings")
    return raw.replace(b"\r\n", b"\n")


def main():
    manifest = json.loads((HERE / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest.get("entries")
    require(manifest.get("schema") == "IBME/SRGG-PAPER-ADAPTIVE-HISTORY-DELIVERY-MANIFEST/1"
            and type(entries) is dict and set(entries) == REQUIRED, "manifest coverage")
    for name, expected in entries.items():
        require(type(expected) is dict and set(expected) == {"bytes", "sha256"}
                and type(expected["bytes"]) is int and expected["bytes"] >= 0
                and type(expected["sha256"]) is str and len(expected["sha256"]) == 64,
                "manifest entry syntax")
        raw = delivery_bytes(name)
        require(len(raw) == expected["bytes"] and
                sha256(raw).hexdigest() == expected["sha256"],
                "manifest byte mismatch: " + name)
    validation = json.loads((HERE / "validation.json").read_text(encoding="utf-8"))
    require(validation.get("schema") == "IBME/SRGG-PAPER-ADAPTIVE-HISTORY-VALIDATION/1"
            and validation.get("targeted_tests", {}).get("passed") == 18
            and validation.get("targeted_tests", {}).get("failed") == 0
            and validation.get("report_generation", {}).get("rows") == 6
            and validation.get("report_generation", {}).get("full_history") is None
            and validation.get("security_claim") == "none", "validation scope drift")
    report = json.loads((HERE / "history-law.json").read_text(encoding="utf-8"))
    require(report.get("schema") == HISTORY_SCHEMA + "/REPORT"
            and report.get("full_random_issuance_signature_fault_history_tv") is None
            and report.get("security_claim") == "none"
            and report.get("backend_admitted") is False
            and report.get("parameters_are_formal") is False
            and report.get("nist_security_category") is None, "aggregate report scope drift")
    rows = report.get("rows")
    require(type(rows) is list and len(rows) == 6, "six original rows required")
    expected = [(p, i) for p in ("PARAM-I", "PARAM-II", "PARAM-III")
                for i in ("table-standard-deviation", "literal-density-width")]
    require([(row.get("profile"), row.get("interpretation")) for row in rows] == expected,
            "Table 4 row order drift")
    capacities = {"PARAM-I": 3, "PARAM-II": 2, "PARAM-III": 1}
    for row in rows:
        require(row.get("schema") == HISTORY_SCHEMA
                and row.get("fixed_service_worst_case_capacity_users") ==
                capacities[row["profile"]]
                and row.get("same_fixture_key_signature_plan_replayed") is True
                and row.get("all_accepted_setup_roots_tv") is None
                and row.get("random_issued_key_then_sign_history_tv") is None
                and row.get("uniform_all_reachable_signing_keys_schur_bound") is None
                and row.get("bad_issued_key_sign_plan_probability") is None
                and row.get("faulty_storage_history_tv") is None
                and row.get("native_strong_security_proven") is False
                and row.get("security_claim") == "none"
                and row.get("backend_admitted") is False
                and row.get("parameters_are_formal") is False
                and row.get("nist_security_category") is None
                and row.get("private_material_exported") is False,
                "row falsely promoted")
        if row["interpretation"] == "literal-density-width":
            require(row.get("one_fresh_issuance_tv_upper") is None
                    and row.get("issuance_only_history_at_capacity_tv_upper") is None
                    and row.get("same_fixture_key_one_sign_call_tv_upper") == "1",
                    "literal scope drift")
        else:
            require(row.get("one_fresh_issuance_tv_upper", "").startswith("2^-")
                    and row.get("issuance_only_history_at_capacity_tv_upper", "").startswith("2^-")
                    and row.get("same_fixture_key_two_adaptive_sign_calls_tv_upper", "").startswith("2^-"),
                    "standard scope drift")
    # Recompute one complete source/signing row under Sage, including the
    # predecessor verifier.  The other five rows are frozen by this manifest.
    require(certificate("PARAM-I", "table-standard-deviation") == rows[0],
            "live same-root/key replay differs")
    print(json.dumps({"status": "verified", "rows": len(rows),
                      "entries": len(entries), "full_history": None,
                      "security_claim": "none"}, sort_keys=True))


if __name__ == "__main__":
    main()
