"""Verify selected source bytes and the exact fault-history obstruction report."""
from __future__ import annotations

from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PREFIX = "docs/research/team-b-delivery/2026-10-18-srgg-fault-history-law/"
SCHEMA = "IBME/SRGG-FAULT-HISTORY-DELIVERY-MANIFEST/1"
PAPER = "papers/2025_efficient_ibs_jia.pdf"
PAPER_SHA256 = "258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152"
SOURCES = {
    "src/ibme/ibs/srgg_paper_service.py", "src/ibme/ibs/srgg_service.py",
    *("experiments/research/candidates/srgg/" + name for name in (
        "paper_fault_history_law.py", "paper_schur_backend.py", "paper_objects.py",
        "paper_parameters.py", "structured_geometry.py", "structured_execution.py",
        "paper_algebra.py", "paper_schur_fourier.py")),
}
PREDECESSOR = (
    "docs/research/team-b-delivery/2026-10-18-srgg-history-law-followup/history-law.json"
)
REQUIRED = {
    PAPER, PREDECESSOR, "tests/test_srgg_paper_fault_history_law.py", *SOURCES,
    *(PREFIX + name for name in (
        "README.md", "README_zh-CN.md", "proof.md", "fault-history-law.json",
        "validation.json", "verify_delivery.py")),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def read_json(name):
    return json.loads((HERE / name).read_text(encoding="utf-8"))


def path_at(name):
    require(type(name) is str and name in REQUIRED, "unexpected manifest path")
    path = (ROOT / name).resolve()
    require(path.is_relative_to(ROOT) and path.is_file(), "missing package file: " + name)
    return path


def main():
    manifest = read_json("MANIFEST.json")
    require(manifest.get("schema") == SCHEMA, "manifest schema")
    entries = manifest.get("entries")
    require(type(entries) is dict and set(entries) == REQUIRED, "manifest exact selected coverage")
    for name, expected in entries.items():
        require(type(expected) is dict and set(expected) == {"bytes", "sha256"},
                "manifest entry structure")
        file = path_at(name)
        require(file.stat().st_size == expected["bytes"] and digest(file) == expected["sha256"],
                "package byte mismatch: " + name)
    require(digest(path_at(PAPER)) == PAPER_SHA256, "frozen paper checksum")

    report = read_json("fault-history-law.json")
    require(report.get("schema") == "IBME/SRGG-PAPER-FAULT-HISTORY-LAW/1" and
            report.get("source_pdf") == PAPER and report.get("source_sha256") == PAPER_SHA256 and
            report.get("predecessor") == {"path": PREDECESSOR,
                "sha256": digest(path_at(PREDECESSOR))}, "source binding drift")
    require(report.get("full_history_bound") is None and
            report.get("security_claim") == "none" and
            report.get("backend_admitted") is False and
            report.get("parameters_are_formal") is False and
            report.get("nist_security_category") is None, "false security closure")
    source_map = report.get("source_map")
    require(type(source_map) is dict and set(source_map) == SOURCES - {
        "experiments/research/candidates/srgg/paper_fault_history_law.py"},
        "source map coverage mismatch")
    for name, record in source_map.items():
        require(record.get("sha256") == digest(path_at(name)) and
                type(record.get("anchors")) is dict and record["anchors"],
                "source map byte/anchor drift")
    fixture = report.get("fixture_key_counterexample")
    fault = report.get("arbitrary_fault_counterexample")
    witness = report.get("wire_valid_bad_sign_plan_witness")
    require(fixture.get("issuance_tv_exact") == "0" and
            fixture.get("fixture_key_0_signing_tv_exact") == "0" and
            Fraction(fixture["complete_issue_then_sign_tv_exact"]) == Fraction(7, 8) and
            fixture.get("is_srgg_attack") is False, "fixture counterexample drift")
    require(fault.get("fault_free_issue_and_sign_tv_exact") == "0" and
            fault.get("complete_history_tv_exact") == "1" and
            fault.get("is_srgg_attack") is False, "fault counterexample drift")
    require(witness.get("profile") == "PARAM-I" and
            witness.get("interpretation") == "table-standard-deviation" and
            witness.get("tail_coefficient") == 100000000 and
            witness.get("key_wire_round_trip") is True and
            witness.get("public_zero_witness_relation") is True and
            Fraction(witness["negative_shifted_schur_rayleigh_exact"]) < 0 and
            witness.get("key_output_by_random_extract_claimed") is False,
            "original-parameter object witness drift")
    hybrid = report.get("conditional_hybrid")
    require(hybrid.get("conditional_complete_history_tv_upper") is None and
            hybrid.get("all_conditional_premises_verified_here") is False,
            "unsupported full-history hybrid")
    rows = report.get("six_rows")
    require(type(rows) is list and len(rows) == 6, "six original Table 4 rows")
    for row in rows:
        require(row.get("full_issuance_signature_fault_history_tv") is None and
                row.get("all_accepted_roots_initial_law_tv") is None and
                row.get("random_issued_key_bad_sign_plan_mass") is None and
                row.get("faulty_storage_conditional_kernel_tv") is None,
                "row false closure")

    validation = read_json("validation.json")
    require(validation.get("schema") == "IBME/SRGG-FAULT-HISTORY-VALIDATION/1" and
            validation.get("receipt_sha256") == digest(HERE / "fault-history-law.json") and
            validation.get("focused_tests_passed") == 13 and
            validation.get("security_claim") == "none" and
            validation.get("backend_admitted") is False and
            validation.get("parameters_are_formal") is False and
            validation.get("nist_security_category") is None,
            "validation receipt or claims drift")

    sys.path.insert(0, str(ROOT))
    from experiments.research.candidates.srgg.paper_fault_history_law import build_report
    require(report == build_report(), "deterministic original-parameter replay differs")
    print(json.dumps({"status": "verified", "manifest_entries": len(entries),
                      "rows": len(rows), "full_history_bound": None,
                      "security_claim": "none"}, sort_keys=True))


if __name__ == "__main__":
    main()
