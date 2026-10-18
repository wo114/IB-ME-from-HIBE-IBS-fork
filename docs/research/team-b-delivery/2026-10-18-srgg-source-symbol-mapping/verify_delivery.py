"""Recompute and byte-bind the scoped original-paper source mapping package."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PACKAGE = "docs/research/team-b-delivery/2026-10-18-srgg-source-symbol-mapping"
PAPER = "papers/2025_efficient_ibs_jia.pdf"
PAPER_SHA256 = "258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152"

sys.path.insert(0, str(ROOT))
from experiments.research.candidates.srgg.paper_source_symbol_mapping import (  # noqa: E402
    BOUND_SOURCES, build_report,
)


REQUIRED = set(BOUND_SOURCES) | {
    PAPER,
    "experiments/research/candidates/srgg/paper_source_symbol_mapping.py",
    "tests/test_srgg_paper_source_symbol_mapping.py",
    *(f"{PACKAGE}/{name}" for name in (
        "README.md", "README_zh-CN.md", "proof.md",
        "source-symbol-mapping.json", "validation.json", "verify_delivery.py")),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def path_for(name):
    require(type(name) is str and bool(name) and "\\" not in name,
            "noncanonical package path")
    relative = Path(name)
    require(not relative.is_absolute() and
            all(part not in ("", ".", "..") for part in relative.parts),
            "unsafe package path")
    target = (ROOT / relative).resolve()
    require(target.is_relative_to(ROOT) and target.is_file(),
            "missing or escaped package file: " + name)
    return target


def content_for(name):
    content = path_for(name).read_bytes()
    return content if name == PAPER else content.replace(b"\r\n", b"\n")


def digest(name):
    return sha256(content_for(name)).hexdigest()


def read_json(name):
    value = json.loads(path_for(f"{PACKAGE}/{name}").read_text(encoding="utf-8"))
    require(type(value) is dict, "JSON object required: " + name)
    return value


def check_security(value):
    require(value.get("security_claim") == "none" and
            value.get("backend_admitted") is False and
            value.get("parameters_are_formal") is False and
            "nist_security_category" in value and
            value["nist_security_category"] is None,
            "research-only security scope changed")


def main():
    manifest = read_json("MANIFEST.json")
    require(manifest.get("schema") == "IBME/SRGG-SOURCE-SYMBOL-MAPPING-MANIFEST/1" and
            manifest.get("self_hash_excluded") is True,
            "manifest schema")
    check_security(manifest)
    entries = manifest.get("entries")
    require(type(entries) is dict and set(entries) == REQUIRED,
            "manifest file coverage")
    for name, record in entries.items():
        require(type(record) is dict and set(record) == {"bytes", "sha256"} and
                type(record["bytes"]) is int and record["bytes"] >= 0 and
                type(record["sha256"]) is str and len(record["sha256"]) == 64,
                "malformed manifest entry: " + name)
        content = content_for(name)
        require(len(content) == record["bytes"] and
                sha256(content).hexdigest() == record["sha256"],
                "package byte mismatch: " + name)

    report = read_json("source-symbol-mapping.json")
    check_security(report)
    require(digest(PAPER) == PAPER_SHA256 and
            report.get("paper", {}).get("sha256") == PAPER_SHA256,
            "reviewed PDF identity")
    require(report.get("bound_source_sha256_normalized_lf") ==
            {name: digest(name) for name in BOUND_SOURCES},
            "source binding drift")
    recomputed = (json.dumps(build_report(), indent=2, sort_keys=True) + "\n").encode()
    require(content_for(f"{PACKAGE}/source-symbol-mapping.json") == recomputed,
            "exact executable report mismatch")
    rows = report.get("original_table4_modulus_rows", [])
    require(len(rows) == 3 and
            [row.get("profile") for row in rows] ==
            ["PARAM-I", "PARAM-II", "PARAM-III"] and
            all(row.get("table3_Q_equals_p_times_q") == 15744063 and
                row.get("theorem1_q_for_direct_same_modulus_mapping") == 15744063 and
                row.get("theorem1_q_strictly_exceeds_2gamma") is False
                for row in rows), "Table 4 exact gate changed")
    eta = report.get("original_table3_eta_rows", [])
    require([row.get("table3_dimension") for row in eta] ==
            [6144, 8192, 10240] and
            all(row["formal_eta_literal_definition"][
                "lower_strictly_exceeds_epsilon"] is True for row in eta),
            "source smoothing discrepancy changed")
    counterexample = report.get("g1_query_count_lower_bound_counterexample", {})
    require(counterexample.get("exact_G1_X_event_probability") == "1/4" and
            counterexample.get(
                "printed_p8_delta_times_1_minus_delta_qS_for_epsilon_1") == "1/2" and
            counterexample.get("underlying_valid_forgery_established") is False,
            "finite G1 trace scope changed")
    trace = report.get("finite_game_trace_under_assumed_valid_forgery", {})
    require(trace.get("old_message_query_then_fresh_message_target_in_X", {}).get(
        "g1_win_but_printed_simulator_aborts") is True and
            trace.get("same_message_different_signature", {}).get(
                "g0_euf_fresh_pair_wins_if_valid") is False and
            trace.get("same_message_different_signature", {}).get(
                "native_strong_exact_triple_wins_if_valid") is True and
            trace.get("conditional_trace_is_a_real_signature_attack") is False,
            "source-game trace scope changed")

    validation = read_json("validation.json")
    check_security(validation)
    require(validation.get("schema") ==
            "IBME/SRGG-SOURCE-SYMBOL-MAPPING-VALIDATION/1" and
            validation.get("source_paper_sha256") == PAPER_SHA256 and
            validation.get("report_sha256_normalized_lf") == digest(
                f"{PACKAGE}/source-symbol-mapping.json") and
            validation.get("focused_tests_passed") == 15 and
            validation.get("focused_tests_failed") == 0 and
            validation.get("actual_signatures_created") == 0,
            "validation evidence changed")
    print(json.dumps({"status": "verified", "manifest_entries": len(entries),
                      "original_rows": 3, "focused_tests_reported": 15,
                      "security_claim": "none"}, sort_keys=True))


if __name__ == "__main__":
    main()
