"""Verify the scoped SRGG covariance/source-correspondence package."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PACKAGE = "docs/research/team-b-delivery/2026-10-18-srgg-covariance-correspondence"
PAPER = "papers/2025_efficient_ibs_jia.pdf"
PDF_SHA256 = "258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152"
RECEIPT_SHA256 = "d20dc36fc8370e0c29c480b6ec66f5e02e0a37a17fe828bccc6aae82a818a0c7"

sys.path.insert(0, str(ROOT))
from experiments.research.candidates.srgg.paper_covariance_correspondence import (  # noqa: E402
    BOUND_SOURCES, report,
)


REQUIRED = set(BOUND_SOURCES) | {
    PAPER,
    "tests/test_srgg_paper_covariance_correspondence.py",
    f"{PACKAGE}/README.md",
    f"{PACKAGE}/README_zh-CN.md",
    f"{PACKAGE}/proof.md",
    f"{PACKAGE}/covariance-correspondence.json",
    f"{PACKAGE}/validation.json",
    f"{PACKAGE}/verify_delivery.py",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def repo_file(name):
    require(type(name) is str and bool(name) and "\\" not in name,
            "noncanonical package path")
    relative = Path(name)
    require(not relative.is_absolute() and
            all(part not in ("", ".", "..") for part in relative.parts),
            "unsafe package path")
    path = (ROOT / relative).resolve()
    require(path.is_relative_to(ROOT) and path.is_file(),
            "missing or escaped package file: " + name)
    return path


def digest(name):
    return sha256(repo_file(name).read_bytes()).hexdigest()


def read_json(name):
    value = json.loads(repo_file(f"{PACKAGE}/{name}").read_text(encoding="utf-8"))
    require(type(value) is dict, "JSON object required: " + name)
    return value


def check_security(value):
    require(value.get("security_claim") == "none" and
            value.get("backend_admitted") is False and
            value.get("parameters_are_formal") is False and
            "nist_security_category" in value and
            value["nist_security_category"] is None,
            "research-only security scope changed")


def check_manifest():
    manifest = read_json("MANIFEST.json")
    require(manifest.get("schema") == "IBME/SRGG-COVARIANCE-CORRESPONDENCE-MANIFEST/1" and
            manifest.get("self_hash_excluded") is True,
            "manifest schema changed")
    entries = manifest.get("entries")
    require(type(entries) is dict and set(entries) == REQUIRED,
            "manifest file coverage changed")
    for name, expected in entries.items():
        require(type(expected) is dict and set(expected) == {"bytes", "sha256"} and
                type(expected["bytes"]) is int and expected["bytes"] >= 0 and
                type(expected["sha256"]) is str and len(expected["sha256"]) == 64,
                "malformed manifest entry: " + name)
        path = repo_file(name)
        require(path.stat().st_size == expected["bytes"] and
                digest(name) == expected["sha256"],
                "manifest byte binding failed: " + name)
    check_security(manifest)
    return len(entries)


def check_receipt():
    require(digest(f"{PACKAGE}/covariance-correspondence.json") == RECEIPT_SHA256,
            "frozen executable receipt changed")
    value = read_json("covariance-correspondence.json")
    check_security(value)
    require(value.get("paper", {}).get("sha256") == PDF_SHA256 and
            digest(PAPER) == PDF_SHA256,
            "frozen paper mismatch")
    require(value.get("source_sha256") ==
            {name: digest(name) for name in BOUND_SOURCES},
            "receipt source binding changed")
    reproduced = (json.dumps(report(), ensure_ascii=False, indent=2,
                             sort_keys=True) + "\n").encode("utf-8")
    require(repo_file(f"{PACKAGE}/covariance-correspondence.json").read_bytes() == reproduced,
            "receipt is not byte-identical to fresh exact audit")
    require([row.get("d") for row in value.get("original_rows", [])] == [2, 3, 4] and
            value.get("finite_ring", {}).get("zeta_lattice_index") ==
            {"base": 2, "exponent": 256} and
            value.get("finite_ring", {}).get("pushforward_density_shape_factor") == 2 and
            value.get("continuous_shape_accounting", {}).get(
                "paper_output_excess_over_Sigma_bar_in_units_of_r_squared_LLstar") == 1 and
            value.get("author_intended_resolution") is None and
            value.get("full_signature_law_bound") is None,
            "math/scope fields changed")


def check_validation():
    value = read_json("validation.json")
    check_security(value)
    require(value.get("schema") == "IBME/SRGG-COVARIANCE-CORRESPONDENCE-VALIDATION/1" and
            value.get("paper", {}).get("sha256") == PDF_SHA256 and
            value.get("receipt", {}).get("sha256") == RECEIPT_SHA256,
            "validation provenance changed")
    execution = value.get("execution", {})
    require(execution.get("test_passed") == 18 and
            execution.get("test_failed") == 0 and execution.get("test_skipped") == 0 and
            all(execution.get(name) == 0 for name in
                ("message_bytes", "identity_bytes", "signature_runs", "setup_runs",
                 "sampling_repetitions", "random_bytes_consumed")) and
            execution.get("algebra_used_random_oracle") is False,
            "validation execution scope changed")
    scope = value.get("proved_scope", {})
    require(scope.get("exact_negacyclic_adjoint_and_norm_factor") is True and
            scope.get("exact_discrete_pushforward_coset_and_shape") is True and
            scope.get("strict_challenge_coset_normalizer_dependence") is True and
            scope.get("actual_discrete_signature_covariance_established") is False and
            scope.get("full_signature_law_bound") is None and
            scope.get("author_intended_resolution") is None and
            scope.get("proof_of_insecurity") is False and
            value.get("route_switches_after_original") == 2,
            "validation claims exceed the audit")


def main():
    entries = check_manifest()
    check_receipt()
    check_validation()
    print(json.dumps({"status": "verified", "manifest_entries": entries,
                      "paper_rows": 3, "focused_tests_reported": 18,
                      "security_claim": "none"}, sort_keys=True))


if __name__ == "__main__":
    main()
