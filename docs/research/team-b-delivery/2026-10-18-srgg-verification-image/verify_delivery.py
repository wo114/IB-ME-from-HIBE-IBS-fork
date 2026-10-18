"""Verify byte bindings and narrow algebraic claims in this SRGG package."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PACKAGE = "docs/research/team-b-delivery/2026-10-18-srgg-verification-image"
PAPER = "papers/2025_efficient_ibs_jia.pdf"
PDF_SHA256 = "258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152"
RECEIPT_SHA256 = "be582a4920c703b3569f3e42349cd62f9e868acf80b244a80ef8fff9b5e3b17c"
SOURCE_FILES = {
    "experiments/research/candidates/srgg/paper_verification_image.py",
    "experiments/research/candidates/srgg/paper_profiles.py",
    "experiments/research/candidates/srgg/paper_algebra.py",
    "experiments/research/candidates/srgg/structured_execution.py",
}
REQUIRED = SOURCE_FILES | {
    PAPER,
    "tests/test_srgg_paper_verification_image.py",
    f"{PACKAGE}/README.md",
    f"{PACKAGE}/README_zh-CN.md",
    f"{PACKAGE}/verification-image.json",
    f"{PACKAGE}/validation.json",
    f"{PACKAGE}/verify_delivery.py",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def repo_file(name: str) -> Path:
    require(type(name) is str and bool(name) and "\\" not in name,
            "noncanonical file name")
    relative = Path(name)
    require(not relative.is_absolute() and
            all(part not in ("", ".", "..") for part in relative.parts),
            "unsafe relative path")
    path = (ROOT / relative).resolve()
    require(path.is_relative_to(ROOT) and path.is_file(),
            "missing or escaped file: " + name)
    return path


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def read_json(name: str) -> dict:
    value = json.loads(repo_file(f"{PACKAGE}/{name}").read_text(encoding="utf-8"))
    require(type(value) is dict, "JSON object required: " + name)
    return value


def check_security(value: dict) -> None:
    require({"security_claim", "backend_admitted",
             "parameters_are_formal", "nist_security_category"} <= set(value),
            "explicit research-only markers missing")
    require(value.get("security_claim") == "none" and
            value.get("backend_admitted") is False and
            value.get("parameters_are_formal") is False and
            value.get("nist_security_category") is None,
            "research-only security markers changed")


def check_manifest() -> int:
    manifest = read_json("MANIFEST.json")
    require(manifest.get("schema") ==
            "IBME/SRGG-VERIFICATION-IMAGE-MANIFEST/1",
            "manifest schema changed")
    entries = manifest.get("entries")
    require(type(entries) is dict and set(entries) == REQUIRED,
            "manifest coverage changed")
    for name, expected in entries.items():
        require(type(expected) is dict and
                set(expected) == {"bytes", "sha256"} and
                type(expected["bytes"]) is int and
                expected["bytes"] >= 0 and
                type(expected["sha256"]) is str and
                len(expected["sha256"]) == 64,
                "malformed manifest entry: " + name)
        path = repo_file(name)
        require(path.stat().st_size == expected["bytes"] and
                digest(path) == expected["sha256"],
                "byte binding failed: " + name)
    require("MANIFEST.json" not in entries, "manifest must not hash itself")
    return len(entries)


def check_receipt() -> int:
    receipt_path = repo_file(f"{PACKAGE}/verification-image.json")
    require(digest(receipt_path) == RECEIPT_SHA256,
            "receipt differs from independently replayed CLI output")
    report = read_json("verification-image.json")
    require(report.get("schema") ==
            "IBME/SRGG-PAPER-VERIFICATION-IMAGE/1",
            "receipt schema changed")
    check_security(report)
    paper = report.get("paper")
    require(type(paper) is dict and paper.get("path") == PAPER and
            paper.get("sha256") == PDF_SHA256 and
            digest(repo_file(PAPER)) == PDF_SHA256,
            "frozen paper binding failed")
    hashes = report.get("source_sha256")
    require(type(hashes) is dict and set(hashes) == SOURCE_FILES,
            "report source coverage changed")
    for name, expected in hashes.items():
        require(digest(repo_file(name)) == expected,
                "source hash drift: " + name)

    rows = report.get("rows")
    require(type(rows) is list and len(rows) == 3,
            "exactly three paper rows expected")
    for index, row in enumerate(rows):
        d = index + 2
        n, q, Q = 512, 961, 15744063
        columns, total = 4 * d, 4 * d + 1
        codimension = n * d - n // 2
        require(row.get("profile") == ("PARAM-I", "PARAM-II", "PARAM-III")[index],
                "row order or name changed")
        require(row.get("matrix") ==
                "[2A | Q*zeta_star*e1-2h] mod 2Q" and
                row.get("source_parameters") ==
                {"q": q, "Q": Q, "p": 16383, "w": 2} and
                row.get("input") ==
                {"n": n, "d": d, "A_columns": columns,
                 "verification_columns": total, "Q": Q,
                 "verification_modulus": 2 * Q},
                "original matrix or input parameters changed")
        mod_q, mod_2, mod_2q = row["mod_Q"], row["mod_2"], row["mod_2Q"]
        require(mod_q.get("image") == "R_Q^d" and
                mod_q.get("surjective_for_every_U_h") is True and
                mod_q.get("coefficient_image_dimension") == n * d and
                mod_q.get("kernel_cardinality") ==
                {"base": Q, "exponent": n * (total - d)},
                "mod-Q image or kernel changed")
        require(mod_2.get("coefficient_image_dimension") == n // 2 and
                mod_2.get("coefficient_codimension") == codimension and
                mod_2.get("kernel_coefficient_dimension") ==
                n * total - n // 2 and
                mod_2.get("other_rows_zero") is True,
                "mod-2 image or kernel changed")
        require(mod_2q.get("image_index_in_full_codomain") ==
                {"base": 2, "exponent": codimension} and
                mod_2q.get("image_cardinality") ==
                {"Q_power": n * d, "two_power": n // 2} and
                mod_2q.get("kernel_cardinality") ==
                {"Q_power": n * (total - d),
                 "two_power": n * total - n // 2} and
                mod_2q.get("image_independent_of_U_and_h") is True,
                "CRT image or kernel changed")
        scope = row.get("scope")
        require(type(scope) is dict, "scope missing")
        check_security(scope)
        require({"paper_theorem_q_Q_2Q_mapping",
                 "accepted_Setup_or_seeded_planted_law",
                 "short_kernel_or_forgery_cost"} <= set(scope),
                "explicit null scope markers missing")
        require(scope.get("exact_algebraic_image_and_kernel_only") is True and
                scope.get("paper_theorem_q_Q_2Q_mapping") is None and
                scope.get("accepted_Setup_or_seeded_planted_law") is None and
                scope.get("short_kernel_or_forgery_cost") is None and
                scope.get("IBS_attack_or_security_inferred") is False,
                "algebraic scope exceeded")
    return len(rows)


def check_validation() -> None:
    validation = read_json("validation.json")
    require(validation.get("schema") ==
            "IBME/SRGG-VERIFICATION-IMAGE-VALIDATION/1",
            "validation schema changed")
    check_security(validation)
    require(validation.get("receipt", {}).get("sha256") == RECEIPT_SHA256 and
            validation.get("paper", {}).get("sha256") == PDF_SHA256,
            "validation evidence link changed")
    tests = validation.get("execution", {})
    require(tests.get("test_passed") == 17 and
            tests.get("test_failed") == 0 and
            tests.get("test_skipped") == 0 and
            all(tests.get(name) == 0 for name in
                ("setup_runs", "extractions", "signatures", "messages",
                 "identities", "sampling_repetitions", "random_bytes_consumed")),
            "test or run-scope claim changed")
    interpretation = validation.get("interpretation", {})
    require(interpretation.get("image_index_is_attack_cost") is False and
            interpretation.get("result_for_unrestricted_mod_2Q_responses_only") is True and
            "free-module rank" in
            interpretation.get("mod_Q_coefficient_image_dimension", "") and
            "Algorithm 7 line 5" in interpretation.get("algorithm_8_b", ""),
            "interpretation boundary changed")
    open_items = validation.get("open", {})
    unresolved = {
        "paper_theorem_q_Q_2Q_mapping",
        "accepted_setup_root_distribution",
        "seeded_planted_public_matrix_law",
        "short_kernel_cost", "forgery_cost",
        "ring_HNF_MSIS_CRT_subfield_attack_cost",
        "formal_hardness_bits",
        "full_issuance_signature_fault_history_bound",
    }
    require(type(open_items) is dict and
            unresolved | {"native_strong_same_message_replacements_resolved"} <=
            set(open_items) and
            all(open_items[name] is None for name in unresolved) and
            open_items["native_strong_same_message_replacements_resolved"]
            is False,
            "open proof or attack-cost boundary changed")


def main() -> None:
    count = check_manifest()
    rows = check_receipt()
    check_validation()
    print(json.dumps({"status": "verified", "manifest_entries": count,
                      "paper_rows": rows, "focused_tests_reported": 17,
                      "security_claim": "none"}, sort_keys=True))


if __name__ == "__main__":
    main()
