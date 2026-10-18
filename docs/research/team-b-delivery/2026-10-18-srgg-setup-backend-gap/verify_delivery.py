"""Verify the bounded zero-atom Setup diagnosis and its exact package bytes."""

from __future__ import annotations

from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
DELIVERY = "docs/research/team-b-delivery/2026-10-18-srgg-setup-backend-gap/"
PAPER = "papers/2025_efficient_ibs_jia.pdf"
PAPER_SHA256 = "258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152"
SCHEMA = "IBME/SRGG-SETUP-BACKEND-GAP-DELIVERY-MANIFEST/1"
REQUIRED = {
    PAPER,
    *("experiments/research/candidates/srgg/" + name for name in (
        "algebra.py", "convolution_bridge.py", "fiber_normalizers.py",
        "formal_candidates.py", "geometry.py", "paper_algebra.py",
        "paper_backend.py", "paper_objects.py", "paper_samplef.py",
        "paper_parameters.py", "paper_profiles.py", "paper_schur_backend.py",
        "paper_schur_fourier.py", "paper_schur_samplef.py",
        "paper_setup_backend_gap.py", "paper_setup_conditioning.py",
        "psf_bridge.py", "sampling.py", "structured_backend.py",
        "structured_execution.py", "structured_geometry.py",
        "structured_samplef.py", "wide_scalar.py", "aggregate_budget.py")),
    "experiments/research/gaussian_reference.py",
    "experiments/research/candidates/wang_pw/hashing.py",
    *("src/ibme/core/" + name for name in (
        "encoding.py", "errors.py", "hashing.py", "randomness.py")),
    "tests/test_srgg_paper_setup_backend_gap.py",
    *(DELIVERY + name for name in (
        "README.md", "README_zh-CN.md", "setup-backend-gap.json",
        "validation.json", "verify_delivery.py")),
}
EXPECT = (
    ("PARAM-I", 2, 8192, Fraction(13208769022924878363, 2114511742034336)),
    ("PARAM-II", 3, 18432, Fraction(20467873059782430888, 2292993012217061)),
    ("PARAM-III", 4, 32768, Fraction(6525839712757462581, 564733141675732)),
)
INTERPRETATIONS = ("table-standard-deviation", "literal-density-width")


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
    require(type(entries) is dict and set(entries) == REQUIRED, "manifest exact coverage")
    for name, expected in entries.items():
        require(type(expected) is dict and set(expected) == {"bytes", "sha256"},
                "manifest entry structure")
        path = path_at(name)
        require(path.stat().st_size == expected["bytes"] and
                digest(path) == expected["sha256"], "package byte mismatch: " + name)
    require(digest(path_at(PAPER)) == PAPER_SHA256, "frozen paper checksum")

    report = read_json("setup-backend-gap.json")
    require(report.get("schema") == "IBME/SRGG-PAPER-SETUP-BACKEND-GAP-ZERO-ATOM/1" and
            report.get("source_pdf") == PAPER and report.get("source_sha256") == PAPER_SHA256 and
            report.get("first_seed_drawn_once_for_all_setup_retries") is True and
            report.get("non_geometry_preparation_errors_terminate_setup") is True and
            report.get("cannot_raise_first_attempt_failure_bound_to_64th_power") is True,
            "source or retry scope mismatch")
    for field in ("all_positive_roots_uniform_numerical_acceptance_bound",
                  "useful_64_attempt_abort_upper", "complete_fault_history_law_upper"):
        require(field in report and report[field] is None, "false closure: " + field)
    require(report.get("security_claim") == "none" and
            report.get("backend_admitted") is False and
            report.get("parameters_are_formal") is False and
            report.get("nist_security_category") is None,
            "security marker drift")
    rows = report.get("rows")
    require(type(rows) is list and len(rows) == 6, "six original Table 4 rows")
    for row, (name, rank, count, threshold), interpretation in zip(
            rows, (entry for entry in EXPECT for _ in INTERPRETATIONS),
            INTERPRETATIONS * len(EXPECT)):
        require(row.get("profile") == name and row.get("interpretation") == interpretation and
                row.get("degree") == 512 and row.get("gadget_digits_w") == 2 and
                row.get("rank_d") == rank and row.get("witness_coefficient_count") == count and
                row.get("first_attempt_entropy_requests_bytes") == [32, count] and
                row.get("positive_gate_threshold_squared_exact") == str(threshold) and
                row.get("zero_witness_fourier_operator_norm_squared") == 0 and
                row.get("complete_zero_seed_zero_witness_setup_accepted") is True,
                "zero-atom replay or original parameter drift")
        require(row.get("zero_witness_probability_exact") == f"2^-{count}" and
                row.get("plan_gap_probability_upper_exact") == f"1-2^-{count}" and
                row.get("zero_seed_and_witness_probability_exact") == f"2^-{count + 256}" and
                row.get("full_first_attempt_gap_probability_upper_exact") ==
                f"1-2^-{count + 256}", "exact zero-atom probability drift")
        for field in ("all_positive_roots_uniform_numerical_acceptance_bound",
                      "useful_64_attempt_abort_upper", "complete_fault_history_law_upper"):
            require(field in row and row[field] is None, "row false closure: " + field)
        require(row.get("numerically_useful_for_64_attempt_abort") is False and
                row.get("actual_backend_all_accepted_roots_gap_closed") is False and
                row.get("security_claim") == "none" and
                row.get("backend_admitted") is False and
                row.get("parameters_are_formal") is False and
                row.get("nist_security_category") is None,
                "row admission drift")

    validation = read_json("validation.json")
    require(validation.get("schema") == "IBME/SRGG-SETUP-BACKEND-GAP-VALIDATION/1" and
            validation.get("receipt_sha256") == digest(HERE / "setup-backend-gap.json") and
            validation.get("focused_tests_passed") == 8 and
            validation.get("security_claim") == "none" and
            validation.get("backend_admitted") is False and
            validation.get("parameters_are_formal") is False and
            validation.get("nist_security_category") is None,
            "validation receipt or claim drift")

    # A byte-perfect receipt is also replayed through the actual frozen backend.
    sys.path.insert(0, str(ROOT))
    from experiments.research.candidates.srgg.paper_setup_backend_gap import build_report
    require(report == build_report(), "deterministic six-row backend replay differs")
    print(json.dumps({"status": "verified", "manifest_entries": len(entries),
                      "zero_atom_rows": 6, "useful_actual_backend_gap_bound": None,
                      "security_claim": "none"}, sort_keys=True))


if __name__ == "__main__":
    main()
