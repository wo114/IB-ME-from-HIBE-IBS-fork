"""Verify the exact mathematical Setup receipt and package file bytes."""
from __future__ import annotations

from fractions import Fraction
from hashlib import sha256
from math import comb, factorial
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SCHEMA = "IBME/SRGG-SETUP-ACCEPTANCE-DELIVERY-MANIFEST/1"
PAPER = "papers/2025_efficient_ibs_jia.pdf"
PAPER_SHA256 = "258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152"
DELIVERY = "docs/research/team-b-delivery/2026-10-18-srgg-setup-acceptance/"
REQUIRED = {
    PAPER,
    "experiments/research/candidates/srgg/paper_setup_acceptance.py",
    "experiments/research/candidates/srgg/paper_setup_conditioning.py",
    "experiments/research/candidates/srgg/paper_parameters.py",
    "experiments/research/candidates/srgg/paper_profiles.py",
    "tests/test_srgg_paper_setup_acceptance.py",
    *(DELIVERY + name for name in (
        "README.md", "README_zh-CN.md", "proof.md", "setup-acceptance.json",
        "validation.json", "verify_delivery.py")),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def path_at(name):
    require(type(name) is str and name and "\\" not in name,
            "noncanonical manifest path")
    relative = Path(name)
    require(not relative.is_absolute() and all(part not in ("", ".", "..")
                                               for part in relative.parts),
            "unsafe manifest path")
    path = (ROOT / relative).resolve()
    require(path.is_relative_to(ROOT) and path.is_file(),
            "missing or escaped package file: " + name)
    return path


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def read_json(name):
    return json.loads((HERE / name).read_text(encoding="utf-8"))


def hook_moment(a, b, k):
    def rising(x, count):
        result = 1
        for i in range(count):
            result *= x + i
        return result

    def falling_below(x, count):
        result = 1
        for i in range(1, count + 1):
            result *= x - i
        return result

    numerator = sum((-1)**h * comb(k - 1, h)
                    * rising(a, k - h) * falling_below(a, h)
                    * rising(b, k - h) * falling_below(b, h)
                    for h in range(min(a, b, k)))
    return Fraction(numerator, factorial(k)) * 256**k


def main():
    manifest = read_json("MANIFEST.json")
    require(manifest.get("schema") == SCHEMA, "manifest schema")
    entries = manifest.get("entries")
    require(type(entries) is dict and REQUIRED <= set(entries), "manifest coverage")
    for name, expected in entries.items():
        require(type(expected) is dict and set(expected) == {"bytes", "sha256"},
                "manifest entry structure")
        path = path_at(name)
        require(path.stat().st_size == expected["bytes"] and
                digest(path) == expected["sha256"], "package byte mismatch: " + name)
    require(digest(path_at(PAPER)) == PAPER_SHA256, "frozen paper checksum")

    report = read_json("setup-acceptance.json")
    require(report.get("schema") == "IBME/SRGG-PAPER-SETUP-ACCEPTANCE-MOMENT/1" and
            report.get("source_pdf") == PAPER and
            report.get("source_sha256") == PAPER_SHA256 and
            report.get("mathematical_positive_gate_bound_is_not_actual_backend_abort_bound") is True,
            "report source/scope")
    require(report.get("security_claim") == "none" and
            report.get("backend_admitted") is False and
            report.get("parameters_are_formal") is False and
            report.get("nist_security_category") is None,
            "formal security marker drift")
    expected_rows = (
        ("PARAM-I", 2, 17, Fraction(13208769022924878363, 2114511742034336), 146),
        ("PARAM-II", 3, 22, Fraction(20467873059782430888, 2292993012217061), 217),
        ("PARAM-III", 4, 28, Fraction(6525839712757462581, 564733141675732), 282),
    )
    rows = report.get("rows")
    require(type(rows) is list and len(rows) == 3, "three original Table 4 rows")
    for row, (name, rank, order, threshold, exponent) in zip(rows, expected_rows):
        a = b = 2 * rank
        moment = hook_moment(a, b, order)
        q = 256 * moment / threshold**order
        require(row.get("profile") == name and row.get("rank_d") == rank and
                row.get("w") == 2 and row.get("degree") == 512 and
                row.get("Fourier_block_shape") == [a, b] and
                row.get("conjugate_paired_blocks") == 256 and
                row.get("interpretations") == ["table-standard-deviation", "literal-density-width"] and
                row.get("moment_order") == order and
                row.get("moment_valid_because_order_less_than_degree") is True,
                "profile or moment assumptions")
        require(row.get("positive_gate_threshold_squared_exact") == str(threshold) and
                row.get("complex_gaussian_wishart_trace_moment_exact") == str(moment) and
                row.get("mathematical_one_attempt_rejection_upper_exact") == str(q) and
                row.get("paper_conditioned_root_vs_raw_CBD1_tv_upper_exact") == str(q),
                "exact moment or rejection bound drift")
        require(q < Fraction(1, 4) and q**64 < Fraction(1, 2**exponent) and
                not q**64 < Fraction(1, 2**(exponent + 1)) and
                row.get("mathematical_64_attempt_exhaustion_strict_dyadic_upper") ==
                "2^-" + str(exponent), "64-retry bound drift")
        for field in ("actual_backend_success_set_vs_paper_positive_set_tv_upper",
                      "actual_backend_interval_inconclusive_probability_upper",
                      "actual_backend_setup_fault_or_abort_upper",
                      "all_accepted_root_finite_source_schur_tv_upper"):
            require(row.get(field) is None, "finite backend falsely certified: " + field)

    validation = read_json("validation.json")
    require(validation.get("security_claim") == "none" and
            validation.get("backend_admitted") is False and
            validation.get("parameters_are_formal") is False and
            validation.get("nist_security_category") is None and
            validation.get("report_sha256") == digest(HERE / "setup-acceptance.json"),
            "validation claim or report binding")
    print(json.dumps({"status": "verified", "manifest_entries": len(entries),
                      "mathematical_rows": 3, "actual_backend_bound": None,
                      "security_claim": "none"}, sort_keys=True))


if __name__ == "__main__":
    main()
