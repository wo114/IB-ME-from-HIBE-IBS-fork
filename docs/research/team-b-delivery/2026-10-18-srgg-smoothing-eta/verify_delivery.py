"""Check the SRGG smoothing-width package and rerun its exact interval report."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(ROOT))

from experiments.research.candidates.srgg.paper_smoothing_eta import build_report  # noqa: E402


SCHEMA = "IBME/SRGG-SMOOTHING-ETA-DELIVERY-MANIFEST/1"
DELIVERY = "docs/research/team-b-delivery/2026-10-18-srgg-smoothing-eta/"
REQUIRED = {
    "papers/2025_efficient_ibs_jia.pdf",
    "experiments/research/candidates/srgg/paper_profiles.py",
    "experiments/research/candidates/srgg/paper_smoothing_eta.py",
    "tests/test_srgg_paper_smoothing_eta.py",
    *(DELIVERY + name for name in ("README.md", "README_zh-CN.md", "proof.md",
                                     "smoothing-eta.json", "validation.json",
                                     "verify_delivery.py")),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def file_at(relative):
    require(type(relative) is str and relative and "\\" not in relative,
            "noncanonical manifest path")
    path = Path(relative)
    require(not path.is_absolute() and all(part not in ("", ".", "..")
                                           for part in path.parts),
            "unsafe manifest path")
    resolved = (ROOT / path).resolve()
    require(resolved.is_relative_to(ROOT) and resolved.is_file(),
            "missing or escaped file: " + relative)
    return resolved


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def main():
    manifest = json.loads((HERE / "MANIFEST.json").read_text(encoding="utf-8"))
    require(manifest.get("schema") == SCHEMA, "manifest schema")
    entries = manifest.get("entries")
    require(type(entries) is dict and set(entries) == REQUIRED,
            "manifest coverage")
    for relative, expected in entries.items():
        require(type(expected) is dict and set(expected) == {"bytes", "sha256"},
                "manifest entry schema")
        path = file_at(relative)
        require(path.stat().st_size == expected["bytes"] and
                digest(path) == expected["sha256"],
                "package byte mismatch: " + relative)

    report = json.loads((HERE / "smoothing-eta.json").read_text(encoding="utf-8"))
    require(report == build_report(), "recomputed mathematical report mismatch")
    require(report.get("schema") == "IBME/SRGG-PAPER-SMOOTHING-ETA/1" and
            report.get("source_dimension") == 10240 and
            report.get("source_epsilon") == "1/16777216" and
            report.get("source_rounded_r") == "29/25", "source inputs")
    require(report.get("source_formal_eta_definition") ==
            "eta_epsilon(Z^m)=min{s>0:rho(s Z^m\\{0})<=epsilon}, rho(x)=exp(-pi||x||^2)",
            "formal source eta definition")
    for branch in ("formal_source_eta", "hypothetical_physical_stddev_conversion"):
        row = report[branch]
        require(row["lower_endpoint"]["lower_exceeds_source_epsilon"] is True and
                row["upper_endpoint"]["upper_below_source_epsilon"] is True and
                row["rounded_width"]["lower_exceeds_source_epsilon"] is True and
                row["exact_rounded_value_satisfies_smoothing"] is False,
                "strict smoothing comparison")
    require(report["formal_source_eta"]["printed_1_16_matches_formal_eta_definition"] is False and
            report["hypothetical_physical_stddev_conversion"][
                "implicit_unit_conversion_explains_printed_two_decimals"] is True and
            report["hypothetical_physical_stddev_conversion"][
                "relation_to_formal_eta"] == "eta_formal/sqrt(2*pi)" and
            report["hypothetical_physical_stddev_conversion"][
                "this_is_the_source_formal_eta_definition"] is False,
            "formal source discrepancy must remain explicit")
    for record in (report, json.loads((HERE / "validation.json").read_text(encoding="utf-8"))):
        require(record.get("security_claim") == "none" and
                record.get("backend_admitted") is False and
                record.get("parameters_are_formal") is False and
                record.get("nist_security_category") is None,
                "security marker drift")
    validation = json.loads((HERE / "validation.json").read_text(encoding="utf-8"))
    require(validation.get("report_sha256") == digest(HERE / "smoothing-eta.json") and
            validation.get("source_paper_sha256") == digest(file_at("papers/2025_efficient_ibs_jia.pdf")),
            "validation source binding")
    print(json.dumps({"status": "verified", "manifest_entries": len(entries),
                      "source_dimension": 10240, "source_exact_width_resolved": False,
                      "security_claim": "none"}, sort_keys=True))


if __name__ == "__main__":
    main()
