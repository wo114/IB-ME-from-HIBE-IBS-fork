"""Verify selected committed source and structural-cost evidence bytes.

No Sage import is needed. This selected-source manifest is not a complete
Python dependency closure; run the recorded tests in the full repository.
"""
from __future__ import annotations

from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
PACKAGE = Path(__file__).resolve().parent
SOURCES = (
    "experiments/research/candidates/srgg/paper_structural_cost.py",
    "experiments/research/candidates/srgg/paper_profiles.py",
    "experiments/research/candidates/srgg/paper_hardness_preflight.py",
    "experiments/research/candidates/srgg/paper_verification_image.py",
    "experiments/research/candidates/srgg/structured_execution.py",
    "experiments/research/candidates/srgg/paper_algebra.py",
    "experiments/research/candidates/srgg/paper_parameters.py",
    "tests/test_srgg_paper_structural_cost.py",
)
DELIVERY = "docs/research/team-b-delivery/2026-10-18-srgg-structural-cost/"
EVIDENCE = tuple(DELIVERY + name for name in (
    "README.md", "README_zh-CN.md", "proof.md", "structural-cost.json",
    "validation.json", "verify_delivery.py",
))
SELECTED = SOURCES + EVIDENCE


def _check(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def _digest(path: Path) -> str:
    # Git text is LF; Windows may materialize CRLF in the checkout.
    return sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def verify() -> dict:
    manifest = json.loads((PACKAGE / "MANIFEST.json").read_text(encoding="utf-8"))
    _check(manifest.get("schema") == "IBME/SRGG-PAPER-STRUCTURAL-COST-MANIFEST/1",
           "manifest schema differs")
    files = manifest.get("files")
    _check(type(files) is dict and set(files) == set(SELECTED),
           "selected manifest paths differ")
    for name in SELECTED:
        _check(_digest(ROOT / name) == files[name], "selected file differs: " + name)
    report = json.loads((PACKAGE / "structural-cost.json").read_text(encoding="utf-8"))
    validation = json.loads((PACKAGE / "validation.json").read_text(encoding="utf-8"))
    _check(report.get("schema") == "IBME/SRGG-PAPER-STRUCTURAL-COST/1",
           "receipt schema differs")
    _check(report["paper"]["sha256"] == validation["source"]["sha256"],
           "source identity differs")
    _check(sha256((ROOT / validation["source"]["path"]).read_bytes()).hexdigest()
           == validation["source"]["sha256"], "frozen paper differs")
    for path, digest in report["source_sha256"].items():
        _check(path in SOURCES and _digest(ROOT / path) == digest,
               "receipt source digest differs: " + path)
    _check(len(report["rows"]) == 3, "Table 4 row count differs")
    for row, rank in zip(report["rows"], (2, 3, 4)):
        p = row["original_inputs"]
        Q = p["Q"]
        gamma = Fraction(p["gamma_exact_rational"])
        _check(p["n"] == 512 and p["d"] == rank and p["w"] == 2
               and Q == 15744063, "original parameter row differs")
        _check(Fraction(p["gamma_published_decimal"]) == gamma,
               "gamma decimal/rational mapping differs")
        cap = (gamma**2).numerator // (gamma**2).denominator
        _check(p["signature_norm_squared_cap"] == cap, "norm cap differs")
        _check(Q < 2*gamma and Q**2 <= cap,
               "universal short-vector inequalities differ")
        _check(row["Q_MSIS_short_kernel"]["euclidean_norm"] == Q
               and row["Q_MSIS_short_kernel"]["sparse_construction_BKZ_calls"] == 0,
               "kernel construction differs")
        _check(row["actual_2Q_verification"]["eligible_shift_coordinates"]
               == 4*rank*512, "verification coordinate count differs")
        _check([x["residue_factor_degree"] for x in row["CRT"]]
               == [256, 32, 256, 8], "CRT factor degrees differ")
        _check(all(x["Qe0_is_zero_in_component"] for x in row["CRT"]),
               "CRT kernel projection differs")
        _check(row["actual_2Q_verification"]["valid_signature_replacement_probability"]
               is None, "conditional replacement promoted to a probability")
        _check(all(row[name] is None for name in (
            "actual_full_ring_HNF_or_structural_CVP_cost",
            "actual_CRT_or_subfield_attack_cost",
            "actual_accepted_setup_root_attack_success")),
            "unknown attack cost promoted to a claim")
        for item in (row, report, validation):
            _check(item["security_claim"] == "none"
                   and item["backend_admitted"] is False
                   and item["parameters_are_formal"] is False
                   and item["nist_security_category"] is None,
                   "security status promoted")
    return {"selected_files_verified": len(SELECTED),
            "profiles_verified": [x["profile"] for x in report["rows"]],
            "security_claim": "none"}


if __name__ == "__main__":
    print(json.dumps(verify(), sort_keys=True))
