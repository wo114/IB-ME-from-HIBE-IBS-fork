"""Pure-Python verifier for the SRGG distribution-chain delivery.

Run from the repository root:

    python docs/research/team-b-delivery/2026-10-18-srgg-distribution-chain/verify_delivery.py

It re-checks the exact algebraic identities in the JSON, the six-row coverage,
the boundary-probe receipts (if present) and the security flags.  It does not
need Sage and it does not re-run any sampler.
"""
from __future__ import annotations

from fractions import Fraction
import json
from pathlib import Path
import sys

if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(0)


ROOT = Path(__file__).resolve().parents[4]
HERE = Path(__file__).resolve().parent
PROFILES = ("PARAM-I", "PARAM-II", "PARAM-III")
INTERPRETATIONS = ("table-standard-deviation", "literal-density-width")


def _fraction(value):
    if value is None:
        raise AssertionError("unexpected null in exact field")
    return Fraction(value)


def check_report(path):
    report = json.loads(path.read_text(encoding="utf-8"))
    assert report["schema"] == "IBME/SRGG-PAPER-DISTRIBUTION-CHAIN/1"
    assert report["security_claim"] == "none"
    assert report["backend_admitted"] is False
    assert report["parameters_are_formal"] is False
    assert report["nist_security_category"] is None
    rows = report["rows"]
    assert len(rows) == 6
    seen = set()
    for row in rows:
        seen.add((row["profile"], row["interpretation"]))
        c = row["good_root_constants"]
        b = row["bad_root_mass"]
        assert Fraction(c["threshold_C_gate_squared_exact"]) < \
            Fraction(c["threshold_A_squared_exact"])
        assert Fraction(c["threshold_C_gate_squared_exact"]) < \
            Fraction(c["threshold_schur_gate_squared_exact"])
        assert Fraction(c["uniform_schur_lower_bound_exact"]) > 64
        assert c["C_gate_implies_A"] is True
        assert c["C_gate_implies_schur_floor"] is True
        qa = _fraction(b["A_rejection_one_attempt_upper_exact"])
        qc = _fraction(b["C_gate_rejection_one_attempt_upper_exact"])
        tv = _fraction(b["accepted_root_tv_upper_exact"])
        assert 0 < qa < qc < 1
        assert tv == qc / (1 - qa)
        abort_text = b["guarded_64_retry_abort_upper_dyadic"]
        assert abort_text.startswith("2^-")
        abort_upper = Fraction(1, 2**int(abort_text[3:]))
        assert qc**64 <= abort_upper
        assert b["guarded_64_retry_abort_below_2_minus_64"] is True
        assert row["accepted_root_distribution"][
            "TV_mu_A_mu_B_upper_exact"] == b["accepted_root_tv_upper_exact"]
        composition = row["guarded_composition"]
        assert composition["beta_bad_unguarded"] is None
        assert composition["beta_bad_strictly_positive"] is True
        assert row["fault_history"]["TV"] is None
        probe = row.get("lifecycle_probe")
        if probe is not None:
            assert probe["functional_verified"] is True
            assert probe["master_audit_certified"] is True
            assert probe["sign_audit_certified"] is True
            assert probe["c_gate_certified"] is True
            assert probe["object_envelope_certified"] is True
            assert probe["setup_attempts"] == 1
    assert seen == {(p, i) for p in PROFILES for i in INTERPRETATIONS}
    return report


def check_boundary():
    receipts = sorted(HERE.glob("boundary-*.json"))
    if not receipts:
        return []
    checked = []
    for path in receipts:
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["functional_pass"] is True
        assert data["all_gates"]["setup_returned"] is True
        assert data["all_gates"]["c_gate"] is True
        assert data["all_gates"]["master_audit"] is True
        assert data["all_gates"]["object_envelope"] is True
        assert data["all_gates"]["verify"] is True
        assert data["witness_gap_to_C"] > 0
        checked.append(path.name)
    return checked


def main():
    report_path = HERE / "distribution-chain.json"
    if not report_path.exists():
        raise SystemExit("distribution-chain.json is missing")
    report = check_report(report_path)
    boundary = check_boundary()
    print(json.dumps({
        "report": str(report_path),
        "rows": len(report["rows"]),
        "boundary_receipts": boundary,
        "security_claim": report["security_claim"],
        "backend_admitted": report["backend_admitted"],
        "parameters_are_formal": report["parameters_are_formal"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
