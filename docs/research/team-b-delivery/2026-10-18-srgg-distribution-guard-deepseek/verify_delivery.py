"""Verify the distribution-guard delivery without rerunning the Sage audits.

Checks the machine-readable receipt against the frozen predecessor receipts
(joint fixed-root, source issuance, history law) and the pinned security fields.
Run with any Python 3 (no Sage import):

    python docs/research/team-b-delivery/2026-10-18-srgg-distribution-guard-deepseek/verify_delivery.py
"""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
PACKAGE = Path(__file__).resolve().parent
DELIVERY = ROOT / "docs/research/team-b-delivery"
JOINT = DELIVERY / "2026-10-18-srgg-finite-chain/joint-fixed-root.json"
SOURCE = DELIVERY / "2026-10-18-srgg-source-issuance/source-issuance.json"
HISTORY = DELIVERY / "2026-10-18-srgg-history-law-followup/history-law.json"
PROFILES = ("PARAM-I", "PARAM-II", "PARAM-III")
INTERPRETATIONS = ("table-standard-deviation", "literal-density-width")
EXPECTED = {(p, i) for p in PROFILES for i in INTERPRETATIONS}


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _row(report, profile, interpretation):
    rows = [row for row in report["rows"]
            if (row.get("profile"), row.get("interpretation")) == (profile, interpretation)]
    assert len(rows) == 1, (profile, interpretation)
    return rows[0]


def main():
    report = _load(PACKAGE / "distribution-guard.json")
    assert report["schema"] == "IBME/SRGG-PAPER-DISTRIBUTION-GUARD/1/REPORT"
    assert len(report["rows"]) == 6
    assert {(r["profile"], r["interpretation"]) for r in report["rows"]} == EXPECTED
    for row in report["rows"]:
        assert row["guarded_backend_ran_audit_at_setup_and_sign"] is True
        assert row["original_backend_runs_audit"] is False
        assert row["security_claim"] == "none"
        assert row["backend_admitted"] is False
        assert row["parameters_are_formal"] is False
        assert row["nist_security_category"] is None
        assert row["root_gate_mass_under_actual_setup"] is None
        assert row["a_minus_b_event_mass"] is None
        assert row["bad_issued_key_mass_beta"] is None
        assert row["bad_key_mass_strictly_positive"] is True
        assert row["full_history_tv"] is None
        assert row["fault_history_tv"] is None
        assert row["setup_attempts"] == 1
        assert row["setup_gate_rejections"] == 0
        assert row["second_root_uniformity"]["master_joint_tv_identical"] is True

    joint = _load(JOINT)
    source = _load(SOURCE)
    history = _load(HISTORY)
    for profile, interpretation in EXPECTED:
        row = _row(report, profile, interpretation)
        frozen_joint = _row(joint, profile, interpretation)
        frozen_source = _row(source, profile, interpretation)
        frozen_history = _row(history, profile, interpretation)
        if interpretation == "table-standard-deviation":
            assert row["master_phase"]["closed"] is True
            assert row["master_phase"]["joint_tv_dyadic_upper"] == \
                frozen_joint["master"]["finite_vs_joint_integer_gaussian_tv_dyadic_upper"]
            assert row["signature_phase"]["joint_tv_dyadic_upper"] == \
                frozen_joint["signature"]["finite_vs_joint_integer_gaussian_tv_dyadic_upper"]
            assert row["issuance"]["complete_law_tv_upper_including_abort"] == \
                frozen_source["complete_law_tv_upper_including_abort"]
            assert row["sign_call"]["one_sign_call_tv_dyadic_upper"] == \
                frozen_history["same_fixture_key_one_sign_call_tv_upper"]
            assert row["issuance"]["closed"] is True
            assert row["sign_call"]["closed"] is True
        else:
            assert row["master_phase"]["closed"] is True
            assert row["master_phase"]["joint_tv_dyadic_upper"] == "1"
            assert row["signature_phase"]["joint_tv_dyadic_upper"] == "1"
            assert row["issuance"]["closed"] is False
            assert row["issuance"]["complete_law_tv_upper_including_abort"] is None
            assert row["sign_call"]["closed"] is False
            assert row["sign_call"]["one_sign_call_tv_dyadic_upper"] == "1"

    assert report["probes"]["unguarded_gate_gap"]["witness_found"] in (True, False)
    assert report["probes"]["sign_gate_mass"]["roots_attempted"] == 3
    assert report["probes"]["scope"].startswith("deterministic fixture searches only")
    assert report["security_claim"] == "none"
    assert report["backend_admitted"] is False
    assert report["parameters_are_formal"] is False
    assert report["nist_security_category"] is None

    digests = {
        "distribution-guard.json": sha256((PACKAGE / "distribution-guard.json").read_bytes()).hexdigest(),
        "proof.md": sha256((PACKAGE / "proof.md").read_bytes()).hexdigest(),
        "README_zh-CN.md": sha256((PACKAGE / "README_zh-CN.md").read_bytes()).hexdigest(),
        "joint-fixed-root.json": sha256(JOINT.read_bytes()).hexdigest(),
        "source-issuance.json": sha256(SOURCE.read_bytes()).hexdigest(),
        "history-law.json": sha256(HISTORY.read_bytes()).hexdigest(),
    }
    print(json.dumps({"ok": True, "rows": 6, "digests": digests}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
