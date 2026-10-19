"""Checks for the consolidated 128-bit security audit."""
import json
from pathlib import Path

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "docs/research/team-b-delivery/2026-10-19-srgg-128bit-reproduction/audit.json"


def load():
    return json.loads(AUDIT.read_text(encoding="utf-8"))


def test_decision_is_limited_to_128_bit_concrete_security():
    audit = load()
    decision = audit["decision"]
    assert audit["final_configuration"]["profile"] == "PARAM-II"
    assert decision["selected_profile"] == "PARAM-II"
    assert decision["meets_128_bit"] is True
    assert decision["forgery_classical_bits_reproduced"] == 171
    assert decision["forgery_quantum_bits_reproduced"] == 155
    assert decision["forgery_classical_bits_reproduced"] >= 128
    assert decision["forgery_quantum_bits_reproduced"] >= 128
    assert "concrete-security" in decision["admitted_for"]
    assert "strong unforgeability" in decision["not_admitted_for"]
    assert "NIST category" in decision["not_admitted_for"]


def test_q_q2q_mapping_and_theorem_gap_are_explicit():
    audit = load()
    mapping = audit["q_Q_2Q"]
    assert mapping["key_recovery_modulus"] == 15744063
    assert mapping["forgery_modulus"] == 31488126
    assert mapping["table5_reproduced"] is True
    assert mapping["theorem_condition_holds_with_Q_or_2Q"] is False
    assert len(mapping["Q_comparison"]) == 3
    for row in mapping["Q_comparison"]:
        assert row["Q_gt_2gamma"] is False
        assert row["2Q_gt_2gamma"] is False


def test_zeta_r_sigma_and_structural_costs_stay_null():
    audit = load()
    assert audit["zeta"]["status"] == "null"
    assert audit["zeta"]["equivalent_response_law_proved"] is False
    assert audit["r_sigma"]["status"] == "null"
    assert audit["r_sigma"]["finite_sampler_to_hnf_signing_tv"] is None
    structural = audit["structural_attacks"]
    assert structural["full_ring_hnf_msis_attack_cost"] is None
    assert structural["CRT_subfield_attack_cost"] is None
    assert structural["accepted_setup_root_structural_attack_cost"] is None
    assert structural["status"].startswith("null")
    assert structural["native_strong"]["target_in_this_report"] == "EUF-CMA only, not strong"


def test_final_flags_and_remaining_work_are_honest():
    audit = load()
    assert audit["security_claim"] == "none"
    assert audit["backend_admitted"] is False
    assert audit["parameters_are_formal"] is False
    assert audit["nist_security_category"] is None
    assert len(audit["remaining_formal_work"]) >= 4
    assert audit["final_configuration"]["n"] == 512
    assert audit["final_configuration"]["Q"] == 15744063
