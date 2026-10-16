from __future__ import annotations

from experiments.research.candidates.srgg.closure_ledger import build_report


def test_closure_ledger_keeps_scope_and_unresolved_terms():
    report = build_report()
    assert report["schema"] == "IBME/SRGG-CLOSURE-LEDGER/1"
    assert len(report["generator"]["sha256"]) == 64
    assert report["paper"]["sha256"] == (
        "258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152"
    )
    assert len(report["source_code_rows"]) == 6
    assert len(report["sampling_receipts"]) == 2
    assert len(report["parameter_gates"]) == 3
    assert len(report["ibs_ledger"]) == 12
    assert report["unresolved_ledger_terms"]
    assert report["closure"]["complete_classical_production_reduction"] is False
    assert report["closure"]["qrom_reduction"] is False
    assert report["closure"]["security_claim"] == "none"


def test_no_unresolved_term_has_a_production_value():
    report = build_report()
    for item in report["ibs_ledger"].values():
        if item["status"] == "unresolved":
            assert item["value"] is None
            assert item["reason"]


def test_required_explicit_premises_are_present():
    report = build_report()
    premises = report["premises"]
    assert premises["raw_first_touch_consistent"]["satisfied"] is True
    assert premises["specified_source_and_arithmetic_model"]["satisfied"] is True
    assert premises["complete_honest_reference"]["satisfied"] is False
    assert premises["same_bounded_game_and_failure_interfaces"]["satisfied"] is False


def test_published_parameter_gates_are_kept_as_failures():
    report = build_report()
    for row in report["parameter_gates"]:
        gate = row["parameter_gate"]
        smoothing = row["literal_smoothing_check"]
        assert gate["Q_gt_2gamma"] is False
        assert gate["2Q_gt_2gamma"] is False
        assert gate["2Q_is_odd"] is False
        assert smoothing["necessary_condition_fails"] is True
