"""Security-profile candidate selection for the standalone SRGG component."""
import json

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

from experiments.research.candidates.srgg.paper_parameters import PaperParams
from experiments.research.candidates.srgg.paper_profiles import profiles
from experiments.research.candidates.srgg import paper_security_profiles as selection


def test_selected_profile_is_smallest_implemented_above_128_bits():
    assert selection.SELECTED_PROFILE == "PARAM-II"
    assert selection.SELECTED_INTERPRETATION == "table-standard-deviation"
    report = selection.selection_report()
    selected = report["selected"]
    assert selected["name"] == "PARAM-II"
    assert selected["implementation_status"] == "implemented_table4"
    assert selected["forgery_classical_bits"] >= 128
    assert selected["key_recovery_classical_bits"] >= 128
    assert selected["forgery_classical_bits"] > 128
    by_name = {row["name"]: row for row in report["candidates"]}
    assert by_name["PARAM-I"]["forgery_classical_bits"] < 128
    assert by_name["PARAM-III"]["forgery_classical_bits"] > selected["forgery_classical_bits"]
    assert report["selection_policy"]["baseline_classical_bits"] == 128
    assert report["selection_policy"]["high_security_profile"] == "PARAM-III"


def test_candidates_match_the_frozen_table4_author_reports():
    report = selection.selection_report()
    by_name = {row["name"]: row for row in report["candidates"]}
    for profile in profiles:
        row = by_name[profile.name]
        source = profile.author_report
        assert row["author_target_bits"] == source.target_bits
        assert row["key_recovery_classical_bits"] == source.key_recovery_classical_bits
        assert row["key_recovery_quantum_bits"] == source.key_recovery_quantum_bits
        assert row["forgery_classical_bits"] == source.forgery_classical_bits
        assert row["forgery_quantum_bits"] == source.forgery_quantum_bits
        assert row["degree"] == profile.degree == 512
        assert row["p"] == profile.p == 16383
        assert row["base"] == profile.base == 31
        assert row["digits"] == profile.digits == 2
        assert row["Q"] == profile.Q == 15744063


def test_static_larger_profiles_are_explicitly_not_selected():
    report = selection.selection_report()
    by_name = {row["name"]: row for row in report["candidates"]}
    n1024 = by_name["STATIC-N1024-D4"]
    p_increase = by_name["STATIC-P-INCREASE"]
    assert n1024["implementation_status"] == "not_executable"
    assert p_increase["implementation_status"] == "rejected"
    assert n1024["selected"] is False and p_increase["selected"] is False
    assert "n<=512" in n1024["rationale"]
    assert "signing Schur geometry" in p_increase["rationale"]
    assert p_increase["Q"] > 2 * int(float(profiles[2].gamma))


def test_selected_params_preserve_explicit_interpretations_and_table4():
    table = selection.selected_params()
    literal = selection.selected_params("literal-density-width")
    assert type(table) is PaperParams and type(literal) is PaperParams
    assert table.profile_name == literal.profile_name == "PARAM-II"
    assert table.interpretation == "table-standard-deviation"
    assert literal.interpretation == "literal-density-width"
    record = selection.selection_report()["selected_params_record"]
    assert record["profile_name"] == "PARAM-II"
    assert record["source_sha256"] == profiles[1].source_sha256
    with pytest.raises(ValueError):
        selection.selected_params("default")


def test_selection_report_keeps_honest_flags_and_known_gaps():
    report = selection.selection_report()
    assert report["security_claim"] == "none"
    assert report["backend_admitted"] is False
    assert report["parameters_are_formal"] is False
    assert report["nist_security_category"] is None
    assert report["table4_unchanged"]["profiles"] == [
        profile.name for profile in profiles]
    text = "\n".join(report["known_gaps"])
    assert "q>2*gamma" in text
    assert "same-message" in text
    assert "not reproduced" in text
    assert "NIST category" in text
    encoded = json.dumps(report, ensure_ascii=False)
    assert "security_claim" in encoded
