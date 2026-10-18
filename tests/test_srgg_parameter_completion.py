"""Integrated SRGG parameter-closure continuation checks."""

import json
from fractions import Fraction

from experiments.research.candidates.srgg.parameter_completion import build_report


def test_completion_keeps_source_size_namespaces_and_status_flags():
    report = build_report()
    mapping = report["source_table_mapping"]
    assert mapping["table1_and_table4_are_distinct_source_views"]
    assert len(mapping["rows"]) == 3
    for row in mapping["rows"]:
        assert row["source_size_namespace_is_preserved"]
        assert not row["table1_mpk_equals_table4_mpk"]
        assert not row["table1_signature_equals_table4_signature"]
        assert row["difference_explanation"] is None

    status = report["global_status"]
    assert status["source_tables_mapped"]
    assert status["listed_static_resource_checks_complete"]
    assert not status["complete_runtime_resource_preflight_closed"]
    assert status["security_claim"] == "none"
    assert status["parameters_are_formal"] is False
    assert status["backend_admitted"] is False
    assert status["nist_security_category"] is None
    json.dumps(report, default=str)


def test_completion_separates_n512_receipt_from_n2048_static_preflight():
    rows = build_report()["resource_preflight"]["rows"]
    assert [row["label"] for row in rows] == ["n512-d2-b31-w8", "n2048-d3-b3-w22"]
    assert rows[0]["execution_status"].startswith("n512_receipt_exists")
    assert rows[1]["execution_status"].startswith("preflight_only")
    assert rows[1]["coefficient_dimensions"]["signing"] == 149504
    assert rows[1]["Q"] == 1682495510936535
    assert rows[0]["execution_limits"]["status"] == "listed_static_guards_pass_only"
    assert rows[1]["execution_limits"]["status"] == "rejected_by_listed_static_guards"
    assert not rows[1]["execution_limits"]["checks"]["digits_le_8_execution_cap"]
    assert rows[1]["execution_limits"]["checks"]["witness_coefficients_le_2pow20_geometry_cap"]
    assert all(not row["execution_limits"]["complete_runtime_preflight_performed"] for row in rows)
    receipt = build_report()["resource_preflight"]["n512_execution_receipt"]
    assert receipt["manifest_match"]
    assert receipt["completed"] is True
    assert receipt["actual_entropy_bytes"] > 0


def test_completion_preserves_structure_and_finite_law_boundaries():
    report = build_report()
    structure = report["structure_and_attack_boundaries"]["rows"]
    assert [row["mod3_full_ring_tv_bits"] for row in structure] == [406, 2430]
    assert [row["mod3_shared_column_tv_bits"] for row in structure] == [402, 2424]
    assert [row["digits"] for row in structure] == [8, 22]
    from experiments.research.candidates.srgg.spectral_bounds import public_t_squared_upper
    for row in structure:
        assert Fraction(row["public_cbd1_spectral_squared_upper"]) == public_t_squared_upper(
            row["degree"], row["rank"], row["digits"])
    assert all(not row["strong_reduction_closed"] for row in structure)
    finite = report["finite_law_and_hnf_boundary"]
    assert finite["toy_hnf_probe"]["is_actual_srgg_sampler_law"] is False
    assert finite["toy_hnf_probe"]["repaired_to_finite_exact_gaussian_tv"] != "0"
    assert finite["n512_hnf_key_distribution_identified"] is False
    assert report["service_abort_boundary"]["full_service_abort_including_IO_crash_and_runtime_fault"] is None


def test_secondary_theorem_gate_is_reported_as_conditional_only():
    gate = build_report()["theorem_secondary_gate"]
    assert gate["all_conditional_Q_gt_s1_eta_r"]
    assert gate["formal_gate_closed"] is False
    assert [Fraction(row["s1_times_eta_r"]) for row in gate["rows"]] == [
        Fraction("977982.312"), Fraction("1214188.472"), Fraction("1436156.560")]
    for row in gate["rows"]:
        assert row["conditional_Q_gt_s1_eta_r"]
        assert row["conditional_Q_gt_converted_product_upper"]
        assert Fraction(row["physical_stddev_two_widths_product_upper"]) > Fraction(row["s1_times_eta_r"])
        assert row["q_mapping_to_Q_verified"] is False
        assert row["s1_symbol_mapping_formally_verified"] is False
        assert row["r_precision_and_normalization_verified"] is False
