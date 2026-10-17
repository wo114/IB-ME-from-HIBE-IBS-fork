"""Exact source-symbol and modulus-gate checks for the SRGG parameter audit."""

import json

from experiments.research.candidates.srgg.parameter_closure import (
    SCHEMA,
    build_report,
)


def test_report_freezes_source_rows_without_admission():
    report = build_report()
    assert report["schema"] == SCHEMA
    assert report["paper"]["sha256"] == (
        "258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152"
    )
    assert [row["modulus_gates"]["profile"] for row in report["rows"]] == [
        "PARAM-I", "PARAM-II", "PARAM-III"
    ]
    assert report["global_status"]["security_claim"] == "none"
    assert not report["global_status"]["parameters_are_formal"]
    assert not report["global_status"]["backend_admitted"]
    json.dumps(report)


def test_all_three_literal_rows_fail_both_q_mappings():
    report = build_report()
    for row in report["rows"]:
        gates = row["modulus_gates"]["modulus_candidates"]
        assert gates["gadget_q"]["odd"]
        assert not gates["gadget_q"]["gt_2gamma"]
        assert gates["ibs_Q"]["odd"]
        assert not gates["ibs_Q"]["gt_2gamma"]
        assert not gates["verification_2Q"]["odd"]
        assert not gates["verification_2Q"]["gt_2gamma"]
        assert row["modulus_gates"]["mapping_status"].startswith("unresolved")


def test_epsilon_grouping_is_explicit_and_both_smoothing_checks_fail():
    report = build_report()
    assert set(report["epsilon_parses"]) == {
        "source_radical_over_Qs_times_256_inside",
        "alternate_radical_over_Qs_times_2pow56_inside",
        "alternate_radical_over_Qs_times_256_outside",
    }
    assert report["epsilon_parses"]["source_radical_over_Qs_times_256_inside"]["epsilon_bits"] == 24
    assert report["epsilon_parses"]["alternate_radical_over_Qs_times_2pow56_inside"]["epsilon_bits"] == 48
    assert report["epsilon_parses"]["alternate_radical_over_Qs_times_256_outside"]["epsilon_bits"] == 28
    for row in report["rows"]:
        for check in row["smoothing"].values():
            assert check["pi_r_squared_less_than_five"]
            assert check["necessary_condition_fails"]
        diagnostic = row["physical_stddev_diagnostic"]
        assert not diagnostic["literal_necessary_condition_passes"]
        assert diagnostic["required_r_lower_diagnostic"].startswith("1.160036")
        assert diagnostic["certificate_status"].startswith("numerical diagnostic")


def test_w3_value_is_diagnostic_only():
    report = build_report()
    for row in report["rows"]:
        gates = row["modulus_gates"]
        assert gates["diagnostic_smallest_w_with_p_times_31_pow_w_above_2gamma"] == 3
        assert gates["diagnostic_Q_at_that_w"] == 488065953
        assert gates["diagnostic_is_new_parameter"]
        assert not report["global_status"]["parameters_are_formal"]
