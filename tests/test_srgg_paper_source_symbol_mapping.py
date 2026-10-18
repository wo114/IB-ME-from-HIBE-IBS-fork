"""Exact original-source symbol and game-counterexample checks."""

from fractions import Fraction
from hashlib import sha256

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

from experiments.research.candidates.srgg.paper_parameters import PaperParams
from experiments.research.candidates.srgg.paper_profiles import SOURCE_PDF, SOURCE_SHA256
from experiments.research.candidates.srgg.paper_source_symbol_mapping import (
    ROOT, build_report, g1_subset_probability, game_trace,
    modulus_correspondence, smallest_odd_above,
)


@pytest.fixture(scope="module")
def report():
    return build_report()


def test_pdf_identity_and_frozen_table4_rows(report):
    assert sha256((ROOT / SOURCE_PDF).read_bytes()).hexdigest() == SOURCE_SHA256
    assert report["paper"]["sha256"] == SOURCE_SHA256
    assert [row["profile"] for row in report["original_table4_modulus_rows"]] == [
        "PARAM-I", "PARAM-II", "PARAM-III"]
    assert [row["gamma_published"] for row in report["original_table4_modulus_rows"]] == [
        "42086491.7", "63653172.0", "86573930.5"]


@pytest.mark.parametrize("name", ["PARAM-I", "PARAM-II", "PARAM-III"])
def test_only_direct_fs_modulus_mapping_fails_necessary_gamma_gate(name):
    params = PaperParams(name)
    row = modulus_correspondence(params)
    gamma = Fraction(params.source.gamma)
    assert params.modulus == params.source.p * params.source.q == 15744063
    assert params.source.q == 961
    assert row["ibS_verification_modulus_2Q"] == 31488126
    assert row["theorem1_q_for_direct_same_modulus_mapping"] == params.modulus
    assert row["theorem1_q_is_odd"]
    assert not row["theorem1_q_strictly_exceeds_2gamma"]
    assert Fraction(row["shortfall_below_2gamma"]) == 2 * gamma - params.modulus > 0
    assert row["smallest_odd_q_strictly_above_2gamma"] > 2 * gamma
    assert row["smallest_odd_q_strictly_above_2gamma"] % 2 == 1
    assert not row["gadget_q_preserves_ibS_verification_modulus"]
    assert not row["taking_q_as_2Q_is_odd"]
    assert not row["source_theorem1_direct_application_established"]


@pytest.mark.parametrize("value,expected", [
    (Fraction(0), 1), (Fraction(3), 5), (Fraction(7, 2), 5),
    (Fraction(420_864_917, 5), 84_172_985),
])
def test_smallest_strictly_larger_odd_integer(value, expected):
    assert smallest_odd_above(value) == expected
    with pytest.raises(ValueError):
        smallest_odd_above(-value - 1)


def test_exact_source_eta_gate_and_explicit_hypothetical_conversion(report):
    rows = report["original_table3_eta_rows"]
    assert [row["table3_dimension"] for row in rows] == [6144, 8192, 10240]
    assert all(row["printed_r_exact_decimal"] == "1.16" for row in rows)
    assert all(row["formal_eta_literal_definition"][
        "lower_strictly_exceeds_epsilon"] for row in rows)
    assert all(row["formal_eta_literal_definition"][
        "printed_r_satisfies_formal_eta_gate"] is False for row in rows)
    assert all(row["hypothetical_physical_sd_conversion"][
        "conversion_stated_by_source"] is False for row in rows)
    assert [row["hypothetical_physical_sd_conversion"][
        "upper_strictly_below_epsilon"] for row in rows] == [True, True, False]
    assert [row["hypothetical_physical_sd_conversion"][
        "lower_strictly_exceeds_epsilon"] for row in rows] == [False, False, True]


def test_source_euf_fresh_pair_is_weaker_than_native_strong(report):
    row = report["finite_game_trace_under_assumed_valid_forgery"][
        "same_message_different_signature"]
    assert not row["g0_euf_fresh_pair_wins_if_valid"]
    assert not row["g1_fresh_pair_and_X_restrictions_win_if_valid"]
    assert row["native_strong_exact_triple_wins_if_valid"]
    assert row["printed_p9_simulator_aborts_before_output"]
    assert not row["actual_forgery_produced_by_this_audit"]
    assert not report["source_security_statement_gap"][
        "theorem1_supplies_theorem2_strong_premise"]
    assert not report["source_security_statement_gap"][
        "definition3_and_G0_are_native_strong"]


def test_allowed_target_signing_trace_is_aborted_by_printed_simulator(report):
    row = report["finite_game_trace_under_assumed_valid_forgery"][
        "old_message_query_then_fresh_message_target_in_X"]
    assert row["g0_euf_fresh_pair_wins_if_valid"]
    assert row["g1_fresh_pair_and_X_restrictions_win_if_valid"]
    assert row["printed_p9_simulator_aborts_before_output"]
    assert row["g1_win_but_printed_simulator_aborts"]
    assert row["trace_assumes_a_valid_forgery"]
    assert not row["actual_forgery_produced_by_this_audit"]
    assert not report["finite_game_trace_under_assumed_valid_forgery"][
        "proof_view_equality_for_all_G1_allowed_queries_established"]


def test_printed_qs_lower_bound_misses_extraction_query_probability(report):
    delta = Fraction(1, 2)
    exact = g1_subset_probability(target_id=b"target",
                                  extraction_queries=(b"other",), delta=delta)
    assert exact == Fraction(1, 4)
    assert exact < delta * (1 - delta * 0) == Fraction(1, 2)
    row = report["g1_query_count_lower_bound_counterexample"]
    assert row["signing_query_count_qS"] == 0
    assert row["explicit_extraction_query_count_qE"] == 1
    assert row["exact_G1_X_event_probability"] == "1/4"
    assert row["printed_p8_delta_times_1_minus_delta_qS_for_epsilon_1"] == "1/2"
    assert row["printed_lower_bound_holds_for_this_query_shape"] is False
    assert row["underlying_valid_forgery_established"] is False
    assert g1_subset_probability(target_id=b"target",
                                 extraction_queries=(b"other", b"other"),
                                 delta=delta) == exact
    with pytest.raises(ValueError):
        g1_subset_probability(target_id=b"target",
                              extraction_queries=(b"target",), delta=delta)


def test_extracting_target_loses_game_and_rejected_signature_does_not_win():
    kwargs = dict(target_id=b"id", target_message=b"new", target_signature=b"sig",
                  signing_answers=((b"id", b"old", b"old-sig"),),
                  x_members=frozenset((b"id",)))
    extracted = game_trace(**kwargs, extraction_queries=(b"id",),
                           verifier_accepts=True)
    assert not extracted["g0_euf_fresh_pair_wins_if_valid"]
    assert not extracted["g1_fresh_pair_and_X_restrictions_win_if_valid"]
    rejected = game_trace(**kwargs, extraction_queries=(),
                          verifier_accepts=False)
    assert not rejected["g0_euf_fresh_pair_wins_if_valid"]
    assert not rejected["native_strong_exact_triple_wins_if_valid"]


def test_noncanonical_trace_and_nonpaper_parameter_rejected():
    with pytest.raises(TypeError):
        modulus_correspondence("PARAM-I")
    with pytest.raises(TypeError):
        game_trace(target_id="id", target_message=b"m", target_signature=b"s",
                   extraction_queries=(), signing_answers=(),
                   x_members=frozenset(), verifier_accepts=True)
    with pytest.raises(TypeError):
        game_trace(target_id=b"id", target_message=b"m", target_signature=b"s",
                   extraction_queries=[], signing_answers=(),
                   x_members=frozenset(), verifier_accepts=True)


def test_report_research_scope(report):
    assert report["security_claim"] == "none"
    assert report["backend_admitted"] is False
    assert report["parameters_are_formal"] is False
    assert report["nist_security_category"] is None
    assert report["author_intended_resolution"] is None
    assert len(report["route_log"]) == 6
