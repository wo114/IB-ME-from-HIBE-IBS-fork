"""Tighter ABB public frontier remains reproducible and fail-closed."""

from fractions import Fraction
import hashlib
import json
from pathlib import Path

import pytest

pytest.importorskip("sage.all", reason="ABB frontier requires Sage")

from experiments.research.abb_rom.noise_tradeoff_probe import (
    CIPHERTEXT_REQUIRED_ESTIMATES,
    COMPARISON_BITS,
    ROOT_REQUIRED_ESTIMATES,
)
from experiments.research.abb_rom.tight_parameter_frontier import (
    BASELINE_SCHEMA,
    OPERATOR_CONDITIONAL_TAIL_BITS,
    OPERATOR_SERVICE_BUDGET_BITS,
    OPERATOR_UNCONDITIONED_TAIL_BITS,
    RECOMMENDED_ID,
    RUNTIME_SCHEMA,
    SCHEMA,
    ap09_dimension_conditions,
    build_frontier_report,
    build_frontier_row,
    finalize_frontier,
    matrix_bernstein_operator_bound,
    minimum_ap09_random_rows,
    runtime_summary,
)


ROOT = Path(__file__).resolve().parents[1]
BASELINE = (
    ROOT
    / "docs/research/team-a-delivery/2026-10-18-abb-noise-tradeoff/parameter-card.json"
)
EVIDENCE = (
    ROOT
    / "docs/research/team-a-delivery/2026-10-18-abb-tight-frontier/parameter-card.json"
)
RUNTIME = EVIDENCE.with_name("runtime-summary.json")


def _estimates(value):
    return {
        "root_trapdoor_recovery": {
            name: {"status": "no_finite_estimate", "rop_log2": None}
            for name in ROOT_REQUIRED_ESTIMATES
        },
        "ciphertext_lwe": {
            name: {"status": "finite_estimate", "rop_log2": value}
            for name in CIPHERTEXT_REQUIRED_ESTIMATES
        },
    }


def test_minimum_ap09_dimension_is_exact_and_previous_integer_fails():
    result = minimum_ap09_random_rows(8192, 179)
    assert result == {
        "random_rows_exceeds_nk": True,
        "strict_setup_dimension": True,
        "lhl_target": True,
        "lhl_dyadic_exponent": -244372,
        "m1": 1_955_158,
        "m2": 6_843_052,
        "dimension": 8_798_210,
    }
    previous = ap09_dimension_conditions(8192, 179, result["m1"] - 1)
    assert previous["dimension"] == 6 * 8192 * 179 - 1
    assert previous["strict_setup_dimension"] is False
    assert previous["random_rows_exceeds_nk"] is previous["lhl_target"] is True


def test_matrix_bernstein_bound_reserves_the_whole_service_budget():
    result = matrix_bernstein_operator_bound(
        8_798_210, 1_290_443_801, tail_bits=OPERATOR_UNCONDITIONED_TAIL_BITS
    )
    assert OPERATOR_SERVICE_BUDGET_BITS == 129
    assert OPERATOR_CONDITIONAL_TAIL_BITS == 149
    assert OPERATOR_UNCONDITIONED_TAIL_BITS == 150
    assert result["operator_norm_upper"] == 71_759_992_151_508
    assert (
        result["operator_norm_squared_upper"]
        < result["deterministic_support_frobenius_squared_upper"]
    )
    assert result["unconditioned_failure_upper"] == "2^-150"
    assert result["independent_zero_mean_bounded_summands"] is True


def test_recommended_row_has_exact_geometry_correctness_and_public_only_metadata():
    row = build_frontier_row(8224, 180)
    assert row["candidate_id"] == RECOMMENDED_ID
    assert row["q"] == 1532495540865888858358347027150309183618739122183602129
    assert (row["random_rows"], row["m2"], row["root_dimension"]) == (
        1_973_761,
        6_908_162,
        8_881_923,
    )
    assert row["matrix_R_finite_scalar_certificate"]["radius"] == 1_308_934_174
    accounting = row["matrix_R_finite_sampler_accounting"]
    assert accounting["total_conditioning_tv_amplification_upper"] == 16
    assert Fraction(accounting["service_tv_union_upper"]) < Fraction(1, 2**129)
    assert accounting["public_fixed_tape_bytes_per_scalar"] == 3_026_760
    assert accounting["whole_matrix_attempt_fixed_tape_bytes"] > 10**20
    assert accounting["sample_R_call_fixed_tape_bytes"] > 10**21
    invertibility = row["matrix_R_finite_invertibility_certificate"]
    assert invertibility["support_mod_q_injective"] is True
    assert Fraction(invertibility["singular_probability_upper"]) < Fraction(51, 1000)
    assert Fraction(invertibility["invertibility_probability_lower"]) > Fraction(94, 100)
    assert invertibility["invertibility_probability_exceeds_one_half"] is True
    assert invertibility["whole_matrix_attempts"] == row["sample_R_max_matrices"] == 35
    assert Fraction(invertibility["service_rank_abort_union_upper"]) < Fraction(
        1, 2**130
    )
    operator = row["transformation_operator_bound"]
    assert operator["operator_norm_upper"] == 73_132_956_277_301
    assert operator["conditional_failure_upper"] == "2^-149"
    assert operator["service_conditional_failure_union_upper"] == "2^-129"
    assert operator["total_service_statistical_budget_below_2^-128"] is True
    assert operator["finite_sampler_conditioning_transfer_verified"] is True
    assert row["noise"]["error_bits"] == 158
    assert row["noise"]["maximum_conditional_correctness_scaled_width"] == 1419
    assert row["noise"]["conditional_noise_sufficient"] is True
    assert row["noise"]["strict_Regev_noise_prerequisite"] is True
    assert row["minimum_wire_bytes"]["parent_stored_full_basis"] == 473_331_337_067_574
    assert row["minimum_wire_bytes"]["capsule_coefficients"] == 52_296_768_512
    assert row["root_or_key_generated"] is row["ciphertext_generated"] is False
    assert row["private_entropy_bytes"] == 0
    assert row["security_claim"] == "none"
    assert row["backend_admitted"] is row["parameters_are_formal"] is False


def test_research_gate_accepts_only_complete_numeric_ciphertext_results():
    report = build_frontier_report(BASELINE, build_cdf=False)
    row = next(row for row in report["rows"] if row["candidate_id"] == RECOMMENDED_ID)
    report["rows"] = [row]
    row["finite_noise_table_built"] = True
    row["ciphertext_noise_service_accounting"]["actual_finite_cdf_built"] = True
    row["estimator_results"] = _estimates(COMPARISON_BITS + 1)
    finalize_frontier(report)
    assert row["root_trapdoor_comparison_status"] == "explicitly_unresolved"
    assert row["ciphertext_comparison_gate"] is True
    assert row["implementation_research_gate"] is True
    assert row["comparison_model_gate"] is row["runtime_admitted"] is False
    assert report["implementation_research_candidates"] == [RECOMMENDED_ID]
    assert report["recommended_implementation_research_candidate"] == RECOMMENDED_ID
    assert report["comparison_model_candidates"] == report["complete_runtime_candidates"] == []
    assert report["secure_candidate_selected"] is False

    row["estimator_results"]["ciphertext_lwe"][
        CIPHERTEXT_REQUIRED_ESTIMATES[0]
    ]["rop_log2"] = float("nan")
    finalize_frontier(report)
    assert row["ciphertext_comparison_estimates_complete"] is False
    assert row["ciphertext_comparison_minimum_log2_rop"] is None
    assert row["implementation_research_gate"] is False
    assert report["implementation_research_candidates"] == []
    assert report["recommended_implementation_research_candidate"] is None


def test_finite_root_result_below_target_is_not_treated_as_unknown():
    report = build_frontier_report(BASELINE, build_cdf=False)
    row = next(row for row in report["rows"] if row["candidate_id"] == RECOMMENDED_ID)
    report["rows"] = [row]
    row["finite_noise_table_built"] = True
    row["ciphertext_noise_service_accounting"]["actual_finite_cdf_built"] = True
    row["estimator_results"] = _estimates(COMPARISON_BITS + 1)
    row["estimator_results"]["root_trapdoor_recovery"] = {
        name: {"status": "finite_estimate", "rop_log2": COMPARISON_BITS - 1}
        for name in ROOT_REQUIRED_ESTIMATES
    }
    finalize_frontier(report)
    assert row["root_trapdoor_comparison_status"] == "finite_below_target"
    assert row["implementation_research_gate"] is False


def test_baseline_binding_rejects_changed_noise_width(tmp_path):
    card = json.loads(BASELINE.read_text(encoding="utf-8"))
    assert card["schema"] == BASELINE_SCHEMA
    row = next(row for row in card["rows"] if row["n"] == 9600)
    row["noise"]["scaled_continuous_width"] += 1
    changed = tmp_path / "changed-baseline.json"
    changed.write_text(json.dumps(card), encoding="utf-8")
    with pytest.raises(ValueError, match="q208/chi721"):
        build_frontier_report(changed, build_cdf=False)


def test_runtime_summary_never_promotes_the_research_frontier():
    report = build_frontier_report(BASELINE, build_cdf=False)
    summary = runtime_summary(report)
    assert summary["schema"] == RUNTIME_SCHEMA
    assert summary["source_schema"] == SCHEMA
    assert summary["rng"].startswith("none")
    assert summary["root_or_key_generations"] == summary["ciphertext_generations"] == 0
    assert summary["private_entropy_bytes"] == 0
    assert summary["complete_runtime_candidates"] == []
    assert summary["security_claim"] == "none"
    assert summary["backend_admitted"] is summary["parameters_are_formal"] is False


def test_checked_in_frontier_is_current_and_stays_research_only():
    report = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    runtime = json.loads(RUNTIME.read_text(encoding="utf-8"))
    assert report["schema"] == SCHEMA
    assert runtime["schema"] == RUNTIME_SCHEMA
    assert report["baseline"]["sha256"] == hashlib.sha256(BASELINE.read_bytes()).hexdigest()
    for name, digest in report["source_sha256"].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
    assert report["estimator"]["commit"] == "53da5982597709ba0fdf94ea37a84d822310fd84"
    assert report["finite_ciphertext_noise"]["built"] is True
    assert (
        report["finite_ciphertext_noise"]["radius"],
        report["finite_ciphertext_noise"]["support_count"],
        report["finite_ciphertext_noise"]["draw_bytes"],
    ) == (10_815, 21_631, 40)
    assert (
        report["finite_ciphertext_noise"]["certificate"]["cdf_sha256"]
        == "0c1141ca50e88cf3084a9a18704186010536ca84e6eb44a74ec60771b79b5d4c"
    )
    assert report["implementation_research_candidates"] == [
        "abb-rom-tight-n8224-q180-chi721",
        "abb-rom-tight-n8704-q180-chi721",
    ]
    assert report["recommended_implementation_research_candidate"] == RECOMMENDED_ID
    assert report["smallest_tested_implementation_research_candidate"] == RECOMMENDED_ID
    q179 = next(row for row in report["rows"] if row["q_bits"] == 179)
    assert q179["ciphertext_comparison_gate"] is True
    assert q179["noise"]["conditional_noise_sufficient"] is False
    recommended = next(row for row in report["rows"] if row["candidate_id"] == RECOMMENDED_ID)
    assert recommended["local_service_statistical_accounting"]["union_below_2^-128"]
    assert report["comparison_model_candidates"] == runtime["comparison_model_candidates"] == []
    assert report["complete_runtime_candidates"] == runtime["complete_runtime_candidates"] == []
    assert report["root_or_key_generations"] == runtime["root_or_key_generations"] == 0
    assert report["private_entropy_bytes"] == runtime["private_entropy_bytes"] == 0
    assert report["security_claim"] == runtime["security_claim"] == "none"
    assert report["backend_admitted"] is report["parameters_are_formal"] is False
