"""ABB public noise/correctness/comparison separation; never key generation."""

from fractions import Fraction

import pytest

pytest.importorskip("sage.all", reason="ABB projection and finite CDF require Sage")

from ibme.core.randomness import DeterministicRandom, SecureRandom
from experiments.research.abb_rom.noise_tradeoff_probe import (
    CIPHERTEXT_REQUIRED_ESTIMATES,
    COMPARISON_BITS,
    FINITE_SCALED_WIDTH,
    Q208,
    ROOT_REQUIRED_ESTIMATES,
    build_finite_noise_certificate,
    build_tradeoff_report,
    finalize_comparison,
)
from experiments.research.abb_rom.scaled_parameter_screen import (
    abb_projection,
    conditional_noise,
    maximum_abb_scaled_width,
)


def test_exact_maximum_correctness_width_has_a_strict_next_integer_boundary():
    row = abb_projection(128, Q208)
    dimension = row["leaf_dimension"]
    width = int(row["decrypt_width_squared"])
    maximum = maximum_abb_scaled_width(Q208, dimension, width)
    assert maximum == row["noise"]["maximum_conditional_correctness_scaled_width"]
    assert conditional_noise(Q208, dimension, width, maximum, abb=True)[
        "conditional_noise_sufficient"
    ]
    assert not conditional_noise(Q208, dimension, width, maximum + 1, abb=True)[
        "conditional_noise_sufficient"
    ]


def test_explicit_noise_changes_only_ciphertext_distribution_not_abb_geometry():
    minimum = abb_projection(128, Q208)
    explicit = abb_projection(128, Q208, noise_width=FINITE_SCALED_WIDTH)
    for name in (
        "random_rows",
        "root_dimension",
        "root_gs_squared_bound",
        "matrix_R_width_squared",
        "parent_width_squared",
        "leaf_width_squared",
        "decrypt_width_squared",
    ):
        assert explicit[name] == minimum[name]
    assert explicit["ciphertext_lwe"]["squared_width"] == FINITE_SCALED_WIDTH**2
    assert explicit["noise"]["scaled_continuous_width"] == FINITE_SCALED_WIDTH
    assert explicit["noise"]["scaled_width_selection"] == "explicit"
    assert explicit["noise"]["strict_Regev_noise_prerequisite"]


def test_qalpha_721_builds_the_actual_finite_rounded_continuous_cdf():
    result = build_finite_noise_certificate()
    certificate = result["certificate"]
    assert result["scaled_width"] == FINITE_SCALED_WIDTH == 721
    assert (result["radius"], result["support_count"], result["draw_bytes"]) == (8189, 16379, 32)
    assert certificate["scaled_width"] == "721"
    assert Fraction(certificate["tv_upper_including_abort"]) < Fraction(1, 2**127)
    assert len(certificate["cdf_sha256"]) == 64
    assert certificate["constant_time"] is False


def test_projection_consumes_no_entropy_and_keeps_petabyte_runtime_blockers(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("public ABB tradeoff projection consumed entropy")

    monkeypatch.setattr(SecureRandom, "read", forbidden)
    monkeypatch.setattr(DeterministicRandom, "read", forbidden)
    report = build_tradeoff_report((9600,), build_cdf=False)
    row = report["rows"][0]
    assert report["root_or_key_generations"] == report["ciphertext_generations"] == 0
    assert report["private_entropy_bytes"] == 0
    assert not report["finite_noise"]["built"]
    assert row["minimum_wire_bytes"]["parent_stored_full_basis"] > 10**15
    assert "root_n_within_current_cap" in row["runtime_blockers"]
    assert row["runtime_admitted"] is row["backend_admitted"] is False


def test_comparison_gate_fails_closed_on_unknown_and_never_grants_security():
    report = build_tradeoff_report((9472, 9600), build_cdf=False)
    for row in report["rows"]:
        row["finite_noise_table_built"] = True
        row["estimator_results"] = {
            "root_trapdoor_recovery": {
                name: {"status": "finite_estimate", "rop_log2": COMPARISON_BITS + 1}
                for name in (
                    "sis_lattice-classical",
                    "sis_lattice-quantum",
                )
            },
            "ciphertext_lwe": {
                name: {"status": "finite_estimate", "rop_log2": COMPARISON_BITS + 1}
                for name in (
                    "primal_usvp-classical",
                    "dual-classical",
                    "primal_usvp-quantum",
                    "dual-quantum",
                )
            }
        }
    report["rows"][0]["estimator_results"]["root_trapdoor_recovery"]["sis_lattice-quantum"] = {
        "status": "no_finite_estimate",
        "rop_log2": None,
    }
    finalize_comparison(report)
    assert not report["rows"][0]["comparison_model_gate"]
    assert not report["rows"][0]["implementation_research_gate"]
    assert report["rows"][0]["root_trapdoor_comparison_status"] == "invalid_or_incomplete"
    assert report["rows"][0]["ciphertext_comparison_gate"]
    assert not report["rows"][0]["root_trapdoor_comparison_gate"]
    assert report["rows"][1]["comparison_model_gate"]
    assert report["rows"][1]["implementation_research_gate"]
    assert report["rows"][1]["root_trapdoor_comparison_status"] == "meets_target"
    assert report["root_trapdoor_comparison_candidates"] == [report["rows"][1]["candidate_id"]]
    assert report["ciphertext_comparison_candidates"] == [
        report["rows"][0]["candidate_id"], report["rows"][1]["candidate_id"]
    ]
    assert report["comparison_model_candidates"] == [report["rows"][1]["candidate_id"]]
    assert report["implementation_research_candidates"] == [report["rows"][1]["candidate_id"]]
    assert report["complete_runtime_candidates"] == []
    assert report["secure_candidate_selected"] is False


def test_explicit_root_unknown_allows_research_but_not_formal_or_runtime_admission():
    report = build_tradeoff_report((9600,), build_cdf=False)
    row = report["rows"][0]
    row["finite_noise_table_built"] = True
    row["estimator_results"] = {
        "root_trapdoor_recovery": {
            name: {"status": "no_finite_estimate", "rop_log2": None}
            for name in ROOT_REQUIRED_ESTIMATES
        },
        "ciphertext_lwe": {
            name: {"status": "finite_estimate", "rop_log2": COMPARISON_BITS + 1}
            for name in CIPHERTEXT_REQUIRED_ESTIMATES
        },
    }
    finalize_comparison(report)
    assert row["root_trapdoor_comparison_status"] == "explicitly_unresolved"
    assert row["implementation_research_gate"] is True
    assert row["comparison_model_gate"] is row["runtime_admitted"] is False
    assert report["implementation_research_candidates"] == [row["candidate_id"]]
    assert report["comparison_model_candidates"] == report["complete_runtime_candidates"] == []
    assert report["secure_candidate_selected"] is False

    row["estimator_results"]["root_trapdoor_recovery"] = {
        name: {"status": "finite_estimate", "rop_log2": COMPARISON_BITS - 1}
        for name in ROOT_REQUIRED_ESTIMATES
    }
    finalize_comparison(report)
    assert row["root_trapdoor_comparison_status"] == "finite_below_target"
    assert row["implementation_research_gate"] is False
    assert report["implementation_research_candidates"] == []


@pytest.mark.parametrize(
    "role,model",
    [
        *(("root_trapdoor_recovery", name) for name in ROOT_REQUIRED_ESTIMATES),
        *(("ciphertext_lwe", name) for name in CIPHERTEXT_REQUIRED_ESTIMATES),
    ],
)
@pytest.mark.parametrize(
    "invalid",
    [float("inf"), float("-inf"), float("nan"), -1.0, True, 10**1000],
    ids=["positive-infinity", "negative-infinity", "nan", "negative", "bool", "float-overflow"],
)
def test_comparison_rejects_invalid_numeric_estimates_in_every_model(role, model, invalid):
    report = build_tradeoff_report((9600,), build_cdf=False)
    row = report["rows"][0]
    row["finite_noise_table_built"] = True
    row["estimator_results"] = {
        "root_trapdoor_recovery": {
            name: {"status": "finite_estimate", "rop_log2": COMPARISON_BITS}
            for name in ROOT_REQUIRED_ESTIMATES
        },
        "ciphertext_lwe": {
            name: {"status": "finite_estimate", "rop_log2": COMPARISON_BITS}
            for name in CIPHERTEXT_REQUIRED_ESTIMATES
        },
    }
    finalize_comparison(report)
    assert row["comparison_model_gate"] is True

    row["estimator_results"][role][model]["rop_log2"] = invalid
    finalize_comparison(report)
    role_prefix = "root_trapdoor" if role == "root_trapdoor_recovery" else "ciphertext"
    assert row["comparison_estimates_complete"] is False
    assert row[f"{role_prefix}_comparison_estimates_complete"] is False
    assert row["comparison_minimum_log2_rop"] is None
    assert row["comparison_model_gate"] is False
    assert row["implementation_research_gate"] is False
    assert row["runtime_admitted"] is False
    assert report["comparison_model_candidates"] == []
    assert report["implementation_research_candidates"] == []
    assert report["smallest_tested_comparison_candidate"] is None
    assert report["smallest_tested_implementation_research_candidate"] is None
    assert report["largest_tested_comparison_margin_candidate"] is None
    assert report["secure_candidate_selected"] is False
