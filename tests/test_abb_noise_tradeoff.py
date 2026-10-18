"""ABB public noise/correctness/comparison separation; never key generation."""

from fractions import Fraction

import pytest

pytest.importorskip("sage.all", reason="ABB projection and finite CDF require Sage")

from ibme.core.randomness import DeterministicRandom, SecureRandom
from experiments.research.abb_rom.noise_tradeoff_probe import (
    COMPARISON_BITS,
    FINITE_SCALED_WIDTH,
    Q208,
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
    report["rows"][0]["estimator_results"]["ciphertext_lwe"]["dual-quantum"] = {
        "status": "no_finite_estimate",
        "rop_log2": None,
    }
    finalize_comparison(report)
    assert not report["rows"][0]["comparison_model_gate"]
    assert report["rows"][1]["comparison_model_gate"]
    assert report["comparison_model_candidates"] == [report["rows"][1]["candidate_id"]]
    assert report["complete_runtime_candidates"] == []
    assert report["secure_candidate_selected"] is False
