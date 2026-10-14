"""Independent arithmetic/attack-role controls for A0, never key generation."""

from fractions import Fraction
from math import isqrt

import pytest

from experiments.research.abb_rom.scaled_parameter_screen import (
    Q61, abb_projection, build_report, chkp_projection, conditional_noise,
    mp12_projection, strict_noise_width,
)


@pytest.mark.parametrize("n", [1, 2, 3, 4, 16, 128, 256, 16384])
def test_strict_regev_boundary_including_square_dimensions(n):
    chi = strict_noise_width(n)
    assert chi**2 > 4*n
    assert (chi-1)**2 <= 4*n


@pytest.mark.parametrize("bad", [True, 0, -1, 16385, 1.0, "4"])
def test_noise_dimension_is_exact_and_bounded(bad):
    with pytest.raises(ValueError):
        strict_noise_width(bad)


@pytest.mark.parametrize("dim,width,chi", [(381, 82903323983053440, 4),
    (65537, 2**72, 23), (2**20, 2**90, 129)])
def test_chkp_noise_matches_independent_exact_inequality_above_old_dimension_cap(dim, width, chi):
    result = conditional_noise(Q61, dim, width, chi)
    # Cross-multiply the published bound, retaining integer rounding error.
    norm = dim*width
    t = isqrt(dim*norm)
    if t*t < dim*norm:
        t += 1
    twice_margin = 2*((Q61//2-1)//2) - (1+t)
    expected = twice_margin > 0 and 4*chi**2*(norm+1)*129 <= twice_margin**2
    assert result["conditional_noise_sufficient"] == expected
    assert result["total_sampler_TV_or_failure_upper"] is None


def test_no_pooling_independent_abb_vectors_and_no_extra_root_lwe_role():
    pytest.importorskip("sage.all", reason="scalar certificates require prescribed WSL Sage")
    row = abb_projection(128, Q61)
    role = row["ciphertext_lwe"]
    assert role["m"] == row["leaf_dimension"]
    assert role["known_plaintext_samples_per_vector"] == role["m"]+1
    assert role["fresh_vector_per_bit"] is True
    assert role["samples_from_different_fresh_vectors_pooled"] is False
    assert row["root_lwe"] is None
    assert row["normalized_quality_conditioning_used"] is False
    assert row["noise"]["strict_Regev_noise_prerequisite"]


def test_statistical_chkp_and_computational_mp12_keep_distinct_root_roles():
    pytest.importorskip("sage.all", reason="scalar certificates require prescribed WSL Sage")
    from ibme.lattice.chkp.joint_parameters import evaluate_noise
    cp, mp = chkp_projection(128), mp12_projection(128)
    assert cp["root_lwe"] is None
    assert mp["root_statistical_uniformity_upper"] is None
    assert mp["root_lwe"]["n"] == mp["root_lwe"]["m"] == 128
    assert mp["root_lwe"]["independent_columns"] == 128*61
    for row in (cp, mp):
        role = row["ciphertext_lwe"]
        assert role["m"] == row["leaf_dimension"]
        assert role["known_plaintext_samples_per_vector"] == role["m"]+256
        assert role["fresh_vector_per_bit"] is False
        old = evaluate_noise(q=Q61, dimension=row["leaf_dimension"],
            width_squared=int(row["leaf_width_squared"]), alpha=Fraction(23, Q61),
            error_bits=128, seed_bits=256, encapsulations=2**20)
        assert row["noise"]["conditional_noise_sufficient"] == old["conditional_noise_sufficient"]
        assert row["noise"]["rounding_error_upper"] == old["rounding_error_upper"]
        assert not row["current_execution_gates"]["parent_wire_not_excluded_by_lower_bound"]


def test_no_keys_samples_or_entropy_and_large_sizes_are_lower_bounds(monkeypatch):
    pytest.importorskip("sage.all", reason="scalar certificates require prescribed WSL Sage")
    from ibme.core.randomness import SecureRandom, DeterministicRandom
    from ibme.lattice.matrix_sampling import MatrixFiniteGaussian
    def forbidden(*args, **kwargs):
        raise AssertionError("public projection attempted sampling")
    monkeypatch.setattr(SecureRandom, "read", forbidden)
    monkeypatch.setattr(DeterministicRandom, "read", forbidden)
    monkeypatch.setattr(MatrixFiniteGaussian, "sample", forbidden)
    report = build_report((128,))
    assert len(report["rows"]) == 5
    assert report["private_entropy_bytes"] == report["root_or_key_generations"] == 0
    assert report["projected_process_peak_RSS"] is None
    assert report["projected_stage_seconds"] is None
    assert report["secure_candidate_selected"] is False
    for row in report["rows"]:
        assert row["parameters_are_formal"] is row["backend_admitted"] is False
        assert row["security_claim"] == "none"
        assert not all(row["current_execution_gates"].values())
        assert row["minimum_wire_bytes"]["parent_stored_full_basis"] == 6*row["parent_dimension"]**2
        assert not row["current_execution_gates"]["Hybrid_parent_not_excluded_by_lower_bound"]
        assert row["estimator_results"] == {}


def test_abb_unconditioned_widths_match_existing_screen_on_identical_root():
    pytest.importorskip("sage.all", reason="scalar certificates require prescribed WSL Sage")
    from ibme.hibe.abb_rom import ABBTrapGenParams, abb_parameter_screen
    from ibme.lattice.matrix_sampling import MatrixFiniteOptions
    row = abb_projection(1, Q61)
    root = ABBTrapGenParams(1, Q61, row["random_rows"], row["m1"], row["m2"],
        hadamard_scale=row["hadamard_scale"])
    existing = abb_parameter_screen(root, options=MatrixFiniteOptions())
    for new, old in (("matrix_R_width_squared", "matrix_gaussian_squared_width"),
        ("parent_width_squared", "sigma1_squared"), ("leaf_width_squared", "sigma2_squared"),
        ("decrypt_width_squared", "decryption_tau_squared")):
        assert row[new] == existing[old]
    # n=1 projection uses chi=3 rather than the frozen backend's chi=4;
    # only the geometry chain above is identical, not its noise configuration.
    assert row["noise"]["scaled_continuous_width"] == 3
