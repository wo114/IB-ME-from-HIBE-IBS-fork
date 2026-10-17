"""Complete target groups, literal public coefficients and resource limits."""

from fractions import Fraction

import pytest
pytest.importorskip("sage.all", reason="use prescribed WSL ~/miniconda3/envs/sage")
from sage.all import ZZ, previous_prime, matrix

from ibme.core.randomness import DeterministicRandom, SecureRandom
from ibme.lattice.chkp.joint_parameters import evaluate_noise
from ibme.hibe.mp12_structured import StructuredHIBEParams
from ibme.lattice.matrix_sampling.gpv import MatrixFiniteGPV
from experiments.research.structured_target_screen import (
    ALLOCATION, analysis_gadget, noise_condition, select_group, target_row, width_group,
)


@pytest.fixture(scope="module")
def row():
    return target_row(128)


def test_projected_decoder_is_the_current_exact_decoder_inequality():
    p = StructuredHIBEParams()
    a = evaluate_noise(q=p.q, dimension=p.leaf_dimension, width_squared=p.leaf_width_squared,
                      alpha=p.alpha, error_bits=128)
    b = noise_condition(p.q, p.leaf_dimension, p.leaf_width_squared, p.q_alpha, error_bits=128)
    for key in ("conditional_noise_sufficient", "rounding_error_upper", "integer_phase_radius",
                "continuous_squared_upper", "continuous_margin"):
        assert a[key] == b[key]


def test_selected_prime_is_minimal_for_the_declared_complete_recipe(row):
    g = row["complete_group"]
    assert ZZ(g["q"]).is_prime(proof=True) and g["noise"]["conditional_noise_sufficient"]
    previous = int(previous_prime(g["q"]))
    assert ZZ(previous).is_prime(proof=True)
    pg = width_group(128, (previous-1).bit_length())
    assert not noise_condition(previous, pg["leaf_dimension"], pg["leaf_width_squared"], pg["q_alpha"])["conditional_noise_sufficient"]


def test_projection_does_not_admit_or_build_a_high_dimensional_key(row):
    assert row["complete_group"]["q_bits"] == 59
    assert row["finite_projection"]["probability_dyadic_exponent"] >= 128
    assert Fraction(row["finite_projection"]["terms"]["ideal_decode_failure_if_norm_good"]) == Fraction(1, 2**132)
    assert row["finite_projection"]["actual_private_precision_or_whole_call_resource_admitted"] is False
    assert row["finite_projection"]["current_HIBE_recipe_implemented"] is False
    assert row["resources"]["current_gates"]["complete_HG_prefix_within_512"] is False
    assert row["resources"]["current_gates"]["parent_JSON_not_excluded_by_32MiB"] is False
    assert row["resources"]["process_peak_RSS"] is None
    assert (row["security_claim"], row["backend_admitted"], row["parameters_are_formal"]) == ("none", False, False)


def test_ciphertext_comparator_uses_both_H_blocks_with_the_correct_small_secret(row):
    g, c = row["complete_group"], row["ciphertext_lwe"]
    assert c["m"] == 2*g["m"] == c["available_H_samples"]
    assert c["secret"] == "small-Gaussian" and c["squared_width"] == g["q_alpha"]**2
    assert c["estimator_distribution_is_literal"] is False
    assert c["root_other_columns_and_256_terminals_used"] is False
    assert row["root_lwe"]["m"] == 128


def test_actual_public_gadget_above_the_runtime_modulus_cap_is_not_a_backend():
    from sage.all import next_prime
    q = int(next_prime(2**70, proof=True))
    block = analysis_gadget(q)
    assert abs(matrix(ZZ, block.basis_rows).det()) == q
    from ibme.lattice.chkp.joint_parameters import smoothing_factor
    squared = 20*smoothing_factor(block.public.ncols, 192)
    sampler = MatrixFiniteGPV(block, squared, epsilon_bits=192)
    x = sampler.sample((q-1,), rng=DeterministicRandom(b"A-public-gadget-q71-TEST"))
    assert sum(a*b for a,b in zip(block.public.rows[0], x)) % q == q-1
    with pytest.raises(ValueError, match="outside resource range"):
        from ibme.lattice.matrix_sampling.mp12_structured import gadget_block
        gadget_block(q)


def test_projector_reads_no_entropy_and_constructs_no_structured_private_key(monkeypatch):
    from ibme.lattice.matrix_sampling import mp12_structured as tool
    def forbidden(*args, **kwargs): raise AssertionError("target projector attempted private work")
    monkeypatch.setattr(SecureRandom, "read", forbidden)
    monkeypatch.setattr(tool.MatrixFiniteGaussian, "sample", forbidden)
    monkeypatch.setattr(MatrixFiniteGPV, "sample", forbidden)
    monkeypatch.setattr(tool.StructuredTrapdoor, "__post_init__", forbidden)
    monkeypatch.setattr(tool.StructuredPreimageSampler, "__init__", forbidden)
    assert target_row(128)["complete_group"]["q_prime_proved"]
