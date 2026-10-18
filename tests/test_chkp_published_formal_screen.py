"""Published CHKP layout target, reduction ledger, and mandatory non-admission."""

from fractions import Fraction

import pytest

pytest.importorskip("sage.all", reason="use a Sage environment for the proven-prime target")

from ibme.core.randomness import SecureRandom
from ibme.hibe.mp12_structured import StructuredHIBEParams
from ibme.lattice.matrix_sampling.gpv import MatrixFiniteGPV
from experiments.research.chkp_published_formal_screen import (
    PROFILE_ID,
    SCHEMA,
    TARGET_N,
    build_target,
)


@pytest.fixture(scope="module")
def target():
    return build_target()


def test_exact_published_layout_is_not_the_installed_three_H_block_layout(target):
    group, layout = target["complete_group"], target["layout"]
    assert target["schema"] == SCHEMA
    assert target["profile_id"] == PROFILE_ID
    assert group["n"] == TARGET_N == 6144
    assert (group["w"], group["m"]) == (491520, 503808)
    assert layout["receiver_key_columns"] == group["m"]
    assert layout["leaf_recipient_columns"] == 2 * group["m"]
    assert layout["used_leaf_preamble_columns"] == 2 * group["m"] == 1007616
    assert layout["conservative_anonymous_uniform_padding_columns"] == group["m"]
    assert layout["transmitted_preamble_columns"] == 3 * group["m"] == 1511424
    assert layout["h_addresses"] == ["H(receiver)"]
    assert layout["g_addresses"] == "G(receiver,sender,bit-position)"
    assert layout["published_Theorem_5_3_is_adaptive_identity_not_anonymity"] is True

    installed = StructuredHIBEParams()
    assert installed.leaf_dimension == 3 * installed.m
    assert target["current_backend_implementation_matches"] is False
    assert target["current_HIBE_recipe_implemented"] is False


def test_numeric_candidate_is_complete_but_no_formal_or_backend_flag_is_flipped(target):
    group = target["complete_group"]
    assert group["q"] == 667066744249733736124919
    assert group["q_bits"] == 80 and group["q_prime_proved"] is True
    assert group["root_r_squared"] == 24577
    assert group["q_alpha"] == 157
    assert all(target["numeric_parameter_gates"].values())
    assert target["paper_numeric_target_complete"] is True
    assert target["proof_mapping_complete"] is False
    assert not any(target["proof_mapping_gates"].values())
    assert (target["paper_parameter_set_formal"], target["parameters_are_formal"]) == (False, False)
    assert (target["security_claim"], target["backend_admitted"]) == ("none", False)
    assert target["NIST_level_claimed"] is target["concrete_security_bits_claimed"] is None


def test_full_declared_query_projection_keeps_128bit_arithmetic_target(target):
    finite = target["formal_finite_budget"]
    group = target["complete_group"]
    assert finite["proof_simulator_controlled_H_roots"] == 2 * 2**20
    assert finite["proof_simulator_controlled_G_vectors"] == 256 * 2**20
    assert finite["proof_simulator_controlled_G_scalar_draws"] == 256 * 2**20 * 2 * group["m"]
    assert "controlled_G_finite_scalar_coupling" in finite["proof_simulator_terms"]
    assert "anonymous_padding_uniform_abort" in finite["anonymous_wire_terms"]
    total = Fraction(finite["full_ROM_finite_TV_or_failure_upper"])
    assert total <= Fraction(1, 2**128)
    assert finite["probability_dyadic_exponent"] == 131
    assert finite["target_128_met"] is True
    assert finite["exact_CHKP_Lemma_2_4_4_constant_mapped"] is False
    assert finite["full_proof_finite_bound_admitted"] is False


def test_reduction_losses_and_estimator_boundary_are_explicit(target):
    losses = target["reduction_loss_ledger"]
    assert losses["CHKP_Theorem_5_3_factor"] == 2**41
    assert losses["multibit_hybrid_factor"] == 2**8
    assert losses["ciphertext_LWE_total_factor"] == 2**49
    assert losses["cross_depth_anonymity_total_factor"] == 2**50
    assert losses["root_LWE_total_factor"] == (1 + 2 * 2**20) * target["complete_group"]["w"]
    assert losses["root_and_ciphertext_losses_are_separate_hybrids_not_summed"] is True
    assert target["ciphertext_lwe"]["anonymous_padding_used_as_samples"] is False
    assert target["estimator_coverage"]["complete_concrete_attack_coverage"] is False
    assert target["concrete_128bit_claim_admitted"] is False


def test_resource_projection_forces_non_admission(target):
    resources = target["resources"]
    assert resources["codec_minimum_bytes"]["parent_R_JSON_bytes"] == 507343011840
    assert resources["codec_minimum_bytes"]["anonymous_capsule_residue_bytes"] == 15116800
    assert resources["current_gates"]["parent_JSON_not_excluded_by_32MiB"] is False
    assert resources["current_gates"]["anonymous_capsule_not_excluded_by_4MiB"] is False
    assert resources["process_peak_RSS"] is resources["stage_seconds"] is None
    assert target["actual_full_HIBE_execution"] is False
    assert (target["root_or_key_generations"], target["sampler_calls"], target["entropy_reads"]) == (0, 0, 0)


def test_target_builder_does_not_read_entropy_or_construct_private_objects(monkeypatch):
    from ibme.lattice.matrix_sampling import mp12_structured as tool

    def forbidden(*args, **kwargs):
        raise AssertionError("paper target attempted private sampling or entropy")

    monkeypatch.setattr(SecureRandom, "read", forbidden)
    monkeypatch.setattr(tool.MatrixFiniteGaussian, "sample", forbidden)
    monkeypatch.setattr(MatrixFiniteGPV, "sample", forbidden)
    monkeypatch.setattr(tool.StructuredTrapdoor, "__post_init__", forbidden)
    monkeypatch.setattr(tool.StructuredPreimageSampler, "__init__", forbidden)
    projected = build_target(128)
    assert projected["paper_numeric_target_complete"] is True
    assert projected["backend_admitted"] is False


@pytest.mark.parametrize("bad", [True, 1, 16385, 2.0])
def test_target_dimension_has_an_exact_bounded_integer_domain(bad):
    with pytest.raises(ValueError, match="exact bounded integer"):
        build_target(bad)
