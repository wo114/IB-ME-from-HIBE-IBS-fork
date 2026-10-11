"""Real same-input diagnostics, controls and explicit scope boundaries."""

import json
import pytest
pytest.importorskip("sage.all", reason="same-input trapdoor chain uses prescribed WSL Sage")

from sage.all import QQ, ZZ, matrix
from experiments.research import ibme_chain_audit as audit
from experiments.research.chkp_genbasis import AP09Parameters, gen_basis
from experiments.research.chkp_basis import ModMatrixReference
from experiments.research.chkp_leaf_reference import LeafPreimages
from experiments.research.gaussian_reference import SamplingAbort
from experiments.research.ibme_root_sampler_audit import checked_sage_lll, geometry, CountingRandom
from experiments.research.ibme_noise_budget import RoundedNoiseParams
from experiments.research.ibme_rounded_noise import build_rounded_noise
from ibme.core.randomness import DeterministicRandom


@pytest.fixture(scope="module")
def tiny_config():
    return AP09Parameters(n=1, q=2, random_rows=2, m1=2, m2=8, hadamard_scale=4)


@pytest.fixture(scope="module")
def result(tiny_config):
    return audit.run_chain(tiny_config, b"ibme-chain-test", leaf_bits=4)


def test_real_chain_uses_parent_randomization_and_terminal_vectors(result):
    assert result["outcome"] == "parent_and_fixed_terminal_preimages_completed"
    stages = result["stages"]
    assert stages["GenBasis"]["dimension"] == 10
    assert stages["parent_RandBasis"]["gaussian_vectors_used"] >= 20
    leaf = stages["terminal_leaf_admission"]
    assert leaf["dimension"] == 30 and not leaf["second_RandBasis_used"]
    fixed = stages["fixed_leaf_cache"]
    assert fixed["equations_exact"] == fixed["preimages"] == 4
    assert fixed["entropy_bytes"] > 0
    assert fixed["norms_within_budget"] == 4


def test_actual_cache_restore_keeps_same_vectors_without_entropy(result):
    fixed = result["stages"]["fixed_leaf_cache"]
    assert fixed["restored_vectors_identical"]
    assert fixed["cache_hit_entropy_bytes"] == fixed["restore_hit_entropy_bytes"] == 0
    assert fixed["snapshot_bytes"] > 0 and not fixed["snapshot_written_to_disk"]


def test_256_bit_rejection_and_missing_security_terms_cannot_be_hidden(result):
    capacity = result["stages"]["256_bit_capacity_control"]
    assert capacity["status"] == "admission_rejected"
    assert capacity["required_seed_bits"] == 256 and not capacity["capacity_met"]
    assert capacity["entropy_bytes"] == 0
    assert result["full_joint_failure_upper"] is None
    assert result["preprocessing_abort_or_resource_upper"] is None
    assert "leaf preimage norm-tail probability" in result["omitted_from_selected_terms"]
    assert not result["backend_admitted"] and result["security_claim"] == "none"
    assert not result["ideal_H_or_G_implemented"]
    assert not result["diagnostic_lll_uniform_resources_admitted"]
    assert not result["parameters_are_formal"]


def test_honest_noise_has_its_own_decode_count_and_conditional_budget(result):
    probe = result["stages"]["rounded_noise_phase_probe"]
    assert probe["negative_noise_control"] and not probe["full_KEM_or_HIBE_implemented"]
    assert len(probe["repetitions"]) == audit.PHASE_REPETITIONS
    for rep in probe["repetitions"]:
        assert rep["phase_equations_exact"] == rep["noiseless_control_correct"] == rep["bits"]
        assert rep["honest_rounded_noise_correct"]+rep["honest_rounded_noise_failed"] == rep["bits"]
        assert rep["scalar_noise_calls"] == 30+rep["bits"]
        assert rep["entropy_bytes"] > 0
        assert not rep["noise_profile_is_full_chain_correctness_candidate"]


def test_only_scalar_counts_and_bounds_leave_diagnostic(result):
    encoded = json.dumps(result)
    for forbidden in ('"basis_rows"', '"preimages": [', '"wire":', '"rng":', '"secret":'):
        assert forbidden not in encoded


@pytest.mark.parametrize("q", [2, 3, 5, 7, 17, 257])
def test_decoder_exhaustively_matches_independent_circle_distances(q):
    for phase in range(-q, 2*q):
        distances = [min(abs(phase-(bit*(q//2)+wrap*q)) for wrap in range(-4, 5))
                     for bit in (0, 1)]
        assert audit.decode_phase(phase, q) == int(distances[0] >= distances[1])


def test_phase_uses_actual_rounded_continuous_errors_and_exact_coset_relation():
    public = ModMatrixReference([[1, 0]], 7)
    batch = LeafPreimages(public, ((1,), (2,)), ((1, 0), (2, 0)))
    noise = build_rounded_noise(RoundedNoiseParams(q=7, alpha="3/7"))
    result = audit.phase_probe(batch, CountingRandom(b"phase-test"), noise)
    assert result["phase_equations_exact"] == result["noiseless_control_correct"] == 2
    assert result["scalar_noise_calls"] == 4
    assert result["nonzero_noise_coordinates"] > 0
    assert result["entropy_bytes"] >= 4*16


def test_exact_lll_postprocessing_matches_the_strict_size_check():
    # This fixed AP09 fixture yields mu=-260/519 with Sage's default eta
    # 0.501. The diagnostic keeps a supported eta and tightens size exactly.
    params = AP09Parameters(n=1, q=257, random_rows=10, m1=10, m2=38, hadamard_scale=10)
    root = gen_basis(params, rng=DeterministicRandom(b"ibme-chain-probe-root")).basis
    original = matrix(ZZ, root.basis_rows)
    loose = original.transpose().LLL(delta=QQ(99)/100, eta=QQ(501)/1000)
    loose_gs, _ = loose.change_ring(QQ).gram_schmidt()
    # Regression is checked using exact output invariants, not the specific
    # approximate library output (which may improve in later Sage versions).
    reduced = checked_sage_lll(root, params.gs_squared_bound)
    lengths, mu = geometry(reduced)
    assert max(lengths) <= params.gs_squared_bound
    assert all(abs(mu[i,j]) <= QQ(1)/2 for i in range(len(lengths)) for j in range(i))
    assert abs(matrix(ZZ, reduced.basis_rows).det()) == params.q
    assert loose_gs.nrows() == len(lengths)


@pytest.mark.parametrize("bits", [0, 33, 256, True, 1.0])
def test_diagnostic_cannot_raise_leaf_capacity(tiny_config, bits):
    with pytest.raises(ValueError, match="32-bit cap"):
        audit.run_chain(tiny_config, b"bad-capacity", leaf_bits=bits)


def test_sampling_abort_is_reported_once_with_no_profile_retry(tiny_config, monkeypatch):
    calls = []
    def abort(self, *, rng=None):
        calls.append(1)
        raise SamplingAbort("injected single parent abort")
    monkeypatch.setattr(audit.CHKPRandBasis, "sample", abort)
    result = audit.run_chain(tiny_config, b"parent-abort", leaf_bits=1)
    assert calls == [1] and result["attempts"] == 1
    assert result["outcome"] == "explicit_abort"
    assert result["stopped_at"] == "parent_RandBasis"
    assert "fixed_leaf_cache" not in result["stages"]
    assert result["reason"] == "injected single parent abort"
