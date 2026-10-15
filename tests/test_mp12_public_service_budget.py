"""Actual public finite profiles and complete fixed-service scope; no keys."""

from fractions import Fraction
from types import SimpleNamespace

import pytest
pytest.importorskip("sage.all", reason="use prescribed WSL ~/miniconda3/envs/sage")
from sage.all import QQ, RealIntervalField

from ibme.core.randomness import SecureRandom
from ibme.hibe.mp12_structured import StructuredHIBEParams
from ibme.lattice.matrix_sampling import mp12_structured as tool
from ibme.lattice.matrix_sampling.scalar import MatrixFiniteGaussian
from experiments.research.structured_service_budget import public_profile, service_budget


@pytest.fixture(scope="module")
def budget():
    return service_budget(StructuredHIBEParams())


def test_rational_norm_chernoff_constant_is_an_outward_upper_bound():
    f = RealIntervalField(256)
    assert (f(2).sqrt()*(-f.pi()/2).exp()).upper() < f(QQ(3)/10).lower()


def test_public_projection_matches_an_actual_nondiagonal_trapdoor_sampler():
    # Public algebra toy: the actual sampler admits its nonzero Schur path;
    # the independent projection cannot inspect R or use its observed norm.
    trapdoor = tool.StructuredTrapdoor(1, 5, ((1, 3),), ((1, -1, 2), (0, 1, -1)), 8)
    actual = tool.StructuredPreimageSampler(trapdoor)
    projected = public_profile(SimpleNamespace(n=1, q=5, w=3), trapdoor.dimension, 8)
    assert actual.public_certificate()["distribution_budget"] == projected["distribution"]
    assert actual.random_tape_bytes == projected["worst_request_tape_bytes"]


def test_public_report_never_draws_entropy_or_constructs_a_private_root(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("public budget attempted a key or a sample")
    monkeypatch.setattr(SecureRandom, "read", forbidden)
    monkeypatch.setattr(MatrixFiniteGaussian, "sample", forbidden)
    monkeypatch.setattr(tool, "generate_structured_root", forbidden)
    monkeypatch.setattr(tool.StructuredTrapdoor, "__post_init__", forbidden)
    monkeypatch.setattr(tool.StructuredPreimageSampler, "__init__", forbidden)
    result = service_budget(StructuredHIBEParams())
    assert result["counts"]["parent_SampleD_calls"] == 160
    assert result["counts"]["leaf_SampleD_calls"] == 1024
    assert result["counts"]["ciphertext_noise_draws"] == 508*2**20
    assert result["root_or_key_generations"] == result["entropy_reads"] == result["sampler_calls"] == 0


def test_report_uses_all_fixed_keys_but_counts_no_resampling_on_reuse(budget):
    assert budget["counts"]["distinct_leaf_keys"] == 4
    assert budget["counts"]["fixed_key_reuse_additional_SampleD_calls"] == 0
    assert budget["parent"]["dimension"] == 88 and budget["leaf"]["dimension"] == 252
    assert budget["parent"]["worst_request_tape_bytes"]*80 == 1462989752320
    assert budget["leaf"]["worst_request_tape_bytes"]*256 == 26907788083200
    assert Fraction(budget["terms"]["ideal_honest_decode_failure_if_norm_good"]) == Fraction(1, 2**100)
    assert budget["meets_target_in_stated_model"] is False
    assert 0 < budget["modeled_probability_dyadic_exponent"] < 128


def test_model_unknowns_stay_unknown_and_are_not_lwe_security_bits(budget):
    assert budget["full_implementation_or_security_failure_upper"] is None
    assert budget["actual_all_key_precision_or_workspace_verified"] is False
    assert budget["actual_SHAKE_indifferentiability_verified"] is False
    assert budget["parent"]["actual_trapdoor_precision_gate_checked"] is False
    assert budget["security_claim"] == "none" and budget["backend_admitted"] is False


def test_increasing_encapsulations_increases_noise_and_uniform_terms(budget):
    small = service_budget(StructuredHIBEParams(), encapsulations=1)
    for name in ("finite_ciphertext_noise_coupling", "ciphertext_secret_uniform_abort",
                 "ideal_honest_decode_failure_if_norm_good"):
        assert Fraction(budget["terms"][name]) == 2**20*Fraction(small["terms"][name])
    assert small["counts"]["leaf_SampleD_calls"] == budget["counts"]["leaf_SampleD_calls"]


def test_oracle_query_budget_cannot_omit_the_fixed_tree():
    with pytest.raises(ValueError, match="fixed key tree"):
        service_budget(StructuredHIBEParams(), h_queries=1)
