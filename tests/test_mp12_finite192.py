"""Actual v2 root/DelTrap/fixed256/noise, strict recovery and its public ledger."""

from dataclasses import replace
from fractions import Fraction

import pytest

pytest.importorskip("sage.all", reason="use prescribed WSL ~/miniconda3/envs/sage")

from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.core.randomness import DeterministicRandom, SecureRandom
from ibme.hibe.mp12_structured import StructuredMP12HIBE, StructuredHIBEParams, StructuredHIBEParams192
from ibme.hibe.mp12_structured.backend import _noise
from ibme.hibe.mp12_structured.objects import (
    StructuredMasterSecret, StructuredLevel1Key, StructuredLevel2Key,
)
from ibme.lattice.chkp.leaf_state import SeedAddressBlocked
from ibme.lattice.matrix_sampling import mp12_structured as tool, mp12_extension
from experiments.research.structured_service_budget import service_budget, _reported_probability


class NoEntropy:
    def __init__(self): self.calls = 0
    def read(self, count):
        self.calls += 1
        raise AssertionError("restoration or fixed reuse requested new entropy")


@pytest.fixture(scope="module")
def budget(): return service_budget(StructuredHIBEParams192())


def test_actual_recipe_meets_probability_target_in_the_declared_model(budget):
    assert budget["meets_target_in_stated_model"] is True
    bound = Fraction(budget["ideal_RO_model_joint_upper"])
    assert Fraction(1, 2**132) < bound <= Fraction(1, 2**131)
    assert budget["modeled_probability_dyadic_exponent"] == 131
    assert budget["parent"]["dimension"] == 88 and budget["leaf"]["dimension"] == 252
    assert budget["counts"]["parent_SampleD_calls"] == 160
    assert budget["counts"]["leaf_SampleD_calls"] == 1024
    assert budget["counts"]["ciphertext_noise_draws"] == 508*2**20
    assert Fraction(budget["terms"]["ideal_honest_decode_failure_if_norm_good"]) == Fraction(1, 2**132)
    assert budget["actual_all_key_precision_or_workspace_verified"] is False
    assert budget["full_implementation_or_security_failure_upper"] is None
    assert budget["backend_admitted"] is False


def test_probability_reporting_rounds_outward_without_turning_tiny_terms_into_zero():
    p = StructuredHIBEParams192()
    for value in (Fraction(1, 3), Fraction(1, 2**20000), Fraction(1, 2**132), Fraction(0), Fraction(1)):
        reported = _reported_probability(value, p)
        assert value <= reported < value+Fraction(1, 2**384)
        assert (reported == 0) == (value == 0)
        assert len(str(reported)) < 400


def test_more_messages_can_fail_the_target_even_for_a_192_bit_sampler():
    report = service_budget(StructuredHIBEParams192(), encapsulations=2**32)
    assert report["meets_target_in_stated_model"] is False
    assert Fraction(report["terms"]["ideal_honest_decode_failure_if_norm_good"]) == Fraction(1, 2**120)


def test_modulus_choice_must_account_for_the_actual_128_trial_oracle_limit():
    p = replace(StructuredHIBEParams192(), q=549755813911)
    report = service_budget(p)
    assert report["parameters"]["finite_recipe"]["oracle_uniform_trials"] == 128
    assert report["meets_target_in_stated_model"] is False
    assert Fraction(report["ideal_RO_bounded_residue_abort_upper"]) > Fraction(1, 2**128)


def test_private_probe_destination_cannot_point_to_publishable_documentation(tmp_path):
    from pathlib import Path
    from experiments.research.structured_finite192_probe import check_private_destination
    root = Path(__file__).resolve().parents[1]
    intended = root/"test-results"/"finite192-destination-TEST-ONLY"
    assert check_private_destination(intended) == intended.resolve()
    for forbidden in (tmp_path, root/"docs"/"finite192-private", root/"test-results"):
        with pytest.raises(ValueError): check_private_destination(forbidden)


def test_public_v2_ledger_never_constructs_a_trapdoor_or_draws_entropy(monkeypatch):
    def forbidden(*args, **kwargs): raise AssertionError("public v2 ledger did private work")
    monkeypatch.setattr(SecureRandom, "read", forbidden)
    monkeypatch.setattr(tool.StructuredTrapdoor, "__post_init__", forbidden)
    monkeypatch.setattr(tool.StructuredPreimageSampler, "__init__", forbidden)
    assert service_budget(StructuredHIBEParams192())["root_or_key_generations"] == 0


@pytest.fixture(scope="module")
def witness():
    observations = []
    root_function, sampler_type = tool.generate_structured_root, mp12_extension.StructuredPreimageSampler
    def generate(*args, **kwargs):
        opts = kwargs["options"]
        observations.append(("root", opts.tail_bits, opts.mass_bits, opts.max_uniform_trials))
        return root_function(*args, **kwargs)
    def prepare(*args, **kwargs):
        opts = kwargs["options"]
        observations.append(("SampleD", kwargs["epsilon_bits"], opts.mass_bits, opts.max_uniform_trials))
        return sampler_type(*args, **kwargs)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(tool, "generate_structured_root", generate)
        patch.setattr(mp12_extension, "StructuredPreimageSampler", prepare)
        backend, p = StructuredMP12HIBE(), StructuredHIBEParams192()
        rng = DeterministicRandom(b"A-finite192-real-lifecycle-TEST-ONLY")
        public, master = backend.setup(p, rng=rng)
        parent = backend.extract(master, b"B"*86, rng=rng)
        leaf = backend.derive(parent, b"A"*86, rng=rng)
        ciphertext = backend.encrypt(public, parent.identity, leaf.child_identity, bytes(range(32)), rng=rng)
    return backend, public, master, parent, leaf, ciphertext, observations


def test_live_root_parent_and_leaf_actually_use_the_versioned_recipe(witness):
    backend, public, master, parent, leaf, ciphertext, observations = witness
    assert observations == [("root",192,320,256),("SampleD",192,320,256),("SampleD",192,320,256)]
    assert parent.trapdoor.frobenius_squared_bound == public.params.parent_bound
    assert len(leaf.key.preimages) == 256 and len(leaf.key.preimages[0]) == 252
    assert backend.decrypt(leaf, ciphertext) == bytes(range(32))
    assert _noise(public.params).params.mass_bits == 320


def test_all_v2_objects_roundtrip_with_profile_and_zero_entropy_reuse(witness, monkeypatch):
    backend, public, master, parent, leaf, ciphertext, _ = witness
    source = NoEntropy()
    monkeypatch.setattr(SecureRandom, "read", source.read)
    restored = [type(value).from_bytes(value.to_bytes()) for value in (public,master,parent,leaf,ciphertext)]
    assert [value.to_bytes() for value in restored] == [value.to_bytes() for value in (public,master,parent,leaf,ciphertext)]
    assert all(type(value.params) is StructuredHIBEParams192 for value in restored[:4])
    cached_parent = backend.extract(restored[1], b"B"*86, rng=source)
    cached_leaf = backend.derive(restored[2], b"A"*86, rng=source)
    assert cached_parent.to_bytes() == parent.to_bytes()
    assert cached_leaf.to_bytes() == leaf.to_bytes()
    assert backend.decrypt(cached_leaf, restored[4]) == bytes(range(32))
    assert source.calls == 0


def test_default_system_entropy_encrypts_the_v2_seed(witness):
    backend, public, _, parent, leaf, _, _ = witness
    ciphertext = backend.encrypt(public, parent.identity, leaf.child_identity, b"\x93"*32)
    assert backend.decrypt(leaf, ciphertext) == b"\x93"*32


def test_selected_v1_decoder_rejects_v2_even_with_identical_numeric_parameters(witness):
    from ibme.hibe.mp12_structured.registration import backend_spec, finite192_backend_spec
    public = witness[1]
    finite192_backend_spec().check_object(public, public.params)
    with pytest.raises(SerializationError):
        backend_spec().check_object(public, StructuredHIBEParams(q=public.params.q))


def test_failed_v2_parent_stays_reserved_across_restore(witness, monkeypatch):
    backend, _, master, _, _, _, _ = witness
    master = StructuredMasterSecret.from_bytes(master.to_bytes())
    def failed(*args, **kwargs): raise RuntimeError("injected finite192 parent abort")
    monkeypatch.setattr(mp12_extension, "delegate_extension", failed)
    with pytest.raises(RuntimeError): backend.extract(master, b"C"*86, rng=NoEntropy())
    restored = StructuredMasterSecret.from_bytes(master.to_bytes())
    with pytest.raises(InvalidParameterError, match="no reissue"):
        backend.extract(restored, b"C"*86, rng=NoEntropy())


def test_failed_v2_leaf_stays_reserved_across_restore(witness, monkeypatch):
    backend, _, _, parent, _, _, _ = witness
    parent = StructuredLevel1Key.from_bytes(parent.to_bytes())
    def failed(*args, **kwargs): raise RuntimeError("injected finite192 leaf abort")
    monkeypatch.setattr(mp12_extension, "StructuredLeftSampler", failed)
    with pytest.raises(RuntimeError): backend.derive(parent, b"E"*86, rng=NoEntropy())
    restored = StructuredLevel1Key.from_bytes(parent.to_bytes())
    with pytest.raises(SeedAddressBlocked): backend.derive(restored, b"E"*86, rng=NoEntropy())
