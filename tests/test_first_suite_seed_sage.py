"""Actual Gaussian/identity/seed lifecycle checks in the mandated Sage env."""

from fractions import Fraction
from pathlib import Path

import pytest
pytest.importorskip("sage.all", reason="Use prescribed WSL Sage; skip is not pass")

from ibme.core.errors import EncodingError, InvalidParameterError, RandomnessError
from ibme.core.randomness import DeterministicRandom
from experiments.research.first_suite.identity import ROHIBEContext
from experiments.research.first_suite.leaf_state import FixedSeedState, SeedScope
from experiments.research.first_suite.seed_kem import encapsulate_seed, uniform_residue
from experiments.research.ibme_noise_budget import RoundedNoiseParams
from experiments.research.ibme_rounded_noise import build_rounded_noise


def test_actual_public_code_hg_private_restore_and_negative_noise_control(tmp_path):
    binary = Path(__file__).resolve().parents[1] / "test-results/qfall-target/release/ibme-qfall-public-fixture"
    if not binary.exists():
        pytest.skip("explicit qFALL build required; missing build is not pass")
    from experiments.research.first_suite.lifecycle_probe import one_probe
    report = one_probe(17, 8, binary, tmp_path)
    assert report["real_H_G_used"]
    assert report["fixed_positions"] == report["native_private_vectors"] == 256
    assert report["private_generations"] == 1
    assert report["fresh_process"]["new_private_draws"] == 0
    assert report["fresh_process"]["private_snapshot_byte_equal"]
    assert not report["fresh_process"]["native_sampler_loaded"]
    assert report["failure_tombstone_recovered"]
    assert report["total_bit_errors"] > 0
    assert report["malformed_capsules_rejected"] == 3
    assert all(r["counted_noise_scalar_calls"] == r["expected_noise_scalar_calls"] == 295 for r in report["capsules"])
    assert not report["conditional_noise"]["conditional_noise_sufficient"]
    assert not report["full_hibe_backend_implemented"] and not report["backend_admitted"]


def test_actual_finite_gpv_can_populate_a_256_position_identity_store():
    # A publicly recoverable complete basis is a toy sampler/statistics control,
    # not a root trapdoor. This exercises the real finite GPV byte API; the
    # larger public fixture profile is separately checked by the probe above.
    from experiments.research.chkp_basis import ModMatrixReference, complete_kernel_basis
    from experiments.research.chkp_gpv import CHKPGPVSampler
    o = ROHIBEContext(1, 1, 5, ((1,),), b"TEST-ONLY/finite-GPV-control", identity_bytes=64)
    s = SeedScope(o, b"Bob", Fraction(4096), b"CHKP-GPV-ONLINE/1; explicit finite toy control")
    state = FixedSeedState(s)
    def generate(plan):
        sampler = CHKPGPVSampler(complete_kernel_basis(ModMatrixReference(plan.public_rows, o.q)),
                                4096, epsilon_bits=16)
        rng = DeterministicRandom(b"first-suite-finite-real-gpv")
        return tuple(sampler.sample(target, rng=rng) for target in plan.targets)
    first = state.resolve(b"Alice", generate)
    restored = FixedSeedState.from_bytes(state.to_bytes(), expected_scope=s)
    assert len(first.preimages) == 256
    assert restored.resolve(b"Alice", lambda _: pytest.fail("resample after restore")).preimages == first.preimages


@pytest.mark.parametrize("bad", ["length", "identity", "noise", "source"])
def test_kem_invalid_inputs_rejected_without_entropy(bad):
    o = ROHIBEContext(1, 1, 17, ((1,),), b"TEST-ONLY/rounded-noise", identity_bytes=64)
    noise = build_rounded_noise(RoundedNoiseParams(19 if bad == "noise" else 17, Fraction(1, 64)))
    class NoEntropy:
        def read(self, count): pytest.fail("bad KEM input consumed entropy")
    with pytest.raises((EncodingError, InvalidParameterError, RandomnessError, ValueError)):
        encapsulate_seed(o, b"" if bad == "identity" else b"Bob", b"Alice",
                         b"x" * (31 if bad == "length" else 32), noise,
                         rng=object() if bad == "source" else NoEntropy())


def test_malformed_and_exhausted_uniform_byte_sources_never_fall_back():
    class Bad:
        def __init__(self, result): self.result, self.calls = result, 0
        def read(self, count): self.calls += 1; return self.result
    for value in (b"", bytearray(b"\0"), b"too long"):
        with pytest.raises(RandomnessError): uniform_residue(Bad(value), 17)
    source = Bad(b"\xff")
    with pytest.raises(RandomnessError, match="exhausted"):
        uniform_residue(source, 17)
    assert source.calls == 128
