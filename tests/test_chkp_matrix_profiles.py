"""Fixed public byte/entropy controls from the unmodified PR14 implementation.

The fixtures use tiny public algebra and declared deterministic test entropy.
They are not HIBE keys, formal parameters or a new honest lifecycle receipt.
ExtendedGPV checks run only when the actual peer implementation is available.
"""

import json
from pathlib import Path

import pytest

pytest.importorskip("sage.all", reason="prescribed WSL Sage required")
from sage.all import QQ
from ibme.core.randomness import DeterministicRandom
from ibme.lattice.matrix_sampling.chkp_profiles import (
    CHKPFiniteOptions, CHKPFiniteGaussian, CHKPFiniteGPV, CHKPFiniteRandBasis,
    chkp_canonical_basis, chkp_to_basis,
)
from ibme.lattice.matrix_sampling.scalar import FirstFiniteOptions, MatrixFiniteOptions
from ibme.lattice.research import FirstFiniteGaussian
from experiments.research.chkp_basis import KernelBasis, ModMatrixReference
from experiments.research.gaussian_reference import SamplingAbort

FIXTURES = json.loads((Path(__file__).parent / "fixtures" / "chkp_shared_profile_controls.json").read_bytes())


class Counted:
    def __init__(self, seed):
        self.rng = DeterministicRandom(seed.encode("ascii"))
        self.bytes_used = 0

    def read(self, size):
        result = self.rng.read(size)
        self.bytes_used += len(result)
        return result


def basis():
    return KernelBasis(ModMatrixReference(((1, 2),), 17), ((17, -2), (0, 1)))


def compare(entry, operation):
    rng = Counted(entry["seed"])
    try:
        value = operation(rng)
    except SamplingAbort:
        assert entry["status"] == "SamplingAbort"
    else:
        assert entry["status"] == "passed"
        assert json.loads(json.dumps(value)) == entry["result"]
    assert rng.bytes_used == entry["entropy_bytes"]


@pytest.mark.parametrize("entry", FIXTURES["scalar"])
def test_scalar_matches_pinned_peer_samples_and_entropy(entry):
    width = entry["width_squared"]
    sampler = CHKPFiniteGaussian(width, width)
    assert sampler.radius == entry["radius"]
    compare(entry, lambda rng: [sampler.sample(width, entry["center"], rng=rng) for _ in range(16)])


@pytest.mark.parametrize("entry", FIXTURES["gpv"])
def test_gpv_matches_pinned_peer_samples_and_entropy(entry):
    sampler = CHKPFiniteGPV(basis(), 2**22, epsilon_bits=32, max_dimension=512)
    assert str(sampler._max_gs_squared) == FIXTURES["parent_max_gs_squared"]
    compare(entry, lambda rng: [sampler.sample((entry["target"],), rng=rng) for _ in range(8)])


def randomize(sampler, rng):
    result = CHKPFiniteRandBasis(sampler, max_vectors=8, max_dimension=512).sample(rng=rng)
    return dict(rows=result.basis.basis_rows, draws_used=result.draws_used,
                independent_vectors=result.independent_vectors)


@pytest.mark.parametrize("entry", FIXTURES["randbasis"])
def test_randbasis_matches_pinned_peer_full_basis_and_entropy(entry):
    sampler = CHKPFiniteGPV(basis(), 2**22, epsilon_bits=32, max_dimension=512)
    compare(entry, lambda rng: randomize(sampler, rng))


def extended():
    module = pytest.importorskip("ibme.lattice.chkp.extended_gpv",
        reason="actual PR14 ExtendedGPV consumer has not been integrated")
    # It must use the shared engine after migration. A synthetic stand-in or
    # the old parallel implementation cannot qualify this integration test.
    sample = module.ExtendedGPV(basis(), ModMatrixReference(((3,),), 17),
                               2**22, epsilon_bits=32)
    assert isinstance(sample.parent, CHKPFiniteGPV)
    return sample


@pytest.mark.parametrize("entry", FIXTURES["extended"])
def test_actual_extended_consumer_matches_pinned_peer(entry):
    sample = extended()
    compare(entry, lambda rng: [sample.sample((entry["target"],), rng=rng) for _ in range(8)])


@pytest.mark.parametrize("entry", FIXTURES["extended_randbasis"])
def test_actual_extended_randbasis_matches_pinned_peer(entry):
    compare(entry, lambda rng: randomize(extended(), rng))


def test_canonical_and_completed_basis_match_pinned_peer():
    assert json.loads(json.dumps(chkp_canonical_basis(basis(), max_dimension=512).basis_rows)) == FIXTURES["canonical_rows"]
    assert json.loads(json.dumps(chkp_to_basis(((34, 41), (0, 5)), basis(), max_dimension=512).basis_rows)) == FIXTURES["completed_rows"]


def test_chkp_does_not_silently_expand_original_first_suite_domain():
    CHKPFiniteGaussian(2**88, 2**88)
    with pytest.raises(ValueError):
        CHKPFiniteGaussian(2**88 + 1, 2**88 + 1)
    with pytest.raises(ValueError):
        FirstFiniteGaussian(2**88, 2**88)
    legacy = FirstFiniteOptions()
    converted = CHKPFiniteGaussian(9, 9, options=legacy)
    assert isinstance(converted.options, CHKPFiniteOptions)
    assert converted.options.__dict__ == legacy.__dict__
    assert type(legacy) is FirstFiniteOptions
    with pytest.raises(ValueError):
        CHKPFiniteGaussian(9, 9, options=MatrixFiniteOptions())
    with pytest.raises(ValueError):
        CHKPFiniteGPV(basis(), 2**22, max_dimension=513)
    with pytest.raises(ValueError):
        CHKPFiniteOptions(max_radius=2**49)


def test_exact_parent_geometry_is_available_to_extension_gate():
    sample = CHKPFiniteGPV(basis(), 2**22, epsilon_bits=32)
    assert sample._max_gs_squared == QQ(289)
    assert sample.width_squared >= 4*sample._max_gs_squared*sample._smoothing_factor
