"""Wide finite DGS/GPV, exact law checks and actual system-RNG controls."""

from fractions import Fraction
import math

import pytest
pytest.importorskip("sage.all", reason="Use prescribed WSL Sage; skip is not pass")
from sage.all import QQ

from ibme.core.errors import RandomnessError
from ibme.core.randomness import SecureRandom, DeterministicRandom
from experiments.research.gaussian_reference import SamplingAbort
from experiments.research.online_gaussian_reference import OnlineOptions, OnlineScalarGaussian
from experiments.research.chkp_basis import ModMatrixReference, complete_kernel_basis
from experiments.research.chkp_gpv import CHKPGPVSampler
from experiments.research.first_suite.finite_gaussian import FirstFiniteOptions, FirstFiniteGaussian
from experiments.research.first_suite.finite_gpv import FirstFiniteGPV
from experiments.research.first_suite.entropy import CheckedEntropy


@pytest.mark.parametrize("center", ["0", "1/3", "-17/7", "10000000000000000000000000000000000000000000000/3"])
def test_exact_overlapping_scalar_law_and_seeded_replay(center):
    args = dict(tail_bits=64, mass_bits=128, precision_bits=192, gaussian_abort_bits=64, max_uniform_trials=128)
    old = OnlineScalarGaussian(9, 9, options=OnlineOptions(**args))
    new = FirstFiniteGaussian(9, 9, options=FirstFiniteOptions(**args))
    assert old.finite_distribution(9, center) == new.finite_distribution(9, center)
    a, b = DeterministicRandom(b"same-finite-scalar"), DeterministicRandom(b"same-finite-scalar")
    assert [old.sample(9, center, rng=a) for _ in range(128)] == [new.sample(9, center, rng=b) for _ in range(128)]
    assert new.tv_upper >= new.tail_upper + new.quantization_error + new.abort_upper


@pytest.mark.parametrize("width", [2**42, 2**60, 2**80])
def test_wide_width_class_is_certified_and_old_cap_remains(width):
    with pytest.raises(ValueError): OnlineScalarGaussian(width, width)
    sampler = FirstFiniteGaussian(width, width)
    cert = sampler.certificate()
    assert cert["profile"] == "FIRST-SUITE-FINITE-DGS/1"
    assert cert["native_Sage_rng_used"] is False and cert["production_random_api"] is True
    assert sampler.tail_upper <= QQ(1)/2**128
    assert sampler.tv_upper < QQ(1)/2**120
    assert sampler.random_tape_bytes <= sampler.options.max_tape_bytes
    rng = DeterministicRandom(b"wide-class" + str(width).encode())
    values = [sampler.sample(width, "1/3", rng=rng) for _ in range(512)]
    assert all(type(x) is int for x in values)
    mean = sum(values)/len(values)
    variance = width/(2*math.pi)
    empirical = sum((x-mean)**2 for x in values)/len(values)
    assert abs(mean-1/3) < 6*math.sqrt(variance/len(values))
    assert 0.75 < empirical/variance < 1.25


def test_scalar_default_entropy_is_real_system_rng_without_native_seed(monkeypatch):
    from experiments.research.first_suite import finite_gaussian as module
    calls = []
    class RecordedOS:
        def __init__(self): self.source = SecureRandom()
        def read(self, count): calls.append(count); return self.source.read(count)
    monkeypatch.setattr(module, "SecureRandom", RecordedOS)
    sampler = FirstFiniteGaussian(9, 9)
    assert type(sampler.sample(9, Fraction(1, 3))) is int
    assert calls and sum(calls) <= sampler.random_tape_bytes


@pytest.mark.parametrize("bad", [b"", b"too-long", bytearray(b"\0"), 0])
def test_bad_entropy_type_and_length_rejected(bad):
    class Bad:
        def read(self, count): return bad
    with pytest.raises(RandomnessError): FirstFiniteGaussian(9, 9).sample(9, rng=Bad())


def test_resource_abort_and_entropy_exception_are_not_retried():
    class Fail:
        def __init__(self): self.calls=0
        def read(self, count): self.calls += 1; raise RuntimeError("entropy unavailable")
    source = Fail()
    with pytest.raises(RuntimeError, match="unavailable"):
        FirstFiniteGaussian(9, 9).sample(9, rng=source)
    assert source.calls == 1
    checked = CheckedEntropy(SecureRandom(), 1)
    with pytest.raises(SamplingAbort, match="budget"):
        checked.read(2)
    assert checked.bytes_used == 0
    class NoRead:
        def read(self, count): pytest.fail("invalid width/center consumed entropy")
    with pytest.raises(ValueError): FirstFiniteGaussian(9, 9).sample(10, rng=NoRead())
    with pytest.raises(ValueError): FirstFiniteGaussian(9, 9).sample(9, center=True, rng=NoRead())
    with pytest.raises(ValueError): FirstFiniteGaussian(2**81, 2**81)
    with pytest.raises(ValueError): FirstFiniteGaussian(2**80, 2**80, options=FirstFiniteOptions(max_radius=32))


def test_exact_gpv_overlap_equations_and_rng_api(monkeypatch):
    from experiments.research.first_suite import finite_gpv as module
    basis = complete_kernel_basis(ModMatrixReference([[1, 2]], 17))
    opts = dict(tail_bits=64, mass_bits=128, precision_bits=192, gaussian_abort_bits=64, max_uniform_trials=128)
    old = CHKPGPVSampler(basis, 2**18, epsilon_bits=32, options=OnlineOptions(**opts))
    new = FirstFiniteGPV(basis, 2**18, epsilon_bits=32, options=FirstFiniteOptions(**opts))
    a, b = DeterministicRandom(b"same-gpv"), DeterministicRandom(b"same-gpv")
    assert [old.sample((i % 17,), rng=a) for i in range(64)] == [new.sample((i % 17,), rng=b) for i in range(64)]
    calls = []
    class RecordedOS:
        def __init__(self): self.source=SecureRandom()
        def read(self, count): calls.append(count); return self.source.read(count)
    monkeypatch.setattr(module, "SecureRandom", RecordedOS)
    x = new.sample((3,))
    assert (x[0]+2*x[1])%17 == 3 and calls
    cert = new.certificate()
    assert cert["production_random_api"] and not cert["native_Sage_rng_used"]
    assert QQ(cert["tv_upper_including_abort"]) < QQ(1)/2**24


def test_independent_gpv_dimension_width_and_batch_resource_domain():
    basis = complete_kernel_basis(ModMatrixReference([[1]+[0]*192], 17))
    with pytest.raises(ValueError): CHKPGPVSampler(basis, 2**18)
    new = FirstFiniteGPV(basis, 2**18)
    x = new.sample((3,), rng=DeterministicRandom(b"finite-193-dim"))
    assert len(x) == 193 and x[0]%17 == 3
    with pytest.raises(ValueError): FirstFiniteGPV(basis, 1)
    with pytest.raises(ValueError): FirstFiniteGPV(basis, 2**18, options=FirstFiniteOptions(max_tape_bytes=1))


def test_finite_randbasis_uses_exact_complete_lattice_and_no_native_rng(monkeypatch):
    from experiments.research.first_suite.finite_randbasis import FirstFiniteRandBasis
    basis = complete_kernel_basis(ModMatrixReference([[1,2]],17))
    sampler = FirstFiniteGPV(basis,2**18,epsilon_bits=128)
    randomizer = FirstFiniteRandBasis(sampler,max_vectors=130)
    result = randomizer.sample(rng=DeterministicRandom(b"finite-randbasis-actual"))
    assert result.basis.public == basis.public and result.independent_vectors == 2
    assert 2 <= result.draws_used <= 130
    cert = randomizer.certificate()
    assert cert["production_random_api"] and not cert["native_Sage_rng_used"]
    assert QQ(cert["actual_vs_bounded_ideal_output_tv_upper"]) < QQ(1)/2**110
    calls=[]
    def norm_failure(target,*,rng=None):
        calls.append(1)
        return (17*10**12,0)
    monkeypatch.setattr(sampler,"sample",norm_failure)
    with pytest.raises(SamplingAbort,match="norm"):
        randomizer.sample(rng=DeterministicRandom(b"forced-norm"))
    assert len(calls)==1
