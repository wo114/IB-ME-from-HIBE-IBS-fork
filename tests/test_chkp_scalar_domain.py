"""Fixed wider execution domain; public fixtures, no security-bit inference."""
import pytest

pytest.importorskip("sage.all")
from sage.all import QQ

from ibme.core.randomness import DeterministicRandom
from ibme.lattice.chkp.basis import KernelBasis, ModMatrixReference
from ibme.lattice.chkp import finite_gaussian, finite_gpv
from ibme.lattice.chkp.finite_gaussian import FirstFiniteGaussian, FirstFiniteOptions


class RecordingSource:
    def __init__(self):
        self.source = DeterministicRandom(b"PUBLIC-CHKP-SCALAR-DOMAIN")
        self.reads = []

    def read(self, count):
        self.reads.append(count)
        return self.source.read(count)


@pytest.mark.parametrize("width", [2**80+1, 2**84, 2**88])
def test_new_public_widths_retain_all_original_finite_certificates(width):
    sampler = FirstFiniteGaussian(width, width)
    assert finite_gaussian.MAX_SQUARED_WIDTH == finite_gpv.MAX_SQUARED_WIDTH == 2**88
    assert sampler.radius <= sampler.options.max_radius == 2**48
    assert sampler.tail_upper <= QQ(1)/2**128
    assert sampler.tv_upper < QQ(1)/2**120
    assert sampler.quantization_error < 1
    assert sampler.gaussian_trials <= sampler.options.max_gaussian_trials
    assert sampler.random_tape_bytes <= sampler.options.max_tape_bytes
    assert sampler.certificate()["security_claim"] == "none"
    left, right = RecordingSource(), RecordingSource()
    assert [sampler.sample(width, -QQ(17)/7, rng=left) for _ in range(4)] == [
        sampler.sample(width, -QQ(17)/7, rng=right) for _ in range(4)]
    assert left.reads == right.reads


@pytest.mark.parametrize("width", [9, 2**60, 2**80])
def test_old_accepted_domain_is_identical_with_old_ceiling(monkeypatch, width):
    # The former fixed ceiling is the only altered branch. Keep every
    # constructor certificate and every sampled byte request identical.
    with monkeypatch.context() as old_domain:
        old_domain.setattr(finite_gaussian, "MAX_SQUARED_WIDTH", 2**80)
        old = FirstFiniteGaussian(width, width)
    new = FirstFiniteGaussian(width, width)
    assert old.certificate() == new.certificate()
    left, right = RecordingSource(), RecordingSource()
    for center in (QQ(0), -QQ(17)/7, QQ(2**2048)+QQ(1)/(2**4096+1)):
        assert old.sample(width, center, rng=left) == new.sample(width, center, rng=right)
    assert left.reads == right.reads


@pytest.mark.parametrize("epsilon", [QQ(1), QQ(1)/(2**512+1)])
def test_above_fixed_ceiling_rejects_before_scalar_profile_build(monkeypatch, epsilon):
    def no_profile(*args, **kwargs):
        pytest.fail("out-of-domain input reached interval profile construction")
    monkeypatch.setattr(finite_gaussian, "RealIntervalField", no_profile)
    with pytest.raises(ValueError, match=r"max <= 2\^88"):
        FirstFiniteGaussian(2**88+epsilon, 2**88+epsilon)


@pytest.mark.parametrize("options, message", [
    (dict(max_radius=32), "radius cannot certify"),
    (dict(max_gaussian_trials=1), "rejection budget insufficient"),
    (dict(max_tape_bytes=1), "tape exceeds resource"),
])
def test_new_domain_does_not_bypass_resource_certificates(options, message):
    with pytest.raises(ValueError, match=message):
        FirstFiniteGaussian(2**88, 2**88, options=FirstFiniteOptions(**options))


def test_insufficient_precision_and_oversized_rationals_still_reject():
    with pytest.raises(ValueError, match="precision_bits outside resource range"):
        FirstFiniteOptions(precision_bits=95)
    with pytest.raises(ValueError, match="rational bit budget"):
        FirstFiniteGaussian(QQ(2**88)-QQ(1)/(2**256+1), 2**88,
                            options=FirstFiniteOptions(rational_bits=128))


def test_gpv_uses_the_same_fixed_ceiling_and_keeps_equation():
    basis = KernelBasis(ModMatrixReference(((1, 0),), 17), ((17, 0), (0, 1)))
    sampler = finite_gpv.FirstFiniteGPV(basis, 2**88, epsilon_bits=128)
    source = RecordingSource()
    result = sampler.sample((3,), rng=source)
    assert result[0] % 17 == 3 and len(result) == 2
    assert source.reads
    with pytest.raises(ValueError, match=r"profile 1\.\.2\^88"):
        finite_gpv.FirstFiniteGPV(basis, QQ(2**88)+QQ(1)/3, epsilon_bits=128)


def test_public_resource_ledger_still_uses_original_radius_ceiling():
    from experiments.research.chkp_parameter_profile import selected_profile, check_profile
    profile = selected_profile()
    checked = check_profile(profile)
    options = profile["finite_options"]
    assert options["max_radius"] == 2**48
    support = 2*options["max_radius"]+2
    candidate_bytes = ((support-1).bit_length()+7)//8
    bound = options["max_gaussian_trials"] * (
        options["max_uniform_trials"]*candidate_bytes+(options["mass_bits"]+7)//8)
    assert checked["worst_entropy_bytes"]["scalar"] == bound
    assert checked["static_numeric_gates_pass"]
    assert checked["security_claim"] == "none" and not checked["parameters_are_formal"]
