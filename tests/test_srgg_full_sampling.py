"""SRGG SampleF operations and polynomial-block Schur sampling, research only."""
from importlib import import_module, util
import json
from fractions import Fraction

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage is required")
from sage.all import QQ, RealField, matrix, vector

from ibme.core.errors import RandomnessError
from ibme.core.randomness import DeterministicRandom
from experiments.research.gaussian_reference import SamplingAbort


def api():
    name = "experiments.research.candidates.srgg.full_sampling"
    assert util.find_spec(name) is not None, "literal SampleF/Schur-block sampler is missing"
    return import_module(name)


class NoRead:
    calls = 0
    def read(self, size):
        self.calls += 1
        raise AssertionError("invalid input consumed entropy")


def test_sample_f_replays_real_continuous_then_integer_rounding():
    fs = api()
    covariance = ((64, -12), (-12, 32))
    center = (QQ(1)/3, -QQ(2)/5)
    left = fs.sample_f(covariance, center, 4, rng=DeterministicRandom(b"srgg-literal-F"))
    right = fs.sample_f(matrix(QQ, covariance), vector(QQ, center), 4,
                        rng=DeterministicRandom(b"srgg-literal-F"))
    assert left == right and len(left) == 2
    assert all(type(x) is int for x in left)


def test_sample_f_full_covariance_has_the_declared_physical_variance():
    fs = api()
    plan = fs.prepare_f(((64, 24), (24, 64)), (QQ(1)/3, -QQ(2)/5), 4)
    source = DeterministicRandom(b"srgg-literal-F-moments")
    values = [plan.sample(rng=source) for _ in range(1024)]
    field = RealField(160)
    means = [sum(field(x[i]) for x in values)/len(values) for i in range(2)]
    variances = [sum((field(x[i])-means[i])**2 for x in values)/len(values) for i in range(2)]
    cross = sum((field(x[0])-means[0])*(field(x[1])-means[1]) for x in values)/len(values)
    target_variance = field(64)/(2*field.pi())
    assert abs(means[0]-field(1)/3) < 0.6 and abs(means[1]+field(2)/5) < 0.6
    assert all(field(0.75) < v/target_variance < field(1.25) for v in variances)
    assert abs(cross-field(24)/(2*field.pi())) < field(1.5)


def test_continuous_tickets_are_fixed_and_separate_from_rounding_draws():
    fs = api()
    class Counting:
        def __init__(self):
            self.source = DeterministicRandom(b"srgg-fixed-normal-tickets")
            self.sizes = []
        def read(self, size):
            self.sizes.append(size)
            return self.source.read(size)
    source = Counting()
    plan = fs.prepare_f(((64, 0), (0, 64)), (0, 0), 4)
    plan.sample(rng=source)
    assert source.sizes[:2] == [16, 16]
    assert len(source.sizes) > 2
    cert = plan.public_certificate()
    assert sum(source.sizes) <= cert["public_entropy_upper_bytes"]
    assert cert["continuous_ticket_count"] == 2


def test_polynomial_block_schur_sampling_retains_cross_block_correlation():
    fs = api()
    covariance = ((64, 0, 24, 0), (0, 64, 0, 24),
                  (24, 0, 64, 0), (0, 24, 0, 64))
    plan = fs.prepare_p(covariance, (0, 0, 0, 0), 2, 4)
    source = DeterministicRandom(b"srgg-polynomial-Schur")
    samples = [plan.sample(rng=source) for _ in range(1024)]
    field = RealField(160)
    mean0 = sum(field(x[0]) for x in samples)/len(samples)
    mean2 = sum(field(x[2]) for x in samples)/len(samples)
    cross = sum((field(x[0])-mean0)*(field(x[2])-mean2) for x in samples)/len(samples)
    assert abs(cross-field(24)/(2*field.pi())) < field(1.5)
    assert all(len(x) == 4 and all(type(v) is int for v in x) for x in samples)
    assert plan.public_certificate()["block_size"] == 2
    assert fs.sample_p(covariance, (0, 0, 0, 0), 2, 4,
                       rng=DeterministicRandom(b"srgg-polynomial-Schur")) == samples[0]


def test_scalar_vector_uses_fixed_r_squared_at_each_exact_rational_center():
    fs = api()
    center = (Fraction(-7, 3), QQ(5)/2)
    a = fs.sample_scalar_vector(4, center, rng=DeterministicRandom(b"srgg-u-fixed-width"))
    b = fs.sample_scalar_vector(4, center, rng=DeterministicRandom(b"srgg-u-fixed-width"))
    assert a == b and len(a) == 2 and all(type(x) is int for x in a)
    assert fs.sample_scalar_vector(4, (0,), rng=DeterministicRandom(b"srgg-u-one"))


@pytest.mark.parametrize("covariance,center", [
    (((4, 0), (0, 4)), (0, 0)),  # equality at r^2 is not strict PD
    (((8, 8), (8, 8)), (0, 0)),
    (((64, 1), (0, 64)), (0, 0)),
    (((64, 0), (0, 64)), (0,)),
    (((True, 0), (0, 64)), (0, 0)),
    (((64.0, 0), (0, 64)), (0, 0)),
])
def test_sample_f_rejects_bad_shapes_and_centers_before_entropy(covariance, center):
    fs, source = api(), NoRead()
    with pytest.raises((ValueError, TypeError)):
        fs.sample_f(covariance, center, 4, rng=source)
    assert source.calls == 0


def test_all_schur_leaves_are_preflighted_before_the_last_block_draw():
    fs, source = api(), NoRead()
    # Last leaf (8) is valid, but its preceding Schur shape is 5-16/8=3<4.
    with pytest.raises(ValueError):
        fs.sample_p(((5, 4), (4, 8)), (0, 0), 1, 4, rng=source)
    assert source.calls == 0


@pytest.mark.parametrize("block_size", [0, True, 3])
def test_block_size_must_partition_the_exact_coefficient_dimension(block_size):
    fs, source = api(), NoRead()
    with pytest.raises(ValueError):
        fs.sample_p(((64, 0), (0, 64)), (0, 0), block_size, 4, rng=source)
    assert source.calls == 0


@pytest.mark.parametrize("change", [
    {"precision_bits": 95}, {"ticket_bits": True}, {"ticket_bits": 256, "precision_bits": 192},
    {"max_dimension": 0}, {"rational_bits": 8193}, {"max_entropy_bytes": 0},
])
def test_public_options_have_exact_bounded_precision_and_resource_gates(change):
    with pytest.raises(ValueError):
        api().FullSamplingOptions(**change)


def test_dimension_center_bits_and_entropy_budget_reject_before_rng():
    fs, source = api(), NoRead()
    for options, center in ((fs.FullSamplingOptions(max_dimension=1), (0, 0)),
                            (fs.FullSamplingOptions(), (QQ(2)**9000, 0)),
                            (fs.FullSamplingOptions(), ("1e1000000", 0)),
                            (fs.FullSamplingOptions(max_entropy_bytes=1), (0, 0))):
        with pytest.raises(ValueError):
            fs.sample_f(((64, 0), (0, 64)), center, 4, rng=source, options=options)
    assert source.calls == 0


@pytest.mark.parametrize("block_size", [None, 1])
def test_mean_bit_budget_reserves_space_for_continuous_dyadic_displacements(block_size):
    fs, source = api(), NoRead()
    # The initial mean fits 8192 bits, but adding a numerical dyadic shift can
    # exceed that class. Reject it in preparation, before a normal ticket.
    center = (QQ(1)/(2**8100+1), 0)
    with pytest.raises(ValueError):
        if block_size is None:
            fs.sample_f(((64, 0), (0, 64)), center, 4, rng=source)
        else:
            fs.sample_p(((64, 0), (0, 64)), center, block_size, 4, rng=source)
    assert source.calls == 0


def test_short_reads_and_typed_memoryview_wrong_byte_count_fail_without_fallback():
    fs = api()
    class Short:
        calls = 0
        def read(self, n):
            self.calls += 1
            return b""
    class Wide:
        calls = 0
        def read(self, n):
            self.calls += 1
            return memoryview(bytearray(4*n)).cast("I")
    for source in (Short(), Wide()):
        with pytest.raises(RandomnessError):
            fs.sample_f(((64, 0), (0, 64)), (0, 0), 4, rng=source)
        assert source.calls == 1


def test_valid_typed_and_falsey_sources_are_retained_and_replay(monkeypatch):
    fs = api()
    class Typed:
        def __init__(self): self.source = DeterministicRandom(b"srgg-typed-tickets")
        def __bool__(self): return False
        def read(self, size):
            raw = self.source.read(size)
            return memoryview(raw).cast("I") if size % 4 == 0 else memoryview(raw)
    def forbidden(): raise AssertionError("injected source was replaced")
    monkeypatch.setattr(fs, "SecureRandom", forbidden)
    expected = fs.sample_f(((64, 0), (0, 64)), (0, 0), 4,
                            rng=DeterministicRandom(b"srgg-typed-tickets"))
    assert fs.sample_f(((64, 0), (0, 64)), (0, 0), 4, rng=Typed()) == expected


def test_gaussian_rounding_abort_does_not_redraw_the_continuous_stage():
    fs = api()
    class Exhausted:
        def __init__(self): self.sizes = []
        def read(self, size):
            self.sizes.append(size)
            return bytes(size) if len(self.sizes) <= 2 else b"\xff"*size
    source = Exhausted()
    with pytest.raises(SamplingAbort):
        fs.sample_f(((64, 0), (0, 64)), (0, 0), 4, rng=source,
                    options=fs.FullSamplingOptions(max_uniform_trials=1))
    assert source.sizes[:2] == [16, 16]
    assert source.sizes.count(16) == 2


def test_private_plans_and_public_certificates_disclose_no_shapes_or_centers():
    fs = api()
    for plan in (fs.prepare_f(((64, 12), (12, 64)), (QQ(1)/3, -7), 4),
                 fs.prepare_p(((64, 12), (12, 64)), (QQ(1)/3, -7), 1, 4)):
        assert "redacted" in repr(plan)
        report = plan.public_certificate()
        assert report["continuous_stage_tv_certified"] is False
        assert report["full_target_tv_upper_including_abort"] is None
        assert report["security_claim"] == "none" and report["backend_admitted"] is False
        assert report["constant_time"] is False
        assert report["finite_uniform_grid"] is True
        assert "covariance" not in json.dumps(report) and "center" not in json.dumps(report)
        report["precision_bits"] = 0
        assert plan.public_certificate()["precision_bits"] == 192
