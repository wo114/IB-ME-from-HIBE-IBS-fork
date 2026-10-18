"""Exact finite-law, actual-wide-draw and resource checks for opt-in SRGG scalar."""
from dataclasses import asdict, replace

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")
from sage.all import QQ, RealIntervalField

from ibme.core.randomness import DeterministicRandom
from experiments.research.gaussian_reference import SamplingAbort, interval_bounds
from experiments.research.gaussian_reference import build_gaussian_table_squared
from experiments.research.online_gaussian_reference import OnlineOptions, OnlineScalarGaussian
from experiments.research.candidates.srgg.formal_candidates import conditional_candidate
from experiments.research.candidates.srgg.wide_scalar import (
    WideScalarGaussian, WideScalarOptions, conditional_widths,
)


class NoEntropy:
    def read(self, size):
        raise AssertionError("rejected input consumed entropy")


def legacy_options():
    opts = OnlineOptions()
    return opts, WideScalarOptions(**asdict(opts), target_tv_bits=64)


@pytest.mark.parametrize("width,center", [(1, 0), (1, QQ(1)/3), (4, QQ(1)/2),
                                          (25, QQ(-7)/3), (25, QQ(17)/2)])
def test_same_finite_law_and_all_certificate_terms_as_legacy(width, center):
    old_options, wide_options = legacy_options()
    old = OnlineScalarGaussian(width, width, options=old_options)
    new = WideScalarGaussian(width, width, options=wide_options)
    assert new.finite_distribution(width, center) == old.finite_distribution(width, center)
    for name in ("radius", "max_support_count", "weight_width", "tail_upper", "theta",
                 "quantization_error", "acceptance_mass_lower", "acceptance_probability_lower",
                 "gaussian_trials", "abort_upper", "tv_upper", "random_tape_bytes"):
        assert getattr(new, name) == getattr(old, name), name
    assert new.sample(width, center, rng=DeterministicRandom(b"same-law")) == old.sample(
        width, center, rng=DeterministicRandom(b"same-law"))


def test_legacy_largest_width_is_bit_for_bit_identical_and_legacy_limit_remains():
    old_options, wide_options = legacy_options()
    old = OnlineScalarGaussian(10**12, 10**12, options=old_options)
    new = WideScalarGaussian(10**12, 10**12, options=wide_options)
    assert old.radius == new.radius and old.tv_upper == new.tv_upper
    assert old.sample(10**12, QQ(2)/7, rng=DeterministicRandom(b"edge")) == new.sample(
        10**12, QQ(2)/7, rng=DeterministicRandom(b"edge"))
    with pytest.raises(ValueError, match=r"10\^12"):
        OnlineScalarGaussian(10**12+1, 10**12+1)
    with pytest.raises(ValueError):
        OnlineOptions(max_radius=2**31)


@pytest.mark.parametrize("low,high,width", [(1, 25, 7), (9, 15, QQ(37)/3)])
def test_nontrivial_width_classes_retain_the_same_law_and_admission(low, high, width):
    old_options, wide_options = legacy_options()
    old = OnlineScalarGaussian(low, high, options=old_options)
    new = WideScalarGaussian(low, high, options=wide_options)
    assert old.tv_upper == new.tv_upper and old.gaussian_trials == new.gaussian_trials
    assert old.finite_distribution(width, QQ(7)/3) == new.finite_distribution(width, QQ(7)/3)


@pytest.mark.parametrize("rank", [2, 3, 4])
def test_every_actual_conditional_n512_width_has_a_real_replayable_draw(rank):
    candidate = conditional_candidate(degree=512, rank=rank, digits=8)
    widths = conditional_widths(candidate)
    assert set(widths) == {"rounding_and_signing_u", "master_lower", "signature_lower"}
    assert widths["signature_lower"] > 10**12
    for label, width in widths.items():
        sampler = WideScalarGaussian(width, width)
        class Tracked:
            def __init__(self):
                self.source, self.total = DeterministicRandom(f"n512/{rank}/{label}".encode()), 0
            def read(self, size):
                self.total += size
                return self.source.read(size)
        left, right = Tracked(), Tracked()
        for center in (QQ(0), QQ(1)/2, QQ(-7)/3, QQ(1)/(2**600+1)):
            x = sampler.sample(width, center, rng=left)
            assert type(x) is int and x == sampler.sample(width, center, rng=right)
            assert abs(x) <= abs(center).ceil()+sampler.radius+1
        assert 0 < left.total <= 4*sampler.random_tape_bytes
        cert = sampler.certificate()
        assert QQ(cert["tail_upper"]) <= QQ(1)/2**128
        assert QQ(cert["tv_upper_including_abort"]) <= QQ(1)/2**96
        assert sampler.gaussian_trials <= sampler.options.max_gaussian_trials
        assert sampler.random_tape_bytes <= sampler.options.max_tape_bytes


@pytest.mark.parametrize("width,center", [(1, QQ(1)/3), (4, QQ(1)/2), (25, QQ(-7)/3)])
def test_small_target_law_against_independent_infinite_gaussian_normalizer(width, center):
    sampler = WideScalarGaussian(width, width)
    law = sampler.finite_distribution(width, center)
    reference = build_gaussian_table_squared(width, center, tail_bits=192, mass_bits=256, precision_bits=384)
    field = RealIntervalField(384)
    inside, difference = field(0), field(0)
    for x, probability in law.items():
        target = (-field.pi()*field((x-center)**2/QQ(width))).exp()/reference.normalizer
        inside += target
        difference += abs(field(probability)-target)
    assert interval_bounds((difference+1-inside)/2)[1] <= sampler.tv_upper


def test_gadget_coset_maps_to_r_squared_not_an_ordinary_wide_61504_kernel():
    candidate = conditional_candidate()
    sampler = WideScalarGaussian(candidate.r_squared, candidate.r_squared)
    b, width = candidate.base, candidate.r_squared
    for residue in range(b):
        center = -QQ(residue)/b
        k = sampler.sample(width, center, rng=DeterministicRandom(f"coset/{residue}".encode()))
        x = residue+b*k
        assert x % b == residue
        assert QQ(x*x)/(b*b*width) == (k-center)**2/width


def test_clipped_relative_weights_stay_in_the_same_quantization_budget(monkeypatch):
    from experiments.research.candidates.srgg import wide_scalar
    sampler = WideScalarGaussian(1, 100)
    def forbidden(*arguments):
        raise AssertionError("clipped exponent was evaluated")
    monkeypatch.setattr(wide_scalar, "capped_exp_minus_pi", forbidden)
    assert sampler.integer_weight(sampler.radius, QQ(1), QQ(0), 0) == 0
    assert sampler.quantization_error >= QQ(sampler.max_support_count)/2**sampler.options.mass_bits


def test_wide_pointwise_weights_are_enclosed_at_independent_higher_precision():
    width = conditional_widths(conditional_candidate())["signature_lower"]
    sampler = WideScalarGaussian(width, width)
    field = RealIntervalField(384)
    scale = QQ(2)**sampler.options.mass_bits
    for center in (QQ(0), QQ(1)/2, QQ(1)/3):
        closest = 0 if center <= QQ(1)/2 else 1
        for x in (closest, -sampler.radius, sampler.radius, sampler.radius//2, 10**10):
            argument = ((x-center)**2-(closest-center)**2)/width
            lo, hi = interval_bounds((-field.pi()*field(argument)).exp())
            approximate = QQ(sampler.integer_weight(x, width, center, closest))/scale
            assert approximate <= hi
            assert hi-approximate <= sampler.weight_width+1/scale
            assert lo >= 0


def test_uniform_tape_replay_translation_and_no_large_support_enumeration():
    width = conditional_widths(conditional_candidate())["signature_lower"]
    sampler = WideScalarGaussian(width, width)
    tape = DeterministicRandom(b"wide-fixed-tape").read(sampler.random_tape_bytes)
    a = sampler.sample_from_tape(width, QQ(1)/3, tape)
    assert sampler.sample_from_tape(width, 10**200+QQ(1)/3, tape)-a == 10**200
    assert sampler.sample_from_tape(width, QQ(1)/3, tape) == a
    with pytest.raises(ValueError, match="enumeration"):
        sampler.finite_distribution(width)
    for bad in (b"", tape[:-1], tape+b"\0", "bad"):
        with pytest.raises(ValueError, match="fixed length"):
            sampler.sample_from_tape(width, 0, bad)


@pytest.mark.parametrize("width,center", [(True, 0), (1.0, 0), (1, True), (1, 0.1),
    (0, 0), (2, 0), (1, 2**2000), (1, QQ(1)/2**8200),
    (1, "1e1000000000"), (1, "9"*20000)], ids=["bool-width", "float-width", "bool-center",
        "float-center", "zero-width", "wrong-class", "output-overflow", "rational-bits",
        "exponent-text", "oversize-text"])
def test_input_and_all_path_output_rejections_precede_any_entropy(width, center):
    with pytest.raises(ValueError):
        WideScalarGaussian(1, 1).sample(width, center, rng=NoEntropy())


@pytest.mark.parametrize("changes,low,high,match", [
    ({}, 0, 1, "widths"), ({}, 2, 1, "widths"), ({}, 1, 2**96+1, "widths"),
    ({"max_radius": 1}, 1, 1, "radius"),
    ({"max_gaussian_trials": 1}, 1, 1, "rejection"),
    ({"max_tape_bytes": 1}, 1, 1, "tape"),
    ({"target_tv_bits": 256}, 1, 1, "TV"),
    ({"max_output_bits": 16}, 2**80, 2**80, "coefficient"),
    ({}, 1, 2**80, "rejection"),
])
def test_invalid_public_classes_fail_at_construction(changes, low, high, match):
    with pytest.raises(ValueError, match=match):
        WideScalarGaussian(low, high, options=replace(WideScalarOptions(), **changes))


@pytest.mark.parametrize("changes", [{"max_radius": 2**80+1}, {"max_width_squared": 2**128+1},
    {"precision_bits": True}, {"max_tape_bytes": 256*1024*1024+1}, {"target_tv_bits": 0}])
def test_explicit_wide_resource_options_are_bounded(changes):
    with pytest.raises(ValueError):
        replace(WideScalarOptions(), **changes)


def test_uniform_and_gaussian_abort_are_explicit_with_no_redraw():
    sampler = WideScalarGaussian(1, 1)
    class UniformReject:
        calls = 0
        def read(self, size):
            self.calls += 1
            return b"\xff"*size
    source = UniformReject()
    with pytest.raises(SamplingAbort, match="Uniform-integer"):
        sampler.sample(1, rng=source)
    assert source.calls == sampler.options.max_uniform_trials
    class GaussianReject:
        calls = 0
        def read(self, size):
            self.calls += 1
            return bytes(size) if size == sampler.candidate_bytes else b"\xff"*size
    source = GaussianReject()
    with pytest.raises(SamplingAbort, match="Gaussian rejection"):
        sampler.sample(1, rng=source)
    assert source.calls == 2*sampler.gaussian_trials
    cert = sampler.certificate()
    assert QQ(cert["abort_upper"]) == QQ(cert["gaussian_rejection_abort_upper"])+QQ(cert["uniform_abort_union_upper"])
    assert cert["public_tape_bytes"] == sampler.gaussian_trials*(
        sampler.options.max_uniform_trials*sampler.candidate_bytes+sampler.bernoulli_bytes)


@pytest.mark.parametrize("result", [b"", "bad", None])
def test_malformed_random_sources_propagate_without_fallback(result):
    class Broken:
        def read(self, size): return result
    with pytest.raises(ValueError, match="byte count or type"):
        WideScalarGaussian(1, 1).sample(1, rng=Broken())


def test_certificates_are_public_copies_and_default_rng_is_explicit(monkeypatch):
    from experiments.research.candidates.srgg import wide_scalar
    sampler = WideScalarGaussian(1, 1)
    certificate = sampler.certificate()
    certificate["finite_options"]["mass_bits"] = 1
    assert sampler.certificate()["finite_options"]["mass_bits"] == 192
    assert certificate["CDF_tables"] == certificate["support_or_centers_precomputed"] == 0
    monkeypatch.setattr(wide_scalar, "SecureRandom", lambda: DeterministicRandom(b"system-path-test-only"))
    assert type(sampler.sample(1)) is int
