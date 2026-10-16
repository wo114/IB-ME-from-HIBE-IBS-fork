"""Public sampler laws, real small draws, zero-entropy n512 and fault paths."""
from collections import Counter
from dataclasses import replace
from fractions import Fraction
from itertools import product

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

from ibme.core.randomness import DeterministicRandom, SecureRandom
from experiments.research.gaussian_reference import SamplingAbort
from experiments.research.candidates.srgg import aggregate_budget
from experiments.research.candidates.srgg import reduction_samplers as rs
from experiments.research.candidates.srgg.wide_scalar import WideScalarGaussian


class NoEntropy:
    def read(self, size):
        raise AssertionError("certificate or rejected input consumed entropy")


class ByteSequence:
    def __init__(self, values):
        self.values = bytes(values)
        self.used = 0

    def read(self, size):
        result = self.values[self.used:self.used+size]
        self.used += size
        return result


class FixedBytes:
    def __init__(self, value):
        self.value = value
        self.calls = 0

    def read(self, size):
        self.calls += 1
        return bytes([self.value])*size


def small_parameters():
    return rs.ReductionParameters(degree=2, rank=1, digits=1,
        p=3, master_squared=4, signature_squared=9)


def test_n512_deep_report_constructs_no_rng_and_performs_no_draw(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("zero-entropy certificate constructed an RNG or sampled")
    monkeypatch.setattr(rs, "SecureRandom", forbidden)
    monkeypatch.setattr(aggregate_budget, "SecureRandom", forbidden)
    monkeypatch.setattr(WideScalarGaussian, "sample", forbidden)
    report = rs.build_report()
    assert report["dimensions"] == {"N": 10240, "D": 10752, "H": 1024}
    assert report["actual_entropy_bytes"] == 0 and not report["draw_performed"]
    assert report["all_samplers_admitted_under_public_caps"]
    for name, count, width in (("public_u", 10240, 1031865954433),
            ("simulator_z", 10752, 22159188660729268928705)):
        cert = report[name]
        assert cert["count"] == count and cert["squared_width"] == str(width)
        assert cert["batch"]["selected_cap_bytes"] <= aggregate_budget.MAX_BYTES
        assert Fraction(cert["finite_to_ideal_tv_upper_including_abort_exact"]) < Fraction(1, 2**176)
        assert Fraction(cert["abort_upper_exact"]) < Fraction(1, 2**176)
    e = report["uniform_e"]
    assert e["all_path_byte_cap"] == 524288
    assert Fraction(e["candidate_rejection_probability_exact"]) == Fraction(1, 16384)
    assert Fraction(e["batch_abort_upper_exact"]) == Fraction(1, 2**3574)
    assert report["binary_challenge"]["random_bytes"] == 64
    assert report["security_claim"] == "none"
    assert not report["backend_admitted"] and not report["parameters_are_formal"]
    assert report["nist_security_category"] is None


@pytest.mark.parametrize("name,width,count", [("sample_public_u", 4, 6),
                                               ("sample_simulator_z", 9, 8)])
def test_small_product_uses_real_securerandom_and_has_no_wrong_shape(name, width, count):
    source = SecureRandom()
    values = getattr(rs, name)(small_parameters(), rng=source)
    assert len(values) == count and all(type(x) is int for x in values)
    # This is a real draw and support sanity check, not a distribution test.
    sampler = WideScalarGaussian(width, width, options=rs.deep_scalar_options())
    _v, _shift, _frac, _closest, low, high = sampler.checked_inputs(width, 0)
    assert all(low <= x <= high for x in values)


@pytest.mark.parametrize("name,width,count", [("sample_public_u", 4, 6),
                                               ("sample_simulator_z", 9, 8)])
def test_product_preserves_frozen_finite_scalar_law_on_identical_test_stream(name, width, count):
    actual = getattr(rs, name)(small_parameters(), rng=DeterministicRandom(b"public-product-law"))
    source = DeterministicRandom(b"public-product-law")
    sampler = WideScalarGaussian(width, width, options=rs.deep_scalar_options())
    assert actual == tuple(sampler.sample(width, 0, rng=source) for _ in range(count))


def test_uniform_e_full_small_law_retains_abort_and_has_no_modulo_bias():
    parameters = small_parameters()  # H=2, p=3, 2-bit masked candidates.
    law = Counter()
    for candidates in product(range(4), repeat=4):
        source = ByteSequence(candidates)
        try:
            value = rs.sample_uniform_e(parameters, rng=source, max_trials=2)
        except SamplingAbort:
            value = None
        law[value] += 1
        assert source.used <= 4
    # Per coordinate success 15/16; all nine outputs have the same mass.
    assert law[None] == 31
    assert set(law) == {None} | set(product(range(3), repeat=2))
    assert all(law[value] == 25 for value in product(range(3), repeat=2))
    cert = rs.uniform_vector_certificate(3, 2, max_trials=2)
    assert Fraction(law[None], 256) <= Fraction(cert["batch_abort_upper_exact"])


def test_binary_challenge_exact_small_law_when_unused_high_bits_are_present():
    law = Counter(rs.sample_binary_challenge(3, rng=ByteSequence([word]))
        for word in range(256))
    assert set(law) == set(product(range(2), repeat=3))
    assert set(law.values()) == {32}
    assert rs.sample_binary_challenge(3, rng=ByteSequence([5])) == (1, 0, 1)


def test_small_e_and_challenge_real_securerandom_paths():
    parameters = small_parameters()
    e = rs.sample_uniform_e(parameters, rng=SecureRandom())
    c = rs.sample_binary_challenge(5, rng=SecureRandom())
    assert len(e) == parameters.H and all(0 <= x < parameters.p for x in e)
    assert len(c) == 5 and all(x in (0, 1) for x in c)


def test_forced_uniform_rejection_stops_once_without_batch_retry():
    source = FixedBytes(255)
    with pytest.raises(SamplingAbort, match="Uniform-integer rejection"):
        rs.sample_uniform_e(small_parameters(), rng=source, max_trials=3)
    assert source.calls == 3  # First coordinate fails; no second coordinate or retry.


@pytest.mark.parametrize("name", ["sample_public_u", "sample_simulator_z"])
def test_forced_gaussian_uniform_abort_is_propagated_without_batch_retry(name):
    source = FixedBytes(255)
    with pytest.raises(SamplingAbort, match="Uniform-integer rejection"):
        getattr(rs, name)(small_parameters(), rng=source)
    assert source.calls == 256  # Frozen deep uniform-trial cap.


@pytest.mark.parametrize("name", ["sample_public_u", "sample_simulator_z", "sample_uniform_e"])
def test_budget_nonadmission_happens_before_entropy(name):
    with pytest.raises(ValueError, match="cap"):
        getattr(rs, name)(small_parameters(), rng=NoEntropy(), max_bytes=1)


@pytest.mark.parametrize("payload", [b"", "not bytes", bytearray(7), memoryview(b"abc")])
@pytest.mark.parametrize("name", ["sample_public_u", "sample_simulator_z", "sample_uniform_e", "challenge"])
def test_malformed_random_sources_fail_closed(payload, name):
    class BadSource:
        def read(self, size):
            return payload
    with pytest.raises(ValueError, match="byte count or type"):
        if name == "challenge":
            rs.sample_binary_challenge(3, rng=BadSource())
        else:
            getattr(rs, name)(small_parameters(), rng=BadSource())


def test_singleton_e_uses_zero_entropy_and_the_uniform_cap_has_no_extra_failure():
    params = replace(small_parameters(), p=1)
    assert rs.sample_uniform_e(params, rng=NoEntropy()) == (0, 0)
    cert = rs.uniform_vector_certificate(1, params.H)
    assert cert["all_path_byte_cap"] == 0 and cert["extra_budget_abort_probability_exact"] == "0"
    assert cert["batch_abort_upper_exact"] == "0"


@pytest.mark.parametrize("kwargs", [{"degree": True}, {"degree": 3}, {"rank": 0},
    {"digits": 65}, {"p": 0}, {"master_squared": 1.5}, {"signature_squared": 2**96+1},
    {"degree": 4096, "rank": 16, "digits": 64}])
def test_invalid_public_parameter_objects_are_rejected(kwargs):
    with pytest.raises(ValueError):
        rs.ReductionParameters(**kwargs)


@pytest.mark.parametrize("bound,count,kwargs", [(True, 1, {}), (0, 1, {}), (3, 0, {}),
    (3, 1, {"max_trials": True}), (3, 1, {"max_trials": 4097}),
    (2**64-1, 1, {"max_trials": 4096}), (3, 1, {"max_bytes": 0})])
def test_uniform_certificate_has_bounded_exact_inputs_and_output_size(bound, count, kwargs):
    with pytest.raises(ValueError):
        rs.uniform_vector_certificate(bound, count, **kwargs)


@pytest.mark.parametrize("degree", [0, True, 1.5, aggregate_budget.MAX_COUNT+1])
def test_binary_invalid_inputs_precede_entropy(degree):
    with pytest.raises(ValueError):
        rs.sample_binary_challenge(degree, rng=NoEntropy())


@pytest.mark.parametrize("name", ["sample_public_u", "sample_simulator_z", "sample_uniform_e"])
def test_unvalidated_parameter_container_precedes_entropy(name):
    with pytest.raises(ValueError):
        getattr(rs, name)(object(), rng=NoEntropy())
