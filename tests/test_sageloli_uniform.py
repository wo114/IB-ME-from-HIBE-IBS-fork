"""Exact finite-domain and failure checks for Sageloli's uniform byte mapping.

No statistical frequency acceptance test is used: the small-domain checks
exhaust the candidate space and count every accepted residue's preimages.
These checks do not establish IBS security or Gaussian distribution bounds.
"""

from collections import Counter
from array import array

import pytest

from ibme.core.encoding import encode_bytes
from ibme.core.errors import EncodingError
from ibme.core.hashing import shake256
from experiments.research.candidates.sageloli import hashing
from experiments.research.candidates.sageloli.uniform import (
    MAX_BYTES, MAX_MODULUS_BITS, MAX_TRIALS_PER_VALUE, MAX_VALUES,
    Shake256Stream, UniformSamplingAbort, shake_uniform_mod_q, uniform_mod_q,
)


class BytesSource:
    def __init__(self, data):
        self.data, self.position, self.calls = data, 0, []

    def read(self, size):
        self.calls.append(size)
        end = self.position + size
        result = self.data[self.position:end]
        self.position = end
        return result


@pytest.mark.parametrize("q", [2, 3, 81, 129, 251, 256, 257])
def test_exhaustive_candidate_space_has_exactly_equal_accepted_preimages(q):
    width = max(1, ((q - 1).bit_length() + 7) // 8)
    space = 256**width
    limit = space - space % q
    source = BytesSource(b"".join(value.to_bytes(width, "big") for value in range(limit)))
    values = uniform_mod_q(source, q, limit, max_trials_per_value=1)
    assert Counter(values) == {residue: limit // q for residue in range(q)}
    assert source.position == limit * width
    # Cover every rejected candidate as well, with no unseen tail behavior.
    for candidate in range(limit, space):
        rejected = BytesSource(candidate.to_bytes(width, "big"))
        with pytest.raises(UniformSamplingAbort, match="trial budget"):
            uniform_mod_q(rejected, q, 1, max_trials_per_value=1)
        assert rejected.calls == [width]


def test_rejection_is_not_reduction_and_budget_resets_per_value():
    source = BytesSource(bytes([243, 242, 255, 81, 244, 0]))
    assert uniform_mod_q(source, 81, 3, max_trials_per_value=2) == (80, 0, 0)
    assert source.calls == [1] * 6


def test_power_of_two_q_uses_the_minimal_width_without_rejections():
    source = BytesSource(bytes(range(256)))
    assert uniform_mod_q(source, 256, 256, max_trials_per_value=1) == tuple(range(256))
    assert source.calls == [1] * 256


def test_trial_exhaustion_returns_no_partial_result_and_stops_reading():
    source = BytesSource(bytes([1, 255, 255, 255, 2]))
    with pytest.raises(UniformSamplingAbort, match="trial budget"):
        uniform_mod_q(source, 81, 2, max_trials_per_value=3)
    assert source.position == 4


def test_total_byte_budget_stops_before_reading_past_cap():
    source = BytesSource(bytes([255, 255, 1]))
    with pytest.raises(UniformSamplingAbort, match="byte budget"):
        uniform_mod_q(source, 81, 1, max_trials_per_value=3, max_bytes=2)
    assert source.position == 2


@pytest.mark.parametrize("result", [b"", b"long", "x", 1, None, memoryview(array("I", [1]))])
def test_malformed_entropy_aborts_immediately(result):
    class Broken:
        calls = 0

        def read(self, size):
            self.calls += 1
            return result

    source = Broken()
    with pytest.raises(UniformSamplingAbort, match="invalid result"):
        uniform_mod_q(source, 81, 1)
    assert source.calls == 1


def test_entropy_exception_is_chained_and_not_retried():
    class Broken:
        calls = 0

        def read(self, size):
            self.calls += 1
            raise OSError("fixture entropy failure")

    source = Broken()
    with pytest.raises(UniformSamplingAbort, match="source failed") as caught:
        uniform_mod_q(source, 81, 1)
    assert isinstance(caught.value.__cause__, OSError)
    assert source.calls == 1


@pytest.mark.parametrize("wrapper", [bytearray, memoryview])
def test_bytes_like_entropy_is_normalized(wrapper):
    class Wrapped:
        def read(self, size):
            return wrapper(b"\x52" * size)

    assert uniform_mod_q(Wrapped(), 81, 2) == (1, 1)


@pytest.mark.parametrize("q,count,options", [
    (True, 1, {}), (1, 1, {}), (-3, 1, {}), (3.0, 1, {}),
    ((1 << MAX_MODULUS_BITS) + 1, 1, {}),
    (81, True, {}), (81, -1, {}), (81, MAX_VALUES + 1, {}),
    (81, 1, {"max_trials_per_value": 0}),
    (81, 1, {"max_trials_per_value": True}),
    (81, 1, {"max_trials_per_value": MAX_TRIALS_PER_VALUE + 1}),
    (81, 1, {"max_bytes": 0}), (81, 1, {"max_bytes": True}),
    (81, 1, {"max_bytes": MAX_BYTES + 1}),
    (257, 2, {"max_bytes": 3}),
])
def test_invalid_parameters_fail_before_entropy(q, count, options):
    source = BytesSource(b"\x00" * 8)
    with pytest.raises(ValueError):
        uniform_mod_q(source, q, count, **options)
    assert source.calls == []


def test_empty_count_is_checked_but_consumes_no_entropy():
    source = BytesSource(b"")
    assert uniform_mod_q(source, 81, 0) == ()
    assert source.calls == []
    with pytest.raises(TypeError):
        uniform_mod_q(object(), 81, 0)


def test_shake_cursor_matches_core_xof_across_prefix_growth_and_reads():
    domain, payload = b"SAG-TEST-v2", b"public payload"
    stream = Shake256Stream(domain, payload, max_bytes=4099)
    sizes = [0, 1, 62, 1, 65, 257, 0, 1025, 2688]
    assert sum(sizes) == 4099
    assert b"".join(stream.read(size) for size in sizes) == shake256(domain, payload, 4099)
    assert stream.read(0) == b""
    with pytest.raises(UniformSamplingAbort, match="byte budget"):
        stream.read(1)
    # Failed reads did not rewind the cursor or change already consumed bytes.
    assert stream.read(0) == b""


@pytest.mark.parametrize("size", [True, -1, 1.0, 65])
def test_invalid_xof_reads_do_not_advance_cursor(size):
    stream = Shake256Stream(b"domain", b"payload", max_bytes=64)
    with pytest.raises(ValueError):
        stream.read(size)
    assert stream.read(64) == shake256(b"domain", b"payload", 64)


def _reference_xof_rejection(domain, payload, q, count):
    # Independent, one-shot reference: no stream adapter or shared sampler.
    width = max(1, ((q - 1).bit_length() + 7) // 8)
    raw = shake256(domain, payload, 8 * count * width)
    limit = 256**width // q * q
    output = []
    for offset in range(0, len(raw), width):
        candidate = int.from_bytes(raw[offset:offset + width], "big")
        if candidate < limit:
            output.append(candidate % q)
            if len(output) == count:
                return tuple(output)
    raise AssertionError("fixture reference byte budget exhausted")


def test_long_xof_rejection_matches_independent_one_shot_reference():
    domain, payload, q, count = b"SAG-UNIFORM-v2", b"test", 129, 3000
    assert shake_uniform_mod_q(domain, payload, q, count) == _reference_xof_rejection(
        domain, payload, q, count)


@pytest.mark.parametrize("route", ["sis", "rsis"])
def test_h1_h2_use_canonical_payload_and_unbiased_reference(route):
    context, r, identity, salt, message = b"ctx", b"r", b"alice", b"s", b""
    h1_payload = encode_bytes(context) + encode_bytes(r) + encode_bytes(identity)
    h2_payload = h1_payload + encode_bytes(salt) + encode_bytes(message)
    if route == "sis":
        actual_h1 = tuple(x for row in hashing.sis_h1(context, r, identity, 3, 4, 81) for x in row)
        actual_h2 = hashing.sis_h2(context, r, salt, identity, message, 3, 81)
        h1_domain, h2_domain, h1_count, h2_count = hashing.H1_SIS_DOMAIN, hashing.H2_SIS_DOMAIN, 36, 3
    else:
        actual_h1 = tuple(x for row in hashing.rsis_h1(context, r, identity, 9, 4, 19683) for x in row)
        actual_h2 = hashing.rsis_h2(context, r, salt, identity, message, 4, 19683)
        h1_domain, h2_domain, h1_count, h2_count = hashing.H1_RSIS_DOMAIN, hashing.H2_RSIS_DOMAIN, 36, 4
    assert h1_domain.endswith(b"v2") and h2_domain.endswith(b"v2")
    assert actual_h1 == _reference_xof_rejection(h1_domain, h1_payload, 81 if route == "sis" else 19683, h1_count)
    assert actual_h2 == _reference_xof_rejection(h2_domain, h2_payload, 81 if route == "sis" else 19683, h2_count)


def test_empty_h2_fields_are_encoded_and_none_is_rejected():
    payload = b"".join(encode_bytes(x) for x in (b"ctx", b"", b"id", b"", b""))
    assert hashing.sis_h2(b"ctx", b"", b"", b"id", b"", 16, 81) == _reference_xof_rejection(
        hashing.H2_SIS_DOMAIN, payload, 81, 16)
    with pytest.raises(EncodingError):
        hashing.sis_h2(b"ctx", b"", None, b"id", None, 16, 81)


def test_hash_field_boundaries_and_domains_remain_separate():
    a = hashing.sis_h2(b"a", b"bc", b"s", b"id", b"m", 32, 81)
    assert a != hashing.sis_h2(b"ab", b"c", b"s", b"id", b"m", 32, 81)
    assert a != hashing.sis_h2(b"a", b"bc", b"s", b"id", b"M", 32, 81)
    assert a != hashing.sis_h2(b"a", b"bc", b"S", b"id", b"m", 32, 81)
    assert a != hashing.rsis_h2(b"a", b"bc", b"s", b"id", b"m", 32, 81)


@pytest.mark.parametrize("call", [
    lambda: hashing.sis_h1(b"c", b"r", b"id", True, 4, 81),
    lambda: hashing.sis_h1(b"c", b"r", b"id", 1024, 1024, 81),
    lambda: hashing.sis_h2(b"c", b"r", b"s", b"id", b"m", 0, 81),
    lambda: hashing.rsis_h1(b"c", b"r", b"id", 4, -1, 81),
    lambda: hashing.rsis_h2(b"c", b"r", b"s", b"id", b"m", 1.0, 81),
    lambda: hashing.sis_h2(b"c", b"r", b"s", b"id", b"m", 3, 81, max_bytes=2),
])
def test_hash_dimension_and_resource_checks(call):
    with pytest.raises(ValueError):
        call()


def test_hash_rejection_exhaustion_is_exposed_without_retry(monkeypatch):
    class AllRejected:
        instances = []

        def __init__(self, domain, payload, *, max_bytes):
            self.calls = 0
            self.instances.append(self)

        def read(self, size):
            self.calls += 1
            return b"\xff" * size

    from experiments.research.candidates.sageloli import uniform
    monkeypatch.setattr(uniform, "Shake256Stream", AllRejected)
    with pytest.raises(UniformSamplingAbort, match="trial budget"):
        hashing.sis_h2(b"c", b"r", b"s", b"id", b"m", 1, 81,
                      max_trials_per_value=2)
    assert len(AllRejected.instances) == 1
    assert AllRejected.instances[0].calls == 2
