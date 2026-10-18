"""Executable byte pushforward versus independent exact laws and real parser."""
from collections import Counter
from fractions import Fraction as F
from itertools import product
import json

import pytest

from ibme.core.randomness import DeterministicRandom, SecureRandom
from experiments.research.candidates.srgg import conditional_xof as cx
from experiments.research.candidates.srgg.seeded_xof import (
    Trace, conditioned_target_trajectory_law, raw_trajectory_law,
)
from experiments.research.candidates.wang_pw.hashing import uniform_values


class Bytes:
    def __init__(self, data):
        self.data, self.used, self.calls = bytes(data), 0, 0

    def read(self, size):
        self.calls += 1
        value = self.data[self.used:self.used+size]
        self.used += size
        return value


class NoRead:
    def read(self, _size):
        raise AssertionError("invalid/cached/empty operation consumed entropy")


@pytest.mark.parametrize("q,bits", [(2, 2), (3, 2), (5, 3), (3, 8), (129, 8), (251, 8)])
def test_every_word_preimage_has_exact_reject_or_target_lift_mass(q, bits):
    size, limit = 2**bits, (2**bits//q)*q
    for target in range(q):
        counts = Counter(cx.map_word(word, target, q=q, word_bits=bits) for word in range(size))
        expected = {word: 1 for word in range(limit, size)}
        expected.update({word: q for word in range(target, limit, q)})
        assert dict(counts) == expected
    # Average external uniform targets; the transformed raw word is uniform.
    mixture = Counter(cx.map_word(word, target, q=q, word_bits=bits)
        for target in range(q) for word in range(size))
    assert set(mixture) == set(range(size))
    assert set(mixture.values()) == {q}


def _pushforward_law(q, bits, targets, trials):
    """Independently enumerate source words and call the actual pushforward."""
    result = {}
    def walk(index, used, words, accepted, mass):
        if index == len(targets) or used == trials:
            trace = Trace(words, accepted, index == len(targets))
            result[trace] = result.get(trace, F(0))+mass
            return
        for raw in range(2**bits):
            emitted = cx.map_word(raw, targets[index], q=q, word_bits=bits)
            if emitted < (2**bits//q)*q:
                walk(index+1, 0, words+(emitted,), accepted+(targets[index],), mass/2**bits)
            else:
                walk(index, used+1, words+(emitted,), accepted, mass/2**bits)
    walk(0, 0, (), (), F(1))
    return result


@pytest.mark.parametrize("q,bits,count,trials", [(3,2,2,2), (5,3,1,2), (2,2,2,2)])
def test_independent_complete_source_pushforward_matches_raw_mixture_with_abort(q,bits,count,trials):
    mixture = {}
    for targets in product(range(q), repeat=count):
        actual = _pushforward_law(q, bits, targets, trials)
        assert actual == conditioned_target_trajectory_law(q=q, word_bits=bits,
            targets=targets, max_trials=trials)
        for trace, mass in actual.items():
            mixture[trace] = mixture.get(trace, F(0))+mass/q**count
    assert mixture == raw_trajectory_law(q=q, word_bits=bits, count=count, max_trials=trials)


def test_actual_byte_generator_exhaustive_two_word_law_includes_partial_abort():
    # Exhaust all 2-byte tapes, not a statistical sample. T=1 has two target
    # coefficients, so abort can occur before or after the first acceptance.
    counts = Counter()
    for first in range(256):
        for second in range(256):
            source = Bytes((first, second))
            trace = cx.generate_trajectory(3, (1, 2), rng=source, max_trials=1)
            key = Trace(trace.words, trace.accepted, trace.success)
            counts[key] += 1
            assert source.used == len(trace.words)
    assert sum(counts.values()) == 256**2
    for trace, count in counts.items():
        assert trace.accepted == (1, 2)[:len(trace.accepted)]
        assert F(count, 256**2) == F(3**len(trace.accepted), 256**len(trace.words))
    abort = sum(count for trace, count in counts.items() if not trace.success)
    assert F(abort, 256**2) == 1-F(255,256)**2


@pytest.mark.parametrize("q,targets,words,success,expected", [
    (3, (2,), (255, 0), True, (255, 2)),
    (3, (1,), (255, 255), False, (255, 255)),
    (251, (17, 42), (252, 253, 250, 254, 12), True, (252, 253, 17, 254, 42)),
    (256, (0, 255), (17, 42), True, (0, 255)),
])
def test_generated_full_bytes_replay_through_unchanged_actual_uniform_parser(q,targets,words,success,expected):
    trials = 3 if q == 251 else 2
    source = Bytes(words)
    trace = cx.generate_trajectory(q, targets, rng=source, max_trials=trials)
    assert trace.success is success and trace.words == expected
    reader = Bytes(trace.raw_prefix)
    if success:
        assert uniform_values(reader, q, len(targets), max_trials=trials) == targets
    else:
        with pytest.raises(ValueError, match="rejection budget exhausted"):
            uniform_values(reader, q, len(targets), max_trials=trials)
    assert source.used == reader.used == len(trace.raw_prefix)


def test_original_256_all_rejects_stop_and_suffix_continues_without_restarting():
    raw = bytes([255])*256+b"continuation bytes"
    source = Bytes(raw)
    point = cx.ConditionalPoint(3, (1, 2), rng=source, raw_query_budget=4096)
    assert point.prefix(1) == b"\xff"
    assert point.trajectory.success is False
    assert point.trajectory.accepted == () and len(point.trajectory.words) == 256
    assert source.used == 256
    assert point.read_at(256, 18) == b"continuation bytes"
    assert source.used == 274 and point.first_touches == 1
    assert point.prefix(274) == raw
    assert source.used == 274
    assert F(1, 256**256) == F(1,2**2048)  # retained branch, not success conditioning


@pytest.mark.parametrize("first", ["one-byte", "prefix", "offset"])
def test_first_nonempty_raw_query_initializes_entire_fixed_trajectory(first):
    # Accepted after one rejection then one rejection: complete prefix is
    # ff 02 ff 04 (the second acceptance keeps lift k=1); the final three
    # bytes are independent suffix source bytes.
    source = Bytes((255, 0, 255, 4, 90, 91, 92))
    point = cx.ConditionalPoint(3, (2, 1), rng=source, max_trials=2, raw_query_budget=32)
    assert point.prefix(0) == b"" and point.read_at(20, 0) == b""
    assert point.trajectory is None and point.first_touches == source.used == 0
    if first == "one-byte":
        assert point.prefix(1) == b"\xff"
        assert source.used == 4
    elif first == "prefix":
        assert point.prefix(4) == bytes((255, 2, 255, 4))
    else:
        assert point.read_at(5, 1) == bytes((91,))
    assert point.first_touches == 1
    assert point.trajectory.success is True and point.trajectory.accepted == (2, 1)
    assert point.prefix(7) == bytes((255, 2, 255, 4, 90, 91, 92))
    assert source.used == point.source_bytes == 7
    assert point.read_at(2, 4) == bytes((255, 4, 90, 91))
    assert source.used == 7


def test_successful_parser_and_public_recomputation_reuse_identical_raw_point():
    source = Bytes((255, 4, 255, 7, 11, 12))
    point = cx.ConditionalPoint(3, (1, 2), rng=source, max_trials=2)
    assert uniform_values(point, 3, 2, max_trials=2) == (1, 2)
    prefix, used = point.prefix(4), source.used
    assert uniform_values(Bytes(prefix), 3, 2, max_trials=2) == (1, 2)
    assert point.prefix(4) == prefix and source.used == used and point.first_touches == 1


def test_actual_small_draw_from_secure_source_has_expected_targets_and_parser():
    # Real randomness, one small draw; this is not a distribution estimate.
    targets = (0, 17, 128, 42)
    trace = cx.generate_trajectory(129, targets, rng=SecureRandom())
    assert trace.success is True and trace.accepted == targets
    assert uniform_values(Bytes(trace.raw_prefix), 129, len(targets)) == targets
    assert len(trace.words) <= 256*len(targets)


def test_multibyte_target_lifts_and_suffix_use_same_sequential_source():
    q = 13972913866395903
    width = 7
    raw_words = (0, q, 5*q, 2*q+7)
    data = b"".join(value.to_bytes(width,"big") for value in raw_words)+b"suffix"
    source = Bytes(data)
    point = cx.ConditionalPoint(q, (q-1, 1, 42), rng=source)
    point.prefix(1)
    assert point.trajectory.words == (q-1, q+1, 5*q, 2*q+42)
    assert point.trajectory.accepted == (q-1, 1, 42)
    assert uniform_values(Bytes(point.trajectory.raw_prefix), q, 3) == (q-1, 1, 42)
    assert point.read_at(28,6) == b"suffix" and source.used == 34


def test_n512_certificate_is_zero_entropy_exact_bounded_and_not_K_h(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("certificate constructed a source or performed a draw")
    monkeypatch.setattr(cx, "SecureRandom", forbidden)
    monkeypatch.setattr(cx, "generate_trajectory", forbidden)
    report = cx.build_report()
    assert report["actual_entropy_bytes"] == 0 and report["draw_performed"] is False
    for name, count, trajectory, cap, exponent in (
            ("matrix",2048,3670016,8388608,-1278),
            ("identity",1024,1835008,4194304,-1279)):
        row = report[name]
        assert row["coefficient_count"] == count
        assert row["word_bytes"] == 7 and row["accepted_lifts_per_residue"] == 5
        assert row["trajectory_random_bytes_all_paths"] == trajectory
        assert row["point_random_bytes_all_paths"] == cap
        assert row["admitted"] is True
        assert row["helper_rejection_trials"] == 0
        assert row["finite_to_ideal_G_h_tv_exact"] == "0"
        assert row["helper_extra_abort_probability_exact"] == "0"
        assert row["extra_runtime_byte_cap_abort_probability_exact"] == "0"
        assert row["original_abort_upper_dyadic_exponent"] == exponent
        assert count*F(row["rho"])**256 < F(1,2**(-exponent))
    assert not report["success_conditioned_K_h_implemented"]
    assert not report["production_SHAKE_or_QRO_programmed"]
    assert not report["whole_adaptive_reduction_implemented"]
    assert report["security_claim"] == "none"
    assert report["backend_admitted"] is report["parameters_are_formal"] is False
    assert all(len(value)==64 for value in report["source_sha256"].values())
    json.dumps(report)


def test_certificate_large_dyadic_remains_json_serializable_without_digit_limit_changes():
    row = cx.conditional_certificate(q=2**128-1, count=1, max_trials=4096)
    assert row["original_abort_upper_dyadic_exponent"] == -128*4096
    json.dumps(row)


@pytest.mark.parametrize("change", [
    {"q":True}, {"q":1}, {"targets":[]}, {"targets":[True]},
    {"targets":[3]}, {"targets":iter((1,))}, {"max_trials":0},
    {"max_trials":True}, {"max_bytes":0}, {"max_bytes":1},
])
def test_invalid_or_unadmitted_trajectory_inputs_stop_before_entropy(change):
    args = dict(q=3, targets=[1], rng=NoRead())
    args.update(change)
    with pytest.raises(ValueError):
        cx.generate_trajectory(**args)


@pytest.mark.parametrize("offset,size", [(-1,1),(0,-1),(True,1),(0,1.0),(31,2)])
def test_invalid_and_overbudget_reads_stop_before_initialization(offset,size):
    point = cx.ConditionalPoint(3,(1,),rng=NoRead(),raw_query_budget=32)
    with pytest.raises(ValueError):
        point.read_at(offset,size)
    assert point.first_touches == 0 and point.source_bytes == 0


def test_byte_cap_admission_covers_whole_trace_and_queried_suffix():
    row = cx.conditional_certificate(q=3,count=2,max_trials=256,
        raw_query_budget=1000,max_bytes=999)
    assert row["trajectory_random_bytes_all_paths"] == 512
    assert not row["admitted"] and row["extra_runtime_byte_cap_abort_probability_exact"] is None
    with pytest.raises(ValueError, match="not admitted"):
        cx.ConditionalPoint(3,(1,2),rng=NoRead(),raw_query_budget=1000,max_bytes=999)
    point = cx.ConditionalPoint(3,(1,2),rng=DeterministicRandom(b"bounded-conditional-point"),
        raw_query_budget=1000,max_bytes=1000)
    point.read_at(999,1)
    assert point.source_bytes == 1000 and point.cached_bytes == 1000


def test_entropy_failure_blocks_point_and_never_reselects_or_retries():
    source = Bytes((255,))
    point = cx.ConditionalPoint(3,(1,),rng=source,max_trials=2)
    with pytest.raises(ValueError,match="wrong byte count"):
        point.prefix(1)
    calls = source.calls
    with pytest.raises(ValueError,match="no reselection"):
        point.prefix(1)
    assert source.calls == calls and point.first_touches == 1
