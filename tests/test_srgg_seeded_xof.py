"""Finite complete trajectories and exact SRGG ideal-XOF arithmetic.

No cryptographic key, production oracle, or quantum oracle is generated.
"""
from fractions import Fraction as F
from itertools import product
import json

import pytest

from experiments.research.candidates.srgg.seeded_xof import (
    Trace, build_report, classical_prequery_hit_upper, conditioned_target_trajectory_law,
    expansion_certificate, observed_prefix_law, raw_trajectory_law, rejection_layout,
)
from experiments.research.candidates.wang_pw.hashing import uniform_values


def _mix(q, bits, count, trials):
    mixed = {}
    for targets in product(range(q), repeat=count):
        law = conditioned_target_trajectory_law(q=q, word_bits=bits,
            targets=targets, max_trials=trials)
        assert sum(law.values()) == 1
        for trace, probability in law.items():
            mixed[trace] = mixed.get(trace, F(0))+probability/q**count
    return mixed


@pytest.mark.parametrize("q,bits,count,trials", [(3, 2, 1, 3), (3, 2, 2, 2), (2, 2, 2, 2), (5, 3, 1, 2)])
def test_uniform_target_mixture_equals_every_raw_trajectory_including_abort(q, bits, count, trials):
    raw = raw_trajectory_law(q=q, word_bits=bits, count=count, max_trials=trials)
    mixed = _mix(q, bits, count, trials)
    assert raw == mixed
    assert sum(raw.values()) == 1
    for trace, probability in raw.items():
        assert probability == F(1, (2**bits)**len(trace.words))
        assert len(trace.accepted) == count if trace.success else len(trace.accepted) < count


def test_fixed_target_law_is_conditioned_at_acceptances_and_retains_failure():
    q, count = 3, 2
    raw = raw_trajectory_law(q=q, word_bits=2, count=count, max_trials=2)
    for targets in product(range(q), repeat=count):
        law = conditioned_target_trajectory_law(q=q, word_bits=2, targets=targets, max_trials=2)
        for trace, mass in raw.items():
            k = len(trace.accepted)
            if trace.accepted == targets[:k]:
                assert law[trace] == q**k*mass
            else:
                assert trace not in law
        # Not the raw law conditioned on parsing all targets: abort is kept.
        abort = sum(p for trace, p in law.items() if not trace.success)
        assert abort == 1-(1-F(1, 4)**2)**count > 0


def test_256_attempt_failure_branch_is_present_with_its_exact_mass():
    raw = raw_trajectory_law(q=3, word_bits=2, count=1, max_trials=256)
    conditional = conditioned_target_trajectory_law(q=3, word_bits=2, targets=(2,), max_trials=256)
    fail = Trace((3,)*256, (), False)
    assert raw[fail] == conditional[fail] == F(1, 4**256)
    assert len(raw) == 3*256+1
    assert len(conditional) == 256+1
    assert sum(raw.values()) == sum(conditional.values()) == 1


def test_all_finite_byte_trajectories_replay_through_the_actual_uniform_values_parser():
    class Bytes:
        def __init__(self, data):
            self.data, self.position = data, 0

        def read(self, size):
            result = self.data[self.position:self.position+size]
            self.position += size
            return result

    # q=251 gives one-byte candidates and five rejected byte values.
    raw = raw_trajectory_law(q=251, word_bits=8, count=1, max_trials=2)
    for trace in raw:
        stream = Bytes(bytes(trace.words))
        if trace.success:
            assert uniform_values(stream, 251, 1, max_trials=2) == trace.accepted
        else:
            with pytest.raises(ValueError, match="rejection budget exhausted"):
                uniform_values(stream, 251, 1, max_trials=2)
        assert stream.position == len(trace.words)


def test_arbitrary_observed_prefixes_and_fresh_suffix_have_one_consistent_iid_law():
    mixed = _mix(3, 2, 2, 2)
    previous = {(): F(1)}
    for length in range(1, 7):
        law = observed_prefix_law(mixed, word_bits=2, words=length)
        assert len(law) == 4**length
        assert set(law.values()) == {F(1, 4**length)}
        projected = {}
        for words, probability in law.items():
            projected[words[:-1]] = projected.get(words[:-1], F(0))+probability
        assert projected == previous
        previous = law


def test_prefix_compatibility_also_holds_when_the_target_matrix_is_fixed():
    law = conditioned_target_trajectory_law(q=3, word_bits=2, targets=(1,), max_trials=2)
    short = observed_prefix_law(law, word_bits=2, words=2)
    long = observed_prefix_law(law, word_bits=2, words=3)
    projected = {}
    for words, probability in long.items():
        projected[words[:2]] = projected.get(words[:2], F(0))+probability
    assert projected == short
    # Every trajectory has stopped by word two; the third is fresh.
    for prefix, mass in short.items():
        assert all(long[prefix+(x,)] == mass/4 for x in range(4))


def test_ignoring_the_raw_xof_seed_relation_is_detectable_in_the_finite_model():
    raw = raw_trajectory_law(q=3, word_bits=2, count=1, max_trials=1)
    conditional = conditioned_target_trajectory_law(q=3, word_bits=2, targets=(0,), max_trials=1)
    assert raw != conditional
    assert sum(p for t, p in conditional.items() if t.success and t.accepted != (0,)) == 0
    assert sum(p for t, p in raw.items() if t.success and t.accepted != (0,)) == F(1, 2)


def test_current_seven_byte_acceptance_lifts_and_abort_budget_are_exact():
    q = 13972913866395903
    row = expansion_certificate(q=q, count=2048)
    assert row["word_bytes"] == 7
    assert row["accepted_lifts_per_residue"] == 5
    assert row["limit"] == 69864569331979515
    rho = F(row["rho"])
    assert rho == F(2193024705948421, 2**56)
    assert rho < F(1, 32)
    for residue in (0, 1, q//2, q-1):
        for lift in range(5):
            word = residue+lift*q
            encoded = word.to_bytes(7, "big")
            assert int.from_bytes(encoded, "big") == word < row["limit"]
            assert word % q == residue
    assert row["maximum_consumed_bytes_before_success_or_abort"] == 3670016
    assert row["raw_read_budget_bytes"] == 8388608
    assert row["generated_prefix_cache_bytes_upper"] == 4194304
    assert row["extra_read_budget_failure_probability"] == "0"
    assert 2048*rho**256 < F(row["trial_failure_upper_dyadic_exact"]) == F(1, 2**1278)
    assert row["Public_recomputation_is_same_oracle_point_not_another_failure_trial"] is True


def test_insufficient_budget_is_not_reported_as_zero_failure():
    row = expansion_certificate(q=13972913866395903, count=2048, budget_per_coefficient=1024)
    assert row["byte_budget_always_sufficient_under_trial_cap"] is False
    assert row["extra_read_budget_failure_probability"] is None


@pytest.mark.parametrize("query_count,expected", [(0, F(0)), (1, F(1, 2**256)), (2**40, F(1, 2**216))])
def test_classical_prequery_hit_is_an_exact_seed_guess_bound(query_count, expected):
    assert classical_prequery_hit_upper(query_count) == expected


@pytest.mark.parametrize("kwargs", [
    {"q": 0, "word_bits": 2}, {"q": 5, "word_bits": 2},
    {"q": True, "word_bits": 8}, {"q": 3, "word_bits": 1.5},
])
def test_invalid_layouts_are_rejected(kwargs):
    with pytest.raises(ValueError):
        rejection_layout(**kwargs)


def test_finite_enumerator_stops_instead_of_expanding_an_unbounded_model():
    with pytest.raises(ValueError, match="resource limit"):
        raw_trajectory_law(q=251, word_bits=8, count=2, max_trials=2)


def test_report_records_source_hashes_and_preserves_all_security_boundaries():
    report = build_report()
    assert report["finite_model"]["whole_trajectory_TV_exact"] == "0"
    assert report["finite_model"]["prefix_to_iid_TV_exact"] == "0"
    assert all(len(h) == 64 for h in report["source_sha256"].values())
    assert report["actual_entropy_bytes"] == 0
    assert report["quantum_prequery_bound_established"] is False
    assert report["QROM_IBS_security_proved"] is False
    assert report["production_SHAKE_or_QRO_programmed"] is False
    assert report["security_claim"] == "none"
    assert report["backend_admitted"] is report["parameters_are_formal"] is False
    json.dumps(report)
