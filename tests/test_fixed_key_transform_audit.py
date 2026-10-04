"""Independently specified transcript checks, not cryptographic security tests."""

from fractions import Fraction
from pathlib import Path
import runpy

import pytest


AUDIT = runpy.run_path(str(Path(__file__).resolve().parents[1] /
                          "experiments/research/fixed_key_transform_audit.py"))
Trace = AUDIT["FixedKeyTrace"]
Abort = AUDIT["TraceAbort"]
distribution = AUDIT["salt_distribution"]
distance = AUDIT["total_variation"]


def test_two_fixed_salts_have_visible_joint_gap_but_same_marginals():
    cached = distribution(["A", "A"], alphabet_size=2)
    fresh = distribution(["A", "A"], alphabet_size=2, cached=False)
    assert cached == {(0, 0): Fraction(1, 2), (1, 1): Fraction(1, 2)}
    assert fresh == {v: Fraction(1, 4) for v in [(0, 0), (0, 1), (1, 0), (1, 1)]}
    assert distance(cached, fresh) == Fraction(1, 2)
    for d in (cached, fresh):
        for i in (0, 1):
            assert sum(p for v, p in d.items() if v[i] == 0) == Fraction(1, 2)


@pytest.mark.parametrize("identities", [[], ["A"], ["A", "B"]])
def test_salt_controls(identities):
    cached = distribution(identities)
    fresh = distribution(identities, cached=False)
    assert sum(cached.values()) == sum(fresh.values()) == 1
    assert distance(cached, fresh) == 0


def test_four_salt_values_and_three_queries_have_fifteen_sixteenths_gap():
    assert distance(distribution(["A"] * 3),
                    distribution(["A"] * 3, cached=False)) == Fraction(15, 16)


@pytest.mark.parametrize("kwargs", [{"alphabet_size": 1}, {"alphabet_size": 100000}])
def test_invalid_or_excessive_salt_enumeration_rejected(kwargs):
    with pytest.raises(ValueError):
        distribution(["A"], **kwargs)


def test_cached_target_can_be_signed_twice_and_other_user_corrupted_after_signing():
    t = Trace(slots=3, signing_limit=3, guess=1)
    assert t.pre_keys == {"x-2", "x-3"}
    assert t.pre_pairs == (("x-1", "y-1"), ("x-1", "y-2"), ("x-1", "y-3"))
    first = t.sign("A", "one")
    other = t.sign("B", "one")
    second = t.sign("A", "two")
    key = t.key("B")
    assert first["r"] == second["r"] == "r-1"
    assert (first["inner_id"], second["inner_id"]) == ("x-1", "x-1")
    assert (first["inner_message"], second["inner_message"]) == ("y-1", "y-2")
    assert other["inner_id"] == key["inner_id"] == "x-2"
    assert other["source"] == "known-cached-key"
    assert t.forgery_eligibility("A", "new")["eligible_if_signature_valid"]


def test_repeated_key_queries_return_the_same_instance():
    t = Trace(slots=1, signing_limit=1)
    first = t.key("A")
    t.sign("A", "m")
    assert t.key("A") == first
    assert len(t.users) == 1
    assert not t.forgery_eligibility("A", "new")["outer_key_fresh"]


def test_repeated_message_uses_distinct_message_salts_but_is_not_fresh_for_forgery():
    t = Trace(slots=1, signing_limit=2, guess=1)
    first, second = t.sign("A", "same"), t.sign("A", "same")
    assert first["r"] == second["r"]
    assert first["s"] != second["s"]
    assert first["inner_message"] != second["inner_message"]
    assert not t.forgery_eligibility("A", "same")["outer_pair_fresh"]


def test_unused_precommitted_message_is_still_excluded():
    t = Trace(slots=2, signing_limit=3, guess=1)
    t.sign("A", "one")
    assert t.batch_used == 1
    assert t.inner_freshness("x-1", "y-3") == {
        "inner_key_fresh": True, "inner_pair_fresh": False}
    assert not t.inner_freshness("x-2", "outside-y")["inner_key_fresh"]


def test_never_signed_target_is_handled_by_B0_and_alternative_salt_is_not_pinned():
    t = Trace(slots=2, signing_limit=1)
    t.sign("B", "old")
    t.key("B")
    assert t.forgery_eligibility("A", "new")["eligible_if_signature_valid"]
    u = Trace(slots=1, signing_limit=1, guess=1)
    u.sign("A", "old")
    assert u.forgery_eligibility("A", "new", r="different-r")["eligible_if_signature_valid"]


def test_wrong_guess_aborts_on_later_corruption():
    t = Trace(slots=2, signing_limit=2, guess=2)
    t.sign("A", "one")
    t.sign("B", "two")
    with pytest.raises(Abort, match="Corruption of guessed"):
        t.key("B")
    with pytest.raises(Abort, match="already aborted"):
        t.sign("A", "new")


def test_existing_target_message_point_cannot_be_reprogrammed():
    t = Trace(slots=1, signing_limit=2, guess=1)
    t.sign("A", "same", nonce="chosen-s")
    with pytest.raises(Abort, match="already defined"):
        t.sign("A", "same", nonce="chosen-s")


def test_message_oracle_alias_across_other_identity_is_allowed():
    t = Trace(slots=2, signing_limit=2, guess=1)
    first = t.sign("A", "same", nonce="same-s")
    other = t.sign("B", "same", nonce="same-s")
    assert first["inner_message"] == other["inner_message"]
    assert other["source"] == "known-cached-key"


@pytest.mark.parametrize("budget", ["slots", "signatures"])
def test_budget_exhaustion_is_explicit(budget):
    t = Trace(slots=1, signing_limit=1)
    t.sign("A", "one")
    with pytest.raises(Abort, match="budget exhausted"):
        t.key("B") if budget == "slots" else t.sign("A", "two")


def test_union_budget_has_independent_integer_expected_values():
    b = AUDIT["error_budget"](key_queries=1, sign_queries=2,
        id_hash_queries=3, msg_hash_queries=4, salt_bits=8,
        inner_id_bits=8, inner_message_bits=8)
    assert b["K"] == 3 and b["B1_guess_probability"] == "1/3"
    assert b["outer_reduction_loss_at_most"] == 4
    assert b["programming_union_bound"] == "17/256"
    assert b["collision_union_bound"] == "21/128"
    assert b["sum_unclamped"] == "59/256"


def test_vacuous_union_bound_is_reported_without_security_label():
    b = AUDIT["error_budget"](key_queries=2, sign_queries=2,
        id_hash_queries=2, msg_hash_queries=2, salt_bits=0,
        inner_id_bits=0, inner_message_bits=0)
    assert Fraction(b["sum_unclamped"]) > 1
    assert b["probability_cap"] == "1"
    assert b["security_claim"] == "none"


def test_negative_budget_rejected():
    with pytest.raises(ValueError):
        AUDIT["error_budget"](key_queries=-1, sign_queries=0,
            id_hash_queries=0, msg_hash_queries=0, salt_bits=1,
            inner_id_bits=1, inner_message_bits=1)
