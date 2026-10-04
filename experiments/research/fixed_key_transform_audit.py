"""Exact, noncryptographic checks for the fixed-key IBS research draft.

The salt enumeration is finite and exact. The reduction trace uses distinct
symbolic labels on paths where collisions are excluded; it neither samples a
random oracle nor verifies a signature. It must never be used as an IBS backend.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from fractions import Fraction
from itertools import product
from math import comb
from pathlib import Path


def salt_distribution(identities, *, alphabet_size=4, cached=True):
    """Public identity-salt transcript under cached or fresh KeyExt per Sig."""
    if not isinstance(alphabet_size, int) or alphabet_size < 2:
        raise ValueError("Salt alphabet must contain at least two elements")
    keys = list(identities) if cached else list(range(len(identities)))
    distinct = list(dict.fromkeys(keys))
    states = alphabet_size ** len(distinct)
    if states > 65536:
        raise ValueError("Exact enumeration is limited to 65536 assignments")
    counts = Counter()
    for assignment in product(range(alphabet_size), repeat=len(distinct)):
        values = dict(zip(distinct, assignment))
        counts[tuple(values[key] for key in keys)] += 1
    return {values: Fraction(count, states) for values, count in sorted(counts.items())}


def total_variation(left, right):
    return sum((abs(left.get(v, 0) - right.get(v, 0))
                for v in left.keys() | right.keys()), Fraction()) / 2


class TraceAbort(ValueError):
    """An explicitly excluded path in the symbolic reduction."""


class FixedKeyTrace:
    """One cached key per outer identity; precommit before any online queries.

    guess=None models B0; a one-based slot number models B1. Nonces are
    illustrative distinct labels, not randomness. All queried identities and
    messages are plain labels. Cryptographic validity is deliberately absent.
    """

    def __init__(self, *, slots, signing_limit, guess=None):
        if slots < 1 or signing_limit < 0 or (guess is not None and not 1 <= guess <= slots):
            raise ValueError("Invalid query bounds or guessed slot")
        self.slots = slots
        self.signing_limit = signing_limit
        self.guess = guess
        self.inner_ids = tuple(f"x-{i}" for i in range(1, slots + 1))
        self.pre_keys = frozenset(x for i, x in enumerate(self.inner_ids, 1) if i != guess)
        self.pre_pairs = (tuple((self.inner_ids[guess - 1], f"y-{j}")
                                for j in range(1, signing_limit + 1))
                          if guess is not None else ())
        self.users = {}
        self.identity_oracle = {}
        self.message_oracle = {}
        self.corrupted = set()
        self.signed_pairs = set()
        self.events = []
        self.sign_calls = 0
        self.batch_used = 0
        self.aborted = False

    def _abort(self, reason):
        self.aborted = True
        raise TraceAbort(reason)

    def _ensure_user(self, identity):
        if self.aborted:
            raise TraceAbort("Trace has already aborted")
        if identity not in self.users:
            slot = len(self.users) + 1
            if slot > self.slots:
                self._abort("Identity-slot budget exhausted")
            salt, inner_id = f"r-{slot}", self.inner_ids[slot - 1]
            self.users[identity] = (slot, salt, inner_id)
            self.identity_oracle[(identity, salt)] = inner_id
        return self.users[identity]

    def key(self, identity):
        slot, salt, inner_id = self._ensure_user(identity)
        if slot == self.guess:
            self._abort("Corruption of guessed signing target")
        self.corrupted.add(identity)
        event = {"query": "Key", "identity": identity, "slot": slot,
                 "r": salt, "inner_id": inner_id, "key": f"sk:{inner_id}"}
        self.events.append(event)
        return event

    def sign(self, identity, message, *, nonce=None):
        slot, salt, inner_id = self._ensure_user(identity)
        if self.sign_calls >= self.signing_limit:
            self._abort("Signing-query budget exhausted")
        self.sign_calls += 1
        nonce = nonce if nonce is not None else f"s-{self.sign_calls}"
        point = (message, nonce)
        if slot == self.guess:
            if point in self.message_oracle:
                self._abort("Target message point already defined; cannot program afresh")
            inner_message = self.pre_pairs[self.batch_used][1]
            self.batch_used += 1
            self.message_oracle[point] = inner_message
            source = "precommitted-signature"
        else:
            if point not in self.message_oracle:
                self.message_oracle[point] = f"outside-y-{len(self.message_oracle) + 1}"
            inner_message = self.message_oracle[point]
            source = "known-cached-key"
        self.signed_pairs.add((identity, message))
        event = {"query": "Sig", "identity": identity, "message": message,
                 "slot": slot, "r": salt, "s": nonce, "inner_id": inner_id,
                 "inner_message": inner_message, "source": source}
        self.events.append(event)
        return event

    def inner_freshness(self, inner_id, inner_message):
        # Unused precommitted keys/messages still count in the base experiment.
        return {"inner_key_fresh": inner_id not in self.pre_keys,
                "inner_pair_fresh": (inner_id, inner_message) not in self.pre_pairs}

    def forgery_eligibility(self, identity, message, *, r=None, s="s-forged"):
        if self.aborted:
            raise TraceAbort("Trace has already aborted")
        r = r if r is not None else (self.users[identity][1] if identity in self.users
                                     else f"r-unissued:{identity}")
        id_point, msg_point = (identity, r), (message, s)
        if id_point not in self.identity_oracle:
            self.identity_oracle[id_point] = f"outside-x-{len(self.identity_oracle) + 1}"
        if msg_point not in self.message_oracle:
            self.message_oracle[msg_point] = f"outside-y-{len(self.message_oracle) + 1}"
        x, y = self.identity_oracle[id_point], self.message_oracle[msg_point]
        checks = {"outer_key_fresh": identity not in self.corrupted,
                  "outer_pair_fresh": (identity, message) not in self.signed_pairs,
                  **self.inner_freshness(x, y)}
        return {"inner_id": x, "inner_message": y, **checks,
                "eligible_if_signature_valid": all(checks.values()),
                "signature_validity_checked": False}


def error_budget(*, key_queries, sign_queries, id_hash_queries, msg_hash_queries,
                 salt_bits, inner_id_bits, inner_message_bits):
    """Draft classical-ROM union bounds; no lattice-security estimate.

    Hash-query bounds include indirect queries and final verification. Distinct
    uniform draws, rather than deliberate oracle aliases, enter collision bounds.
    """
    values = (key_queries, sign_queries, id_hash_queries, msg_hash_queries,
              salt_bits, inner_id_bits, inner_message_bits)
    if any(not isinstance(v, int) or v < 0 for v in values):
        raise ValueError("All budgets must be nonnegative integers")
    slots = max(1, key_queries + sign_queries)
    n_id = slots + id_hash_queries + 1
    n_msg = sign_queries + msg_hash_queries + 1
    programming = Fraction(slots * id_hash_queries + sign_queries * msg_hash_queries,
                           2 ** salt_bits)
    collisions = (Fraction(comb(n_id, 2), 2 ** inner_id_bits)
                  + Fraction(comb(n_msg, 2), 2 ** inner_message_bits))
    total = programming + collisions
    return {"K": slots, "B1_guess_probability": str(Fraction(1, slots)),
            "outer_reduction_loss_at_most": slots + 1,
            "distinct_draw_budget": {"identity": n_id, "message": n_msg},
            "programming_union_bound": str(programming),
            "collision_union_bound": str(collisions),
            "sum_unclamped": str(total), "probability_cap": str(min(Fraction(1), total)),
            "omits_sampler_and_base_reduction_errors": True,
            "security_claim": "none"}


def audit_report():
    controls = {}
    for name, identities in {
        "same_identity_twice": ["A", "A"],
        "same_identity_three_times": ["A", "A", "A"],
        "different_identities": ["A", "B"],
    }.items():
        cached = salt_distribution(identities)
        fresh = salt_distribution(identities, cached=False)
        all_equal = lambda d: sum((p for v, p in d.items() if len(set(v)) <= 1), Fraction())
        controls[name] = {"identities": identities, "salt_alphabet_size": 4,
                          "cached_all_equal_probability": str(all_equal(cached)),
                          "fresh_all_equal_probability": str(all_equal(fresh)),
                          "salt_transcript_total_variation": str(total_variation(cached, fresh))}

    cached = FixedKeyTrace(slots=3, signing_limit=3, guess=1)
    cached.sign("A", "a-first")
    cached.sign("B", "b-first")
    cached.sign("A", "a-second")
    cached.key("B")
    existing_point = ("A", cached.users["A"][1])
    cached_trace = {"pre_keys": sorted(cached.pre_keys), "pre_pairs": list(cached.pre_pairs),
                    "events": cached.events, "forgery": cached.forgery_eligibility("A", "a-new"),
                    "literal_PW_G1_abort_on_second_cached_Sig": existing_point in cached.identity_oracle}
    repeated = FixedKeyTrace(slots=1, signing_limit=2, guess=1)
    repeated.sign("A", "same")
    repeated.sign("A", "same")
    no_sign = FixedKeyTrace(slots=2, signing_limit=1)
    no_sign.sign("B", "m")
    no_sign.key("B")
    wrong = FixedKeyTrace(slots=3, signing_limit=3, guess=2)
    wrong.sign("A", "a-first")
    wrong.sign("B", "b-first")
    try:
        wrong.key("B")
    except TraceAbort as exc:
        wrong_abort = str(exc)
    return {
        "schema_version": 1, "security_claim": "none",
        "method": "exact finite salt enumeration and symbolic query-flow checks",
        "monte_carlo_repetitions": 0, "cryptographic_signatures_generated": 0,
        "salt_checks": controls, "cached_target_with_later_other_user_corruption": cached_trace,
        "repeated_message": {"events": repeated.events,
                             "old_message_forgery": repeated.forgery_eligibility("A", "same"),
                             "unused_precommit_check": cached.inner_freshness("x-1", "y-3")},
        "B0_target_never_signed": {"events": no_sign.events,
                                   "forgery": no_sign.forgery_eligibility("A", "new")},
        "wrong_guess": {"events": wrong.events, "abort": wrong_abort},
        "tiny_budget_example": error_budget(key_queries=1, sign_queries=2,
            id_hash_queries=3, msg_hash_queries=4, salt_bits=8,
            inner_id_bits=8, inner_message_bits=8),
        "limitations": ["No random oracle or Gaussian sampler implemented",
                        "No signature validity or lattice attack evaluated",
                        "Conditional reduction and uniform joint-distribution bounds remain unproved"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    serialized = json.dumps(audit_report(), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(serialized, encoding="utf-8", newline="\n")
    else:
        print(serialized, end="")


if __name__ == "__main__":
    main()
