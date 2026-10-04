"""Exact and symbolic checks for a conditional Foo-Li classical-ROM draft.

This is not an IBS implementation: labels are not random secrets, vector examples
are hand-chosen, and no Gaussian samples or cryptographic signatures are made.
The trace checks observable consistency, not statistical indistinguishability.
"""

from __future__ import annotations

import argparse
from collections import Counter
from fractions import Fraction
from itertools import product
import json
from pathlib import Path


def _integer(value, name, *, minimum=0):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value


def _label(value, name):
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a nonempty symbolic label")
    return value


def bit_law(pairs, *, per_message=False):
    """Enumerate visible bit transcripts; keys are tuples, never concatenation."""
    pairs = list(pairs)
    for identity, message in pairs:
        _label(identity, "identity")
        _label(message, "message")
    keys = pairs if per_message else [identity for identity, _ in pairs]
    distinct = list(dict.fromkeys(keys))
    if len(distinct) > 16:
        raise ValueError("Enumeration exceeds 65536 assignments")
    counts = Counter()
    for bits in product((0, 1), repeat=len(distinct)):
        mapping = dict(zip(distinct, bits))
        counts[tuple(mapping[key] for key in keys)] += 1
    return {v: Fraction(c, 2 ** len(distinct)) for v, c in sorted(counts.items())}


def total_variation(left, right):
    return sum((abs(left.get(v, 0) - right.get(v, 0))
                for v in left.keys() | right.keys()), Fraction()) / 2


class TraceAbort(ValueError):
    """An explicit bad event or excluded path, not a cryptographic failure."""


class FixedBitTrace:
    """Lazy identity-slot bookkeeping for B_same or B_other.

    Internal records intentionally reveal labels to the auditor. Seed labels are
    symbolic names, NOT an identity-derived method of generating secret bytes.
    Every non-target signature records an honest deterministic-sampler call with
    its real symbolic key and the corresponding persistent seed-oracle coin.
    """

    def __init__(self, *, mode, slots, guess, bits=None):
        if mode not in ("same", "other"):
            raise ValueError("mode must be same or other")
        self.slots = _integer(slots, "slots", minimum=1)
        self.guess = _integer(guess, "guess", minimum=1)
        if self.guess > self.slots:
            raise ValueError("guess exceeds slots")
        self.mode = mode
        self.bits = dict(bits or {})
        for identity, bit in self.bits.items():
            _label(identity, "identity")
            if isinstance(bit, bool) or not isinstance(bit, int) or bit not in (0, 1):
                raise ValueError("Each scheduled bit must be 0 or 1")
        self.users = {}
        self.hashes = {}
        self.references = {}
        self.coins = {}
        self.signatures = {}
        self.corrupted = set()
        self.events = []
        self.aborted = False

    def _abort(self, reason):
        self.aborted = True
        raise TraceAbort(reason)

    def _register(self, identity):
        if self.aborted:
            raise TraceAbort("Trace has already aborted")
        _label(identity, "identity")
        if identity not in self.users:
            slot = len(self.users) + 1
            if slot > self.slots:
                self._abort("Identity-slot budget exhausted")
            active = self.bits.get(identity, (slot - 1) % 2)
            target = slot == self.guess
            # B_same has no trapdoor for the target's active branch. B_other
            # has a trapdoor for the active branch and programmes the other.
            tags = {active: not (target and self.mode == "same"), 1-active: False}
            self.users[identity] = {"slot": slot, "active_bit": active,
                "target": target, "tags": tags, "seed": f"private-seed-{slot}",
                "key": f"private-trapdoor-{slot}-{active}"}
        return self.users[identity]

    def h1(self, identity, bit):
        user = self._register(identity)
        if isinstance(bit, bool) or not isinstance(bit, int) or bit not in (0, 1):
            raise ValueError("branch must be 0 or 1")
        value = f"A*R[{identity},{bit}]" + ("+G" if user["tags"][bit] else "")
        self.events.append({"query": "H1", "identity": identity, "bit": bit, "value": value})
        return value

    def h2(self, identity, message):
        user = self._register(identity)
        _label(message, "message")
        point = (identity, message)
        if point not in self.hashes:
            if user["target"]:
                branch = user["active_bit"] if self.mode == "same" else 1-user["active_bit"]
                ref = f"hidden-reference-{len(self.references)+1}"
                self.references[point] = {"branch": branch, "vector": ref,
                    "matrix": self.h1(identity, branch)}
                value = f"F[{identity},{branch}]*{ref}"
            else:
                value = f"uniform-syndrome-{len(self.hashes)+1}"
            self.hashes[point] = value
        self.events.append({"query": "H2", "identity": identity, "message": message,
                            "value": self.hashes[point]})
        return self.hashes[point]

    def seed_oracle(self, seed, identity, message):
        user = self._register(identity)
        _label(seed, "seed")
        _label(message, "message")
        if user["target"] and seed == user["seed"]:
            self._abort("Guessed target signing seed: excluded seed-hit event")
        return self._coin(seed, identity, message)

    def _coin(self, seed, identity, message):
        point = (seed, identity, message)
        if point not in self.coins:
            self.coins[point] = f"coin-{len(self.coins)+1}"
        return self.coins[point]

    def key(self, identity):
        user = self._register(identity)
        if user["target"]:
            self._abort("Corruption of guessed target")
        self.corrupted.add(identity)
        key = {"identity": identity, "bit": user["active_bit"],
               "trapdoor": user["key"], "seed": user["seed"]}
        self.events.append({"query": "Key", **key})
        return key

    def sign(self, identity, message):
        user = self._register(identity)
        _label(message, "message")
        point = (identity, message)
        if point in self.signatures:
            return dict(self.signatures[point])
        syndrome = self.h2(identity, message)
        coin = self._coin(user["seed"], identity, message)
        if user["target"] and self.mode == "same":
            vector = self.references[point]["vector"]
            source = "programmed-reference; hidden target coins require a proof bridge"
        else:
            vector = f"SampleD({user['key']},{syndrome},{coin})"
            source = "honest-deterministic-SampleD"
        record = {"identity": identity, "message": message, "bit": user["active_bit"],
                  "vector": vector, "syndrome": syndrome, "source": source, "coin": coin}
        self.signatures[point] = record
        self.events.append({"query": "Sig", **record})
        return dict(record)

    def extraction_plan(self, identity, message, bit):
        user = self._register(identity)
        _label(message, "message")
        if isinstance(bit, bool) or not isinstance(bit, int) or bit not in (0, 1):
            raise ValueError("branch must be 0 or 1")
        self.h2(identity, message)  # Includes a never-queried final hash point.
        ref = self.references.get((identity, message))
        eligible = identity not in self.corrupted and (identity, message) not in self.signatures
        matching = bool(user["target"] and ref and bit == ref["branch"])
        return {"ordinary_UF_fresh": eligible, "guessed_target": user["target"],
                "forged_bit": bit, "reference_bit": None if ref is None else ref["branch"],
                "zero_tag_on_forged_branch": not user["tags"][bit],
                "reference_equation_matches": matching,
                "usable_if_valid_and_nonzero": eligible and matching and not user["tags"][bit],
                "cryptographic_signature_validity_checked": False}


def _vector(values, name):
    values = tuple(values)
    if not values or any(isinstance(v, bool) or not isinstance(v, int) for v in values):
        raise ValueError(f"{name} must be a nonempty integer vector")
    return values


def extraction_witness(a, r, g, reference, forged, *, q, tagged=False):
    """One-row hand-chosen algebra only; signed integers are never reduced first."""
    _integer(q, "q", minimum=2)
    a, g = _vector(a, "a"), _vector(g, "g")
    r = tuple(_vector(row, "r-row") for row in r)
    if len(r) != len(a) or any(len(row) != len(g) for row in r):
        raise ValueError("R dimensions must be len(a) by len(g)")
    reference, forged = _vector(reference, "reference"), _vector(forged, "forged")
    if len(reference) != len(a)+len(g) or len(forged) != len(reference):
        raise ValueError("Preimage dimensions mismatch")
    b = tuple((sum(a[i]*r[i][j] for i in range(len(a))) + (g[j] if tagged else 0)) % q
              for j in range(len(g)))
    f = a+b
    syndrome = lambda v: sum(x*y for x,y in zip(f,v)) % q
    delta = tuple(x-y for x,y in zip(reference,forged))
    e = tuple(delta[i]+sum(r[i][j]*delta[len(a)+j] for j in range(len(g)))
              for i in range(len(a)))
    return {"q":q, "A":list(a), "R":[list(row) for row in r], "G":list(g),
            "tagged":tagged, "F":list(f), "reference":list(reference), "forged":list(forged),
            "reference_syndrome":syndrome(reference), "forged_syndrome":syndrome(forged),
            "same_syndrome":syndrome(reference)==syndrome(forged), "e":list(e),
            "Ae_mod_q":sum(x*y for x,y in zip(a,e))%q, "e_nonzero":any(e),
            "e_norm_squared":sum(x*x for x in e),
            "frobenius_cauchy_squared_bound":(1+sum(x*x for row in r for x in row))*sum(x*x for x in delta),
            "security_claim":"none"}


def conditional_uniform_example(*, q=3):
    """Finite uniform prior on Z_q^2, conditioned on r0+r1=0.

    Not a Gaussian surrogate. It disproves a general conditional-distribution
    inference even when the image is EXACTLY uniform.
    """
    _integer(q, "q", minimum=2)
    if q > 64:
        raise ValueError("Finite enumeration limit is q<=64")
    prior = {v: Fraction(1,q*q) for v in product(range(q), repeat=2)}
    posterior = {v: Fraction(1,q) for v in prior if sum(v)%q == 0}
    return {"q":q, "prior_states":q*q, "posterior_states":q,
            "image_zero_probability":str(Fraction(1,q)), "image_is_exactly_uniform":True,
            "posterior_prior_TV":str(total_variation(prior,posterior)),
            "prior_max_atom":str(Fraction(1,q*q)), "posterior_max_atom":str(Fraction(1,q)),
            "distribution":"uniform finite counting example; NOT discrete Gaussian"}


def posterior_atom_bound(*, q, rows, normalizer_lower, relative_error):
    """Arithmetic of max rho(x)<=1 and a POINTWISE image-mass lower bound.

    The caller supplies an assumed lower bound on the unconditioned normalizer;
    this function does not evaluate a Gaussian sum or establish smoothing.
    """
    _integer(q, "q", minimum=2)
    _integer(rows, "rows", minimum=1)
    if any(isinstance(v, (bool,float)) for v in (normalizer_lower,relative_error)):
        raise ValueError("Bounds must be exact rational values")
    lower, error = Fraction(normalizer_lower), Fraction(relative_error)
    if lower <= 0 or not 0 <= error < 1:
        raise ValueError("Need positive normalizer and relative error in [0,1)")
    upper = Fraction(q ** rows)/(lower*(1-error))
    return {"max_atom_unclamped":str(upper), "max_atom_cap":str(min(Fraction(1),upper)),
            "normalizer_lower_is_assumed":True,
            "requires_pointwise_image_lower_bound":True, "security_claim":"none"}


def query_budget(*, key, sign, hash1, hash2, seed):
    """Conservative draft slots include all public seed-domain queries and Finish."""
    values = [_integer(v, "query bound") for v in (key,sign,hash1,hash2,seed)]
    slots = max(1,sum(values)+1)
    return {"K":slots, "correct_slot_probability":str(Fraction(1,slots)),
            "coarse_two_reduction_factor":2*slots, "includes_final_identity":True,
            "conditional_only":True, "security_claim":"none"}


def audit_report():
    paths = {}
    for mode in ("same", "other"):
        trace = FixedBitTrace(mode=mode,slots=4,guess=2,bits={"A":1,"B":0})
        trace.h1("A",0)  # A is first seen through a hash, not through Key/Sig.
        before = trace.h2("B","first")
        first = trace.sign("B","first")
        second = trace.sign("B","second")
        repeat = trace.sign("B","first")
        old = trace.sign("A","first")
        key = trace.key("A")
        exposed_coin = trace.seed_oracle(key["seed"],"A","first")
        plan = trace.extraction_plan("B","fresh",0 if mode=="same" else 1)
        paths[mode] = {"events":trace.events, "hash_before_sign_preserved":first["syndrome"]==before,
            "same_identity_fixed_bits":[first["bit"],second["bit"]], "repeat_is_identical":repeat==first,
            "other_user_after_corruption": {"seed_coin_matches_old_signature":exposed_coin==old["coin"],
                "signature_source":old["source"], "key_bit_matches_old_signature":key["bit"]==old["bit"]},
            "fresh_forgery_plan":plan,
            "old_message_plan":trace.extraction_plan("B","first",0 if mode=="same" else 1)}
    a,r,g = [1,2],[[1,0,2],[2,1,-1]],[1,2,4]
    reference = [1,0,1,0,0]
    pairs = [("A","first"),("A","second")]
    fixed = bit_law(pairs)
    by_message = bit_law(pairs,per_message=True)
    wrong = FixedBitTrace(mode="same",slots=2,guess=1)
    wrong.h2("A","early")
    try:
        wrong.key("A")
    except TraceAbort as exc:
        wrong_abort = str(exc)
    return {"schema_version":1, "security_claim":"none", "proof_status":"WIP conditional ROM draft",
        "method":"exact finite enumeration, symbolic lazy-oracle traces and hand-chosen integer equations",
        "monte_carlo_repetitions":0, "gaussian_samples":0, "cryptographic_signatures_generated":0,
        "bit_gap_TV":str(total_variation(fixed,by_message)), "paths":paths,
        "wrong_guess_corruption":wrong_abort,
        "zero_tag_extraction":extraction_witness(a,r,g,reference,[6,0,0,0,0],q=7),
        "tagged_branch_counterexample":extraction_witness(a,r,g,reference,[0,0,0,0,0],q=7,tagged=True),
        "conditional_entropy_counterexample":conditional_uniform_example(),
        "posterior_bound_arithmetic_example":posterior_atom_bound(q=3,rows=1,
            normalizer_lower=81,relative_error="1/4"),
        "query_example":query_budget(key=1,sign=2,hash1=3,hash2=4,seed=5),
        "limitations":["No Gaussian law, seeded-ROM bridge or sampler simulated",
            "No computational adversary, lattice-security estimate or real signature validity check",
            "Conditional reduction assumptions, error bounds and implementation admission remain open"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path)
    args = parser.parse_args()
    value = json.dumps(audit_report(),ensure_ascii=False,indent=2)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(value,encoding="utf-8",newline="\n")
    else:
        print(value,end="")


if __name__ == "__main__":
    main()
