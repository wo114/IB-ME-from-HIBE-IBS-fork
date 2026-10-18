"""Exact costs of the conditional classical SRGG strong-reduction route.

The input advantage and complete simulation distance are hypotheses.  This
module does not prove that a real IBS game has that distance, instantiate a
hardness assumption, implement a forgery, or establish a QROM/NIST claim.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path


SCHEMA = "IBME/SRGG-CONDITIONAL-CLASSICAL-REDUCTION-COST/1"
DEFAULT_INPUT = Path("docs/research/team-b-delivery/2026-10-16-srgg-reduction/native-sig.json")


def _count(value, name, minimum=0):
    if type(value) is not int or not minimum <= value <= 2**64:
        raise ValueError("bounded exact integer required: " + name)
    return value


def _prob(value, name):
    if type(value) not in (int, Fraction, str):
        raise ValueError("exact rational probability required: " + name)
    try:
        value = Fraction(value)
    except (ValueError, ZeroDivisionError) as exc:
        raise ValueError("exact rational probability required: " + name) from exc
    if not 0 <= value <= 1 or max(value.numerator.bit_length(), value.denominator.bit_length()) > 8192:
        raise ValueError("probability range or resource limit violated: " + name)
    return value


def _degree(value):
    if type(value) is not int or not 2 <= value <= 4096 or value & (value-1):
        raise ValueError("bounded power-of-two degree required")
    return value


def owner_fork_cost(*, advantage, free_queries, degree, simulation_tv=0):
    """Apply strong-games.md sections 5.2/8.1 under their stated premises.

    q counts every free H2 entry of the replayable machine, including its
    internal known-key computations. Sign-owned entries must have a valid
    signature actually returned for this same fixed target public key.
    """
    epsilon = _prob(advantage, "assumed fixed-key adversary advantage")
    delta = _prob(simulation_tv, "assumed complete simulation distance")
    q = _count(free_queries, "free H2 entries", 1)
    n = _degree(degree)
    guess, kappa = Fraction(1, 2**n), Fraction(1, 2**(n//2))
    t = max(Fraction(0), epsilon-delta-guess)
    lower = max(Fraction(0), t*t/(8*q)-t*kappa/4)
    return {"assumed_fixed_key_advantage_exact": str(epsilon),
        "assumed_complete_simulation_tv_upper_exact": str(delta),
        "free_H2_entry_bound": q, "degree": n,
        "unqueried_full_challenge_guess_upper_exact": str(guess),
        "same_effective_challenge_unconditioned_upper_exact": str(kappa),
        "residual_owner_success_lower_exact": str(t),
        "fair_owner_solver_short_kernel_success_lower_exact": str(lower),
        "positive_conditional_lower_bound": lower > 0,
        "meaning": "conditional extraction probability, not a security advantage upper bound",
        "actual_IBS_simulation_distance_established": False,
        "actual_matrix_hardness_established": False, "QROM_reduction_established": False}


def programming_collision_cost(*, signing_queries, max_sign_attempts,
        free_entries, commitment_bits):
    """Conservative union bound using ideal full-cap commitment entropy.

    A complete classical simulation must justify using this ledger. Finite
    sampler TV is paid once in a whole-game hybrid, never once per RO point.
    At most 512 certified bits are retained to keep exact fractions small.
    """
    qs = _count(signing_queries, "signing queries")
    attempts = _count(max_sign_attempts, "maximum attempts", 1)
    if attempts > 2**16:
        raise ValueError("attempt resource limit exceeded")
    qh = _count(free_entries, "free H2 entries")
    if type(commitment_bits) is not int or not 0 <= commitment_bits <= 2**24:
        raise ValueError("bounded certified commitment bit count required")
    bits = min(commitment_bits, 512)
    point_count = qh+qs*attempts
    bound = min(Fraction(1), Fraction(qs*attempts*point_count, 2**bits))
    return {"signing_queries": qs, "maximum_sign_attempts": attempts,
        "free_H2_entries": qh, "table_points_bound": point_count,
        "certified_ideal_commitment_bits": commitment_bits,
        "arithmetic_commitment_bits_used": bits,
        "conditional_programming_collision_upper_exact": str(bound),
        "finite_sampler_TV_multiplied_by_table_size": False,
        "whole_game_simulation_proved_here": False}


def build_report(input_path=DEFAULT_INPUT):
    path = Path(input_path)
    data = path.read_bytes()
    source = json.loads(data)
    if source.get("schema") != "IBME/SRGG-NATIVE-SIG-INTERACTIVE-BRIDGE/1":
        raise ValueError("known native interactive bridge schema required")
    profiles = []
    for profile in source["profiles"]:
        p = profile["parameters"]
        entropy = profile["full_cap_ideal_commitment_entropy"]
        if entropy["entropy_certificate_available"] is not True:
            raise ValueError("nonvacuous full-cap ideal commitment certificate required")
        scenarios = []
        for ledger in profile["conditional_statistical_ledgers"]:
            qs = ledger["signing_queries"]
            # This is an illustrative free-entry budget, not a measured count
            # or an automatic bound on internal known-key computations.
            qh = max(1, qs)
            collision = programming_collision_cost(signing_queries=qs,
                max_sign_attempts=p["sign_max_attempts"], free_entries=qh,
                commitment_bits=entropy["ideal_commitment_min_entropy_bits_lower"])
            assumed_delta = min(Fraction(1), Fraction(ledger["total_upper_exact"])
                + Fraction(collision["conditional_programming_collision_upper_exact"]))
            scenarios.append({"counted_issuances": ledger["counted_issuances"],
                "signing_queries": qs, "illustrative_free_H2_entries": qh,
                "conditional_statistical_tv_premise_exact": ledger["total_upper_exact"],
                "collision": collision,
                "total_distance_is_a_composition_hypothesis": True,
                "fixed_key_advantage_scenarios": [owner_fork_cost(
                    advantage=Fraction(1, 2**bits), free_queries=qh,
                    degree=p["degree"], simulation_tv=assumed_delta)
                    for bits in (0, 64, 96, 128)]})
        profiles.append({"profile": profile["profile"], "scenarios": scenarios})
    return {"schema": SCHEMA, "input_path": path.as_posix(),
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "source_sha256": {"experiments/research/candidates/srgg/classical_cost.py":
            hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
        "profiles": profiles, "actual_entropy_bytes": 0,
        "scope": "conditional classical fixed-key costs; no IBS-to-SIG loss hidden in epsilon",
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = build_report(args.input)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
