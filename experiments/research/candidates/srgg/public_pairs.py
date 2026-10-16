"""Exact finite SRGG public-pair model with latent raw-norm failures.

The raw variable must survive until its gate: canonical head repair can merge
raw vectors with different norms. This module retains h on failure and never
conditions on successful issuance. It is finite probability evidence, not an
efficient Gaussian sampler or an IBS security proof.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
from itertools import product
import json
from pathlib import Path

from . import mixed_domain as md


SCHEMA = "IBME/SRGG-LATENT-PUBLIC-PAIRS/1"


def _add(law, atom, mass):
    if mass:
        law[atom] = law.get(atom, Fraction(0))+mass


def _gates(raw, repaired, raw_cap, user_cap):
    return (sum(x*x for x in raw) <= raw_cap
            and sum(x*x for x in repaired) <= user_cap)


def latent_pair_law(raw_domain, a, *, p, modulus):
    """Return law of (h,U,E,Y), before either norm gate, h=AY mod Q."""
    raw, dimension = md._law(raw_domain)
    head, q = md._layout(a, dimension, modulus)
    md._int(p, "p", 1, q)
    if len(raw)*p**head > md.MAX_STATES:
        raise ValueError("latent pair enumeration resource limit exceeded")
    result = {}
    for u, mass in raw.items():
        for e in product(range(p), repeat=head):
            y = md._repair(u, e, q)
            h = md._forward(a, y, q)
            _add(result, (h, u, e, y), mass/Fraction(p**head))
    return result


def gated_public_pair_law(raw_domain, a, *, p, modulus,
                          raw_norm_cap, user_norm_cap):
    """Sample globally, set h before gates, emit (h,Y) or (h,bottom)."""
    raw_cap = md._int(raw_norm_cap, "raw squared norm cap", 0, 2**256)
    user_cap = md._int(user_norm_cap, "user squared norm cap", 0, 2**256)
    result = {}
    for (h, u, _e, y), mass in latent_pair_law(
            raw_domain, a, p=p, modulus=modulus).items():
        key = y if _gates(u, y, raw_cap, user_cap) else None
        _add(result, (h, key), mass)
    return result


def conditional_issuer_law(raw_domain, a, target, *, p, modulus,
                           raw_norm_cap, user_norm_cap):
    """Independently condition raw U on S_h, then repair and apply both gates.

    Return the key-or-bottom law and Pr[U in S_h]. No rejection renormalization
    occurs after the gates. A zero-probability fiber has no conditional law.
    """
    raw, dimension = md._law(raw_domain)
    head, q = md._layout(a, dimension, modulus)
    md._int(p, "p", 1, q)
    h = md._target(target, head, q)
    raw_cap = md._int(raw_norm_cap, "raw squared norm cap", 0, 2**256)
    user_cap = md._int(user_norm_cap, "user squared norm cap", 0, 2**256)
    result, total = {}, Fraction(0)
    for u, mass in raw.items():
        au = md._forward(a, u, q)
        e = tuple((x-y) % q for x, y in zip(h, au))
        if any(x >= p for x in e):
            continue
        y = md._repair(u, e, q)
        key = y if _gates(u, y, raw_cap, user_cap) else None
        _add(result, key, mass)
        total += mass
    if not total:
        raise ValueError("zero-probability conditional fiber")
    return {key: mass/total for key, mass in result.items()}, total


def total_variation(first, second):
    """Exact TV on finite normalized laws; atoms may contain explicit bottom."""
    for law in (first, second):
        if not isinstance(law, dict) or not 1 <= len(law) <= md.MAX_STATES:
            raise ValueError("bounded normalized finite law required")
        if sum((md._prob(p, "mass") for p in law.values()), Fraction(0)) != 1:
            raise ValueError("normalized finite law required")
    return sum((abs(first.get(k, 0)-second.get(k, 0))
                for k in first.keys() | second.keys()), Fraction(0))/2


def compare_public_and_uniform_pairs(raw_domain, a, *, p, modulus,
                                      raw_norm_cap, user_norm_cap):
    """Verify conditional equality and exact TV=image TV, for full support.

    With h retained, TV(uniform(h)*K_h, image(h)*K_h) is exactly the TV of
    the h marginals, even when K_h contains bottom. Missing fibers raise;
    they are not filled with an invented conditional key law.
    """
    raw, dimension = md._law(raw_domain)
    head, q = md._layout(a, dimension, modulus)
    if q**head > md.MAX_STATES:
        raise ValueError("target enumeration resource limit exceeded")
    options = dict(p=p, modulus=q, raw_norm_cap=raw_norm_cap,
                   user_norm_cap=user_norm_cap)
    public = gated_public_pair_law(raw, a, **options)
    image, honest = {}, {}
    for (h, _key), mass in public.items():
        _add(image, h, mass)
    uniform = {h: Fraction(1, q**head) for h in product(range(q), repeat=head)}
    for h, probability in uniform.items():
        conditional, union_mass = conditional_issuer_law(raw, a, h, **options)
        if union_mass != p**head*image.get(h, 0):
            raise ArithmeticError("latent conditional mass identity failed")
        expected = {key: mass/image[h] for (target, key), mass in public.items()
                    if target == h}
        if expected != conditional:
            raise ArithmeticError("latent conditional key/abort laws disagree")
        for key, mass in conditional.items():
            _add(honest, (h, key), probability*mass)
    distance = total_variation(public, honest)
    image_distance = total_variation(image, uniform)
    if distance != image_distance:
        raise ArithmeticError("retained-h total variation identity failed")
    return {"conditional_key_and_abort_laws_identical": True,
        "joint_pair_tv_exact": str(distance),
        "image_tv_to_uniform_exact": str(image_distance),
        "target_count": q**head,
        "public_abort_probability_exact": str(sum(
            mass for (_h, key), mass in public.items() if key is None)),
        "uniform_target_abort_probability_exact": str(sum(
            mass for (_h, key), mass in honest.items() if key is None)),
        "both_gates_applied_before_discarding_latent_U": True,
        "failed_pair_retains_its_H1_target": True,
        "global_success_conditioning_used": False}


def build_report():
    examples = []
    for q, head, a, raw in (
        (3, 1, ((1, 2),), {(0, 0): Fraction(1, 2),
                           (3, 0): Fraction(1, 3), (1, 1): Fraction(1, 6)}),
        (4, 2, ((1, 0, 1), (0, 1, 3)),
         {(0, 0, 0): Fraction(1, 2), (4, -4, 1): Fraction(1, 2)}),
    ):
        for caps in ((0, 0), (1, 3), (100, 100)):
            examples.append({"Q": q, "head": head, "p": q,
                "raw_norm_cap": caps[0], "user_norm_cap": caps[1],
                **compare_public_and_uniform_pairs(raw, a, p=q, modulus=q,
                    raw_norm_cap=caps[0], user_norm_cap=caps[1])})
    # Full-support, genuinely nonuniform h marginal, including bottom.
    examples.append({"Q": 3, "head": 1, "p": 1,
        "raw_norm_cap": 1, "user_norm_cap": 1,
        **compare_public_and_uniform_pairs(
            {(0,): Fraction(1, 2), (1,): Fraction(1, 3), (2,): Fraction(1, 6)},
            ((1,),), p=1, modulus=3, raw_norm_cap=1, user_norm_cap=1)})
    counterexample = gated_public_pair_law({(0,): Fraction(1, 2),
        (3,): Fraction(1, 2)}, ((1,),), p=1, modulus=3,
        raw_norm_cap=0, user_norm_cap=0)
    return {"schema": SCHEMA,
        "source_sha256": {"experiments/research/candidates/srgg/"+name:
            hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in ("public_pairs.py", "mixed_domain.py")},
        "finite_public_examples": examples,
        "raw_gate_is_not_a_Y_predicate_counterexample": {
            "Q": 3, "p": 1, "raw_atoms": [[0], [3]],
            "both_repair_to_Y": [0], "raw_and_user_norm_caps": 0,
            "honest_abort_probability_exact": str(counterexample[((0,), None)]),
            "Y_only_norm_gate_abort_probability_exact": "0"},
        "scope": "finite latent law identity and counterexample; no Gaussian sampler",
        "actual_entropy_bytes": 0, "actual_IBS_reduction_established": False,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(build_report(), indent=2)+"\n",
                           encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
