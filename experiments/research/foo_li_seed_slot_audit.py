"""Exact finite controls for Foo-Li's classical hidden-seed and target-slot lemmas.

The oracle outputs are single bits and signatures reveal a toy random-tape bit.
No lattice, Gaussian sampler, actual IBS signature or security estimate is used.
The probability controls accompany, and do not replace, the written proof.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass, replace
from fractions import Fraction
from itertools import product
import json
from pathlib import Path


def _natural(value, name, minimum=0):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value


def classical_seed_budget(*, ell, q1, q2, q3):
    """Union bound for three independent oracle domains with hidden seed prefixes."""
    _natural(ell, "ell", 1)
    if ell > 4096:
        raise ValueError("Finite arithmetic resource limit is ell<=4096")
    total = sum(_natural(v, "query budget") for v in (q1, q2, q3))
    return min(Fraction(1), Fraction(total, 2**ell))


@dataclass(frozen=True)
class _World:
    target_seed: int
    other_seed: int
    table: dict
    view: tuple = ()
    bad: bool = False


def _step(states, point, label, *, external=False):
    """Exhaust all fresh oracle output bits instead of Monte Carlo sampling."""
    result = []
    for world, probability in states:
        key = point(world)
        bad = world.bad or (external and key[1] == world.target_seed)
        values = (world.table[key],) if key in world.table else (0, 1)
        for value in values:
            table = dict(world.table)
            table[key] = value
            result.append((replace(world, table=table, bad=bad,
                view=world.view+((label,value),)), probability/len(values)))
    return result


def _seed_worlds(seed_space, *, ideal, replace_exposed_other=False):
    states = [(_World(a,b,{}), Fraction(1,seed_space**2))
              for a,b in product(range(seed_space), repeat=2)]
    states = _step(states, lambda w: ("RO",0,"target","old"),
                   "before-sign", external=True)
    target = lambda w: (("private-ideal", "target", "old") if ideal else
                        ("RO",w.target_seed,"target","old"))
    other = lambda w: (("wrong-independent", "other", "old") if replace_exposed_other else
                       ("RO",w.other_seed,"other","old"))
    states = _step(states,target,"target-sign")
    states = _step(states,other,"other-sign")
    states = [(replace(w,view=w.view+(("other-key-seed",w.other_seed),)),p)
              for w,p in states]
    # This can hit the hidden target through a collision of independent seeds.
    states = _step(states,lambda w: ("RO",w.other_seed,"target","old"),
                   "after-other-key",external=True)
    states = _step(states,lambda w: ("RO",w.other_seed,"other","old"),
                   "recomputed-other",external=True)
    states = _step(states,target,"target-repeat")
    def adaptive(w):
        observed = dict(w.view)
        guess = (w.other_seed+observed["before-sign"]+observed["target-sign"]+1)%seed_space
        return ("RO",guess,"target","fresh")
    states = _step(states,adaptive,"adaptive-before-new-sign",external=True)
    states = _step(states,lambda w: (("private-ideal", "target", "fresh") if ideal else
                   ("RO",w.target_seed,"target","fresh")),"target-new-sign")
    return states


def _law(states, *, include_hidden=False):
    law = defaultdict(Fraction)
    for world,p in states:
        value = (world.target_seed,world.view) if include_hidden else world.view
        law[value] += p
    return dict(law)


def _tv(left,right):
    return sum((abs(left.get(x,0)-right.get(x,0))
                for x in left.keys() | right.keys()),Fraction())/2


def seed_bridge_control(seed_space=8):
    _natural(seed_space,"seed_space",2)
    if seed_space > 16 or seed_space & (seed_space-1):
        raise ValueError("Exhaustive seed space must be a power of two <=16")
    real = _seed_worlds(seed_space,ideal=False)
    ideal = _seed_worlds(seed_space,ideal=True)
    wrong = _seed_worlds(seed_space,ideal=True,replace_exposed_other=True)
    def consistency(states):
        return sum((p for w,p in states
            if dict(w.view)["other-sign"]==dict(w.view)["recomputed-other"]),Fraction())
    return {"seed_space":seed_space,"ell":seed_space.bit_length()-1,
        "external_Hcal3_queries":4,
        "public_view_TV":str(_tv(_law(real),_law(ideal))),
        "view_and_hidden_seed_TV":str(_tv(_law(real,include_hidden=True),
                                            _law(ideal,include_hidden=True))),
        "ideal_prefix_hit_probability":str(sum((p for w,p in ideal if w.bad),Fraction())),
        "conservative_query_bound":str(min(Fraction(1),Fraction(4,seed_space))),
        "real_other_recomputation":str(consistency(real)),
        "correct_ideal_other_recomputation":str(consistency(ideal)),
        "wrong_ideal_other_recomputation":str(consistency(wrong)),
        "wrong_all_signatures_TV":str(_tv(_law(real),_law(wrong))),
        "real_total_probability":str(sum((p for _,p in real),Fraction())),
        "ideal_total_probability":str(sum((p for _,p in ideal),Fraction())),
        "real_leaf_states":len(real),"ideal_leaf_states":len(ideal),
        "model":"one-bit oracle and one-bit toy signing tape; not an IBS sampler",
        "security_claim":"none"}


def adaptive_slot_control():
    """Independent exhaustive reference/stopped executions with adaptive final ID.

    A is first seen via H2, B via Key or Sig, C via a public seed-domain query.
    The final identity is B or a never-seen D, depending on the probe bit.
    All forgery-validity predicates are stipulated, not cryptographically tested.
    """
    k = 4
    success = defaultdict(Fraction)
    joint = defaultdict(Fraction)
    stopped_joint = defaultdict(Fraction)
    wrong_guess_aborts = Fraction()
    final_slots = set()
    for x,b_a,b_b,b_c,b_d in product((0,1),repeat=5):
        p = Fraction(1,32)
        operations = [("H2","A"),("Key" if x==0 else "Sig","B"),
                      ("Hcal3","C")]
        final = "D" if x==0 else "B"
        active = b_d if final=="D" else b_b
        forged = 0 if final=="D" else 1-b_b
        event = "same" if forged==active else "other"
        # A successful final message is fresh even if B has an earlier signature.
        order = list(dict.fromkeys([identity for _,identity in operations]+[final]))
        final_slot = order.index(final)+1
        final_slots.add(final_slot)
        success[event] += p
        for g in range(1,k+1):
            weight = p/k
            target = order[g-1] if g<=len(order) else None
            abort = any(op=="Key" and identity==target for op,identity in operations)
            if abort:
                wrong_guess_aborts += weight
            if g==final_slot:
                joint[event] += weight
                if not abort:
                    stopped_joint[event] += weight
    return {"K":k,"full_reference_success":{e:str(success[e]) for e in ("same","other")},
        "correct_guess_joint":{e:str(joint[e]) for e in ("same","other")},
        "after_target_Key_abort":{e:str(stopped_joint[e]) for e in ("same","other")},
        "wrong_guess_abort_probability":str(wrong_guess_aborts),
        "adaptive_final_slots":sorted(final_slots),
        "hash_and_seed_only_identities_registered":True,
        "final_never_seen_identity_registered":True,
        "signature_validity_checked":False,"security_claim":"none"}


def audit_report():
    return {"schema_version":1,"security_claim":"none",
        "proof_scope":"finite controls for two written classical-ROM lemmas",
        "seed_control":seed_bridge_control(),"slot_control":adaptive_slot_control(),
        "monte_carlo_repetitions":0,"gaussian_samples":0,"real_signatures":0,
        "limitations":["No TrapGen, DelTrap, perturbation or SampleD implemented",
            "Finite seed control covers Hcal3 only; the two master domains are handled by the written lemma",
            "Toy exhaustive controls are not a security proof or lattice parameter estimate",
            "Full-key target corruption is excluded by ordinary UF; other users remain corruptible"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path)
    args = parser.parse_args()
    value=json.dumps(audit_report(),ensure_ascii=False,indent=2)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(value,encoding="utf-8",newline="\n")
    else:
        print(value,end="")


if __name__=="__main__":
    main()
