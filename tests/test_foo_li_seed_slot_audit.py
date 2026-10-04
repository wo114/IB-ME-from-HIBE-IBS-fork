"""Exact probability controls independent of cryptographic implementation."""

from fractions import Fraction
import json

import pytest

from experiments.research.foo_li_seed_slot_audit import (
    adaptive_slot_control, classical_seed_budget, seed_bridge_control,
)


@pytest.mark.parametrize("space",[2,4,8])
def test_hidden_seed_joint_distance_and_adaptive_prefix_hits(space):
    c=seed_bridge_control(space)
    public,joint,bad,bound=map(Fraction,(c["public_view_TV"],c["view_and_hidden_seed_TV"],
        c["ideal_prefix_hit_probability"],c["conservative_query_bound"]))
    assert 0<public<=joint<=bad<=bound
    assert c["real_total_probability"]==c["ideal_total_probability"]=="1"
    assert c["real_other_recomputation"]==c["correct_ideal_other_recomputation"]=="1"
    assert c["wrong_ideal_other_recomputation"]=="1/2"
    assert Fraction(c["wrong_all_signatures_TV"])>=Fraction(1,2)


def test_revealed_target_seed_does_not_satisfy_hidden_prefix_bound():
    # Independent two-bit enumeration: an exposed seed lets an adversary query
    # the exact old signing point. Real coins agree always; ideal coins agree 1/2.
    real={(0,0):Fraction(1,2),(1,1):Fraction(1,2)}
    ideal={(a,b):Fraction(1,4) for a in (0,1) for b in (0,1)}
    tv=sum(abs(real.get(v,0)-ideal[v]) for v in ideal)/2
    assert tv==Fraction(1,2)>classical_seed_budget(ell=3,q1=0,q2=0,q3=1)
    # Ordinary UF excludes the corrupted target; this is the non-target control
    # showing why its real seeded deterministic sampler must stay unchanged.


def test_adaptive_identity_and_branch_partition_preserves_one_over_K_exactly():
    c=adaptive_slot_control()
    assert c["K"]==4 and c["adaptive_final_slots"]==[2,4]
    assert c["full_reference_success"]=={"same":"1/4","other":"3/4"}
    assert c["correct_guess_joint"]=={"same":"1/16","other":"3/16"}
    assert c["after_target_Key_abort"]==c["correct_guess_joint"]
    assert c["wrong_guess_abort_probability"]=="1/8"
    assert c["hash_and_seed_only_identities_registered"]
    assert not c["signature_validity_checked"]
    for event in ("same","other"):
        assert Fraction(c["correct_guess_joint"][event])==Fraction(c["full_reference_success"][event])/4


@pytest.mark.parametrize("queries",[(0,0,0),(1,2,3),(8,8,8),(0,0,30)])
def test_three_domain_bound_counts_external_queries_and_caps_probability(queries):
    assert classical_seed_budget(ell=4,q1=queries[0],q2=queries[1],q3=queries[2])==min(
        Fraction(1),Fraction(sum(queries),16))


@pytest.mark.parametrize("kwargs",[dict(ell=0),dict(ell=True),dict(ell=4097),
    dict(q1=-1),dict(q2=0.0),dict(q3=True)])
def test_invalid_seed_budget_is_not_certified(kwargs):
    args=dict(ell=4,q1=1,q2=2,q3=3)
    args.update(kwargs)
    with pytest.raises(ValueError):
        classical_seed_budget(**args)


@pytest.mark.parametrize("space",[1,3,32,True,4.0])
def test_enumeration_resource_limits_are_explicit(space):
    with pytest.raises(ValueError):
        seed_bridge_control(space)


def test_finite_control_metadata_does_not_claim_cryptographic_validation():
    c=json.loads(json.dumps(adaptive_slot_control()))
    assert c["security_claim"]=="none" and not c["signature_validity_checked"]
