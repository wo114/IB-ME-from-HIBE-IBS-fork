"""Independent controls for a proof draft, not cryptographic security tests."""

from fractions import Fraction
from itertools import product
import json
from pathlib import Path
import runpy

import pytest


AUDIT = runpy.run_path(str(Path(__file__).resolve().parents[1] /
                          "experiments/research/foo_li_fixed_key_audit.py"))
Trace, Abort = AUDIT["FixedBitTrace"], AUDIT["TraceAbort"]
witness = AUDIT["extraction_witness"]


def test_original_two_bit_joint_gap_is_exact_despite_equal_marginals():
    pairs = [("A","one"),("A","two")]
    fixed = AUDIT["bit_law"](pairs)
    independent = AUDIT["bit_law"](pairs,per_message=True)
    assert fixed == {(0,0):Fraction(1,2),(1,1):Fraction(1,2)}
    assert independent == {v:Fraction(1,4) for v in product((0,1),repeat=2)}
    assert AUDIT["total_variation"](fixed,independent) == Fraction(1,2)
    for law in (fixed,independent):
        assert sum(p for v,p in law.items() if v[0]==0) == Fraction(1,2)


@pytest.mark.parametrize("pairs",[[],[("A","one")],[("A","one"),("A","one")],
                                  [("A","one"),("B","one")]])
def test_bit_controls_do_not_have_the_same_user_new_message_gap(pairs):
    left = AUDIT["bit_law"](pairs)
    right = AUDIT["bit_law"](pairs,per_message=True)
    assert sum(left.values()) == sum(right.values()) == 1
    assert AUDIT["total_variation"](left,right) == 0


@pytest.mark.parametrize("mode",["same","other"])
@pytest.mark.parametrize("active",[0,1])
def test_target_hash_before_sign_fixed_bit_and_new_forgery_branch(mode,active):
    t = Trace(mode=mode,slots=3,guess=2,bits={"target":active})
    t.h1("hash-only-user",1)
    before = t.h2("target","one")
    first,second = t.sign("target","one"),t.sign("target","two")
    assert t.users["hash-only-user"]["slot"] == 1 and t.users["target"]["slot"] == 2
    assert first["syndrome"] == before and t.h2("target","one") == before
    assert first["bit"] == second["bit"] == active
    assert t.sign("target","one") == first
    branch = active if mode=="same" else 1-active
    plan = t.extraction_plan("target","fresh",branch)
    assert plan["usable_if_valid_and_nonzero"] and plan["zero_tag_on_forged_branch"]
    assert not plan["cryptographic_signature_validity_checked"]
    assert not t.extraction_plan("target","fresh",1-branch)["reference_equation_matches"]
    assert not t.extraction_plan("target","one",branch)["ordinary_UF_fresh"]
    if mode=="same":
        assert first["vector"] == t.references[("target","one")]["vector"]
    else:
        assert first["source"] == "honest-deterministic-SampleD"
        assert t.users["target"]["tags"][active]
        assert first["vector"] != t.references[("target","one")]["vector"]


@pytest.mark.parametrize("mode",["same","other"])
def test_sign_then_corrupt_exposes_coins_that_recompute_the_original_signature(mode):
    t = Trace(mode=mode,slots=3,guess=2,bits={"other":1})
    old = t.sign("other","one")
    t.sign("target","one")
    key = t.key("other")
    coin = t.seed_oracle(key["seed"],"other","one")
    assert coin == old["coin"] and key["bit"] == old["bit"] == 1
    assert old["source"] == "honest-deterministic-SampleD"
    # A later seed/key disclosure must preserve this exact deterministic call,
    # not merely its marginal Gaussian distribution.
    expected = f"SampleD({key['trapdoor']},{old['syndrome']},{coin})"
    assert old["vector"] == expected
    assert t.sign("other","one") == old and t.key("other") == key
    new = t.sign("other","two")
    assert new["coin"] != old["coin"] and new["source"] == old["source"]
    assert not t.extraction_plan("other","fresh",1)["ordinary_UF_fresh"]


def test_seed_query_before_signature_and_key_disclosure_uses_the_same_coin():
    t = Trace(mode="same",slots=3,guess=3)
    t.h1("other",0)
    key = t.key("other")
    before = t.seed_oracle(key["seed"],"other","future")
    assert t.sign("other","future")["coin"] == before
    # Distinct tuple inputs cannot alias via an ambiguous concatenation.
    assert t.seed_oracle("ab","c","d") != t.seed_oracle("a","bc","d")


def test_public_seed_domain_queries_also_register_identity_slots():
    t = Trace(mode="same",slots=3,guess=2)
    t.seed_oracle("a-wrong-seed","first","one")
    t.h2("second","one")
    assert t.users["second"]["slot"] == 2 and t.users["second"]["target"]


@pytest.mark.parametrize("mode",["same","other"])
def test_wrong_guess_can_abort_on_corruption_after_hash_and_signature(mode):
    t = Trace(mode=mode,slots=2,guess=1)
    t.h2("A","earlier")
    t.sign("A","one")
    with pytest.raises(Abort,match="Corruption"):
        t.key("A")
    with pytest.raises(Abort,match="already aborted"):
        t.sign("B","one")


@pytest.mark.parametrize("mode",["same","other"])
def test_guessed_target_seed_hit_is_an_explicit_bad_event(mode):
    t = Trace(mode=mode,slots=1,guess=1)
    t.h1("A",0)
    with pytest.raises(Abort,match="seed-hit"):
        t.seed_oracle(t.users["A"]["seed"],"A","one")


def test_unqueried_final_identity_is_included_in_the_guess_budget():
    t = Trace(mode="same",slots=2,guess=2)
    t.key("other")
    final = t.extraction_plan("never-seen","new",1)
    assert final["usable_if_valid_and_nonzero"]
    b = AUDIT["query_budget"](key=1,sign=2,hash1=3,hash2=4,seed=5)
    assert b["K"] == 16 and b["correct_slot_probability"] == "1/16"
    assert b["coarse_two_reduction_factor"] == 32 and b["conditional_only"]
    zero = AUDIT["query_budget"](key=0,sign=0,hash1=0,hash2=0,seed=0)
    assert zero["K"] == 1


def test_slot_budget_cannot_be_silently_extended():
    t = Trace(mode="same",slots=1,guess=1)
    t.h2("A","one")
    with pytest.raises(Abort,match="budget"):
        t.h1("B",0)


def test_zero_tag_extraction_and_failed_tagged_shortcut_are_independent_equations():
    a,r,g = [1,2],[[1,0,2],[2,1,-1]],[1,2,4]
    first = witness(a,r,g,[1,0,1,0,0],[6,0,0,0,0],q=7)
    assert first["F"] == [1,2,5,2,0] and first["reference_syndrome"] == 6
    assert first["same_syndrome"] and first["e"] == [-4,2]
    assert first["Ae_mod_q"] == 0 and first["e_nonzero"] and first["e_norm_squared"] == 20
    tagged = witness(a,r,g,[1,0,1,0,0],[0,0,0,0,0],q=7,tagged=True)
    assert tagged["F"] == [1,2,6,4,4] and tagged["same_syndrome"]
    assert tagged["e"] == [2,2] and tagged["Ae_mod_q"] == 6
    # The correct tagged equation has an additional G*delta_child term.
    assert (tagged["Ae_mod_q"]+1)%7 == 0
    for case in (first,tagged):
        assert case["e_norm_squared"] <= case["frobenius_cauchy_squared_bound"]


def test_exhaustive_small_zero_tag_differences_project_to_the_A_kernel():
    a,r,g = [1,2],[[1,0,2],[2,1,-1]],[1,2,4]
    count = 0
    for delta in product(range(-1,2),repeat=5):
        if sum(x*y for x,y in zip([1,2,5,2,0],delta))%7:
            continue
        result = witness(a,r,g,delta,[0]*5,q=7)
        assert result["same_syndrome"] and result["Ae_mod_q"] == 0
        assert result["e_norm_squared"] <= result["frobenius_cauchy_squared_bound"]
        count += 1
    assert count > 20


def test_nonzero_vector_difference_alone_does_not_prove_nonzero_extraction():
    result = witness([1,2],[[1,0,2],[2,1,-1]],[1,2,4],[-1,-2,1,0,0],[0]*5,q=7)
    assert result["reference"] != result["forged"] and result["same_syndrome"]
    assert result["e"] == [0,0] and not result["e_nonzero"]


def test_total_verification_norm_does_not_imply_each_block_has_a_smaller_bound():
    d = [2,0,0,0]
    assert sum(x*x for x in d) <= 4  # s'=1, m+w=4
    assert sum(x*x for x in d[:2]) > 2  # Exceeds s'^2*m.


@pytest.mark.parametrize("q",[2,3,5,7])
def test_uniform_image_does_not_leave_the_conditioned_prior_unchanged(q):
    example = AUDIT["conditional_uniform_example"](q=q)
    assert example["image_is_exactly_uniform"] and example["posterior_states"] == q
    assert Fraction(example["posterior_prior_TV"]) == 1-Fraction(1,q)
    assert Fraction(example["posterior_max_atom"]) == q*Fraction(example["prior_max_atom"])


def test_pointwise_posterior_bound_matches_finite_counting_and_nonzero_error_arithmetic():
    for q in (2,3,5,7):
        bound = AUDIT["posterior_atom_bound"](q=q,rows=1,normalizer_lower=q*q,relative_error=0)
        assert Fraction(bound["max_atom_cap"]) == Fraction(1,q)
    assumed = AUDIT["posterior_atom_bound"](q=3,rows=1,normalizer_lower=81,relative_error="1/4")
    assert assumed["max_atom_unclamped"] == "4/81"
    assert assumed["requires_pointwise_image_lower_bound"] and assumed["normalizer_lower_is_assumed"]
    vacuous = AUDIT["posterior_atom_bound"](q=7,rows=1,normalizer_lower=1,relative_error="1/2")
    assert vacuous["max_atom_unclamped"] == "14" and vacuous["max_atom_cap"] == "1"


@pytest.mark.parametrize("kwargs",[dict(q=3,rows=0,normalizer_lower=9,relative_error=0),
    dict(q=3,rows=1,normalizer_lower=0,relative_error=0),
    dict(q=3,rows=1,normalizer_lower=9,relative_error=1),
    dict(q=3,rows=1,normalizer_lower=9,relative_error=0.0)])
def test_posterior_bound_rejects_missing_or_inexact_hypotheses(kwargs):
    with pytest.raises(ValueError):
        AUDIT["posterior_atom_bound"](**kwargs)


@pytest.mark.parametrize("kwargs",[dict(mode="unknown",slots=1,guess=1),
    dict(mode="same",slots=0,guess=1),dict(mode="same",slots=1,guess=2),
    dict(mode="same",slots=True,guess=1),dict(mode="same",slots=1,guess=1,bits={"A":0.0})])
def test_invalid_trace_setup_is_rejected(kwargs):
    with pytest.raises(ValueError):
        Trace(**kwargs)


@pytest.mark.parametrize("bit",[-1,2,True,0.0,"0"])
def test_invalid_branch_is_rejected(bit):
    t = Trace(mode="same",slots=1,guess=1)
    with pytest.raises(ValueError):
        t.h1("A",bit)


def test_invalid_integer_dimensions_and_query_bounds_are_rejected():
    with pytest.raises(ValueError,match="dimensions"):
        witness([1,2],[[1]],[1,2],[1,2,3,4],[0]*4,q=7)
    with pytest.raises(ValueError):
        witness([1],[[1]],[1],[0,0],[0,0],q=True)
    with pytest.raises(ValueError):
        AUDIT["query_budget"](key=-1,sign=0,hash1=0,hash2=0,seed=0)
    with pytest.raises(ValueError):
        AUDIT["bit_law"]([(str(i),"one") for i in range(17)])


def test_report_serializes_and_keeps_limitations_and_negative_controls():
    report = json.loads(json.dumps(AUDIT["audit_report"]()))
    assert report["security_claim"] == "none" and report["gaussian_samples"] == 0
    assert report["cryptographic_signatures_generated"] == report["monte_carlo_repetitions"] == 0
    assert report["proof_status"].startswith("WIP")
    for path in report["paths"].values():
        assert path["hash_before_sign_preserved"] and path["repeat_is_identical"]
        assert path["other_user_after_corruption"]["seed_coin_matches_old_signature"]
        assert path["fresh_forgery_plan"]["usable_if_valid_and_nonzero"]
        assert not path["old_message_plan"]["ordinary_UF_fresh"]
    assert report["tagged_branch_counterexample"]["Ae_mod_q"] != 0
