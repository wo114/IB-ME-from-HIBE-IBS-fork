"""Exact parameter-search constraints and reduction loss, without estimator RNG."""
from fractions import Fraction
from math import gcd

import pytest

from experiments.research.candidates.srgg.formal_candidates import conditional_candidate
from experiments.research.candidates.srgg import hardness_search as hs


def test_current_research_point_preserves_every_existing_arithmetic_input():
    candidate = hs.build_candidate(degree=512,rank=2,base=31,digits=8,r_squared=64,p=16383)
    reference = conditional_candidate()
    for field in reference.__dataclass_fields__:
        if field != "name":
            assert getattr(candidate, field) == getattr(reference, field)
    row = hs.candidate_record(candidate)
    assert row["arithmetic_passes"]
    assert row["Q"] == 13972913866395903
    assert row["HNF_MSIS_comparator"]["squared_length_bound_exact"] == 953022385920644398085744640
    assert row["MLWE_single_column_comparator"]["n"] == 1024
    assert row["MLWE_single_column_comparator"]["m"] == 1024


@pytest.mark.parametrize("n,d,b,w,r2", [
    (2,1,3,2,1),(2,1,3,4,1),(4,1,7,3,2),
    (4,2,15,4,2),(8,1,31,3,4),(8,2,3,10,4),
    (512,2,31,8,64),(512,2,3,20,64)])
def test_minimum_p_matches_independent_finite_enumeration(n,d,b,w,r2):
    expected = None
    for p in range(3, 512, 2):
        if gcd(p,b) != 1:
            continue
        candidate = hs.build_candidate(degree=n,rank=d,base=b,digits=w,r_squared=r2,p=p)
        if candidate.modulus**2 > 4*candidate.signature_norm_squared_cap:
            expected = p
            break
    assert hs.minimum_p(degree=n,rank=d,base=b,digits=w,r_squared=r2,p_max=511) == expected


def test_selected_shapes_all_pass_existing_geometric_and_smoothing_predicates():
    report = hs.arithmetic_search(points=((512,2),(1024,2)),r_squared_values=(64,128))
    assert len(report["selected_candidates"]) == 4
    assert all(row["arithmetic_passes"] for row in report["selected_candidates"])
    current = report["current_research_point"]
    optimized = report["selected_candidates"][0]
    assert optimized["Q"] < current["Q"]
    assert optimized["full_kernel_smoothing"]["passes"]
    assert report["actual_entropy_bytes"] == 0
    assert report["backend_preset_modified"] is False
    assert report["parameters_are_formal"] is False


def test_geometry_only_minimum_q_can_fail_the_independent_full_kernel_gate():
    p = hs.minimum_p(degree=512,rank=2,base=3,digits=15,r_squared=64)
    candidate = hs.build_candidate(degree=512,rank=2,base=3,digits=15,r_squared=64,p=p)
    assert hs.geometry_bounds(candidate)["all_arithmetic_gates_pass"]
    assert not hs.full_kernel_smoothing(candidate)["passes"]


def test_fork_requirement_uses_exact_advantage_and_detects_vacuous_entropy():
    requirement = hs.reduction_requirement(degree=512,rank=2,digits=8)
    def decode(record):
        return Fraction(int(record["numerator_hex"],16),int(record["denominator_hex"],16))
    f = decode(requirement["F_at_target_after_identity_loss_exact"])
    threshold = decode(requirement["each_hardness_advantage_upper_required_exact"])
    bits = requirement["sufficient_each_advantage_dyadic_bits"]
    assert threshold == f/17 and f > 0
    assert Fraction(1,2**bits) <= threshold < Fraction(1,2**(bits-1))
    assert hs.reduction_requirement(degree=256,rank=2,digits=8)["sufficient_each_advantage_dyadic_bits"] is None
    assert requirement["finite_attack_cost_is_not_an_advantage_bound"]


def test_large_degree_exact_fractions_do_not_require_unbounded_decimal_conversion():
    requirement = hs.reduction_requirement(degree=8192,rank=2,digits=8)
    numerator = int(requirement["F_at_target_after_identity_loss_exact"]["numerator_hex"],16)
    assert numerator > 0


@pytest.mark.parametrize("kwargs", [{"degree":True},{"degree":3},{"rank":0},
    {"base":2},{"p":31},{"r_squared":0},{"digits":33}])
def test_invalid_candidate_inputs_reject_before_any_estimator_import(kwargs):
    parameters = dict(degree=512,rank=2,base=31,digits=8,r_squared=64,p=16383)
    parameters.update(kwargs)
    with pytest.raises(ValueError):
        hs.build_candidate(**parameters)


@pytest.mark.parametrize("base", [0,True,2,2**16])
def test_invalid_minimum_p_inputs_cannot_enter_coprime_search(base):
    with pytest.raises(ValueError):
        hs.minimum_p(degree=512,rank=2,base=base,digits=8,r_squared=64)
