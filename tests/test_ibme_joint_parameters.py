"""Current-domain coverage and finite CHKP rounded-noise accounting."""

from fractions import Fraction
import json

import pytest

from experiments.research.ibme_joint_parameters import (
    ceil_sqrt,current_dimension_obstruction,dimension_obstruction,evaluate_noise,
    main,matrix_tv_upper,plan_numeric_candidate,
)


def test_all_current_parameter_intervals_conflict_even_with_optimistic_gs():
    report = current_dimension_obstruction()
    assert report["leaf_cap"] == 192
    assert len(report["intervals"]) == 35
    assert report["all_intervals_conflict"] and not report["empty_dimension_domain"]
    assert {r["n"] for r in report["intervals"]} == set(range(1,13))
    assert all(r["optimistic_q_upper"]**2 < r["required_q_squared"] for r in report["intervals"])
    assert not report["physical_decryption_impossibility_claim"]
    assert not report["backend_admitted"] and report["security_claim"] == "none"


def test_obstruction_covers_larger_epsilon_and_m_without_using_measured_gs():
    relaxed = dimension_obstruction(leaf_cap=192,minimum_epsilon_bits=2)
    stronger = dimension_obstruction(leaf_cap=192,minimum_epsilon_bits=32)
    assert stronger["all_intervals_conflict"]
    assert all(b["required_q_squared"] >= a["required_q_squared"]
               for a,b in zip(relaxed["intervals"],stronger["intervals"]))


def test_a_larger_hypothetical_domain_is_not_reported_impossible_or_admitted():
    report = dimension_obstruction(leaf_cap=300)
    assert not report["all_intervals_conflict"]
    assert not report["backend_admitted"]


@pytest.mark.parametrize("value,expected", [(0,0),(4,2),(5,3),(Fraction(4,9),1),
                                            (Fraction(9,4),2),(Fraction(10,4),2)])
def test_exact_square_root_upper_never_rounds_down(value,expected):
    assert ceil_sqrt(value) == expected
    assert expected**2 >= value and (expected == 0 or (expected-1)**2 < value)


@pytest.mark.parametrize("q", [2,3,4,5,6,7,9,11,100,101])
def test_integer_phase_radius_is_safe_for_both_bits_and_odd_moduli(q):
    radius = evaluate_noise(q=q,dimension=1,width_squared=1,alpha=Fraction(1,1024))["integer_phase_radius"]
    theta = q//2
    for bit in (0,1):
        for error in range(-radius,radius+1):
            phase = (bit*theta+error)%q
            zero_distance = min(phase,q-phase)
            one_delta = (phase-theta)%q
            one_distance = min(one_delta,q-one_delta)
            decoded = int(zero_distance >= one_distance)
            assert decoded == bit


def test_q_over_four_without_odd_q_tie_handling_can_fail():
    # q=5, bit=0, error=1 is below q/4, but exactly halfway to floor(q/2).
    q, phase, theta = 5,1,2
    assert Fraction(phase) < Fraction(q,4)
    assert min(phase,q-phase) == min(abs(phase-theta),q-abs(phase-theta))
    assert evaluate_noise(q=q,dimension=1,width_squared=1,alpha=Fraction(1,1024))["integer_phase_radius"] == 0


def test_rounded_gaussian_budget_is_conditional_and_lifetime_bits_share_prefix():
    good = evaluate_noise(q=101,dimension=2,width_squared=4,alpha=Fraction(1,128),
                          error_bits=32,seed_bits=256,encapsulations=1024)
    assert good["conditional_noise_sufficient"]
    assert good["l1_integer_upper"] == 4
    assert Fraction(good["rounding_error_upper"]) == Fraction(5,2)
    assert Fraction(good["conditional_lifetime_failure_upper"]) == Fraction(1,2**14)
    assert not good["shared_preamble_independence_required"]
    assert not good["preimage_norm_measured_or_certified"]
    assert not good["noise_implementation_verified"]
    assert not good["lwe_hardness_or_reduction_verified"]
    bad = evaluate_noise(q=101,dimension=2,width_squared=4,alpha=Fraction(1,4),error_bits=32)
    assert not bad["conditional_noise_sufficient"]
    assert bad["conditional_lifetime_failure_upper"] is None


def test_small_q_rounding_deficit_is_not_hidden_by_making_alpha_tiny():
    report = evaluate_noise(q=2,dimension=30,width_squared=15952640,alpha=Fraction(1,2**128))
    assert Fraction(report["continuous_margin"]) < 0
    assert not report["conditional_noise_sufficient"]


def test_hypothetical_candidate_closes_numeric_relations_but_keeps_resource_gaps():
    result = plan_numeric_candidate(n=1,q=274877844481)
    assert result["selected_q_relation_sufficient"]
    assert result["conditional_noise"]["conditional_noise_sufficient"]
    assert result["conditional_noise"]["alpha"] == "1/8589934592"
    assert Fraction(result["conditional_noise"]["conditional_lifetime_failure_upper"]) == Fraction(1,2**36)
    assert result["parameters"]["root_dimension"] == 445
    assert result["parameters"]["leaf_dimension"] == 1335
    public = result["public_error"]
    assert sum(Fraction(public[x]) for x in
               ("matrix_tv_upper","rank_abort_union_upper","uniform_abort_upper")) <= Fraction(public["target"])
    assert not any(result["caps"].values())
    assert result["sampler_tv_and_abort"] is None
    assert result["actual_scalar_tape_or_width_profiles"] is None
    assert not result["actual_genbasis_or_sampling_executed"]
    assert not result["backend_admitted"] and not result["parameters_are_formal"]


@pytest.mark.parametrize("field,value", [
    ("q",True),("q",101.0),("dimension",0),("dimension",True),("width_squared",4.0),
    ("width_squared",-1),("alpha",0),("alpha",1),("alpha",0.1),("alpha","1e99999999"),
    ("alpha","1/0"),("alpha","1/"+"9"*2401),("seed_bits",True),("encapsulations",0),
    ("alpha",Fraction(1,2**4096)),("error_bits",1),("error_bits",4097),
])
def test_noise_input_rejected_before_large_arithmetic(field,value):
    kwargs=dict(q=101,dimension=2,width_squared=4,alpha=Fraction(1,128))
    kwargs[field]=value
    with pytest.raises(ValueError):
        evaluate_noise(**kwargs)


@pytest.mark.parametrize("kwargs", [dict(q=100),dict(n=True),dict(public_tv_bits=65),
                                    dict(epsilon_bits=129),dict(seed_bits=0)])
def test_invalid_or_uncertifiable_plan_inputs(kwargs):
    inputs=dict(n=1,q=274877844481)
    inputs.update(kwargs)
    with pytest.raises(ValueError):
        plan_numeric_candidate(**inputs)


def test_public_matrix_bound_matches_actual_delivered_sage_certificate():
    pytest.importorskip("sage.all",reason="certificate comparison uses prescribed WSL Sage")
    from experiments.research.chkp_genbasis import AP09Parameters,genbasis_certificate
    params=AP09Parameters(n=1,q=257,random_rows=55,m1=55,m2=128,hadamard_scale=21)
    actual=Fraction(genbasis_certificate(params)["unconditioned_paper_matrix_tv_upper"])
    assert actual == matrix_tv_upper(1,257,55,128)
    assert actual < Fraction(1,2**16)


def test_cli_writes_complete_evidence_but_never_returns_backend_success(tmp_path):
    path=tmp_path/"joint.json"
    assert main(["--output",str(path)])==2
    result=json.loads(path.read_text(encoding="utf-8"))
    assert result["current_domain"]["all_intervals_conflict"]
    assert result["hypothetical_candidate"]["conditional_noise"]["conditional_noise_sufficient"]
    assert not result["backend_admitted"]


def test_large_numeric_plan_keeps_rank_certificate_bounded_and_parseable():
    result=plan_numeric_candidate(n=16,q=274877844481)
    encoded=json.dumps(result)
    assert len(encoded)<20000
    assert Fraction(result["public_error"]["rank_abort_union_upper"])==Fraction(1,2**34)
    assert not result["backend_admitted"]
