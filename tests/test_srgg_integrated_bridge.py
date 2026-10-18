"""Meaningful composition and alias-safe entropy checks for the new bridge."""
from fractions import Fraction
import pytest

from experiments.research.candidates.srgg.integrated_bridge import (
    mixed_entropy_bound,successful_key_entropy,
)


@pytest.mark.parametrize("dimension,head,s,q",[(4,1,16,3),(8,2,64,17),(16,2,4096,257)])
def test_coarse_entropy_encloses_exact_algebraic_envelope(dimension,head,s,q):
    report = mixed_entropy_bound(dimension=dimension,head_dimension=head,squared_width=s,
                                modulus=q,kernel_relative_error=Fraction(1,3))
    # These square s fixtures allow independent exact evaluation of the
    # peak+integral envelope; this checks the log rounding in both directions.
    from math import isqrt
    bound = min(Fraction(1),Fraction(2*(q+isqrt(s))**head,s**(dimension//2)))
    assert bound<=Fraction(1,2**report["ideal_conditional_min_entropy_bits_lower"])
    assert report["head_aliases_included"] and not report["global_wrap_bound_used"]


def test_entropy_after_success_retains_normalization_cost():
    value = successful_key_entropy(ideal_bits=256,key_tv_including_abort=Fraction(1,2**128),
                                  actual_abort_upper=Fraction(1,2))
    assert Fraction(value["conditional_success_max_atom_upper_exact"])==2*(Fraction(1,2**256)+Fraction(1,2**128))
    assert value["conditional_success_min_entropy_bits_lower"]==126
    assert not successful_key_entropy(ideal_bits=256,key_tv_including_abort=0,actual_abort_upper=1)["available"]


@pytest.mark.parametrize("changes",[{"dimension":3},{"head_dimension":9},{"squared_width":True},
    {"modulus":1},{"kernel_relative_error":.1},{"kernel_relative_error":Fraction(1,2)}])
def test_entropy_rejects_missing_exact_premises(changes):
    args=dict(dimension=8,head_dimension=2,squared_width=64,modulus=17,kernel_relative_error=0)
    args.update(changes)
    with pytest.raises(ValueError): mixed_entropy_bound(**args)


def test_actual_plans_close_conditional_composition_without_entropy():
    pytest.importorskip("sage.all")
    from experiments.research.candidates.srgg.integrated_bridge import execution_certificate
    from experiments.research.candidates.srgg.structured_execution import Execution,ExecutionParams,sampler_profile
    from experiments.research.candidates.srgg.formal_candidates import conditional_candidate
    class NoEntropy:
        def read(self,size): raise AssertionError("certificate consumed secret entropy")
    params = ExecutionParams.from_candidate(conditional_candidate(degree=512,rank=2,digits=8))
    series,scalar=sampler_profile("query-bounded-deep")
    execution=Execution(params,rng=NoEntropy(),series_options=series,scalar_options=scalar)
    report=execution_certificate(execution,profile="query-bounded-deep",queries=(0,1,2**40))
    key=report["hnf_common_gate_comparison"]
    pre=Fraction(report["issuance_pre_raw_finite_and_recurrence_tv_upper"])
    conv=Fraction(report["convolution"]["ideal_raw_to_union_gaussian_tv_upper_exact"])
    tail=Fraction(report["raw_union_norm_reject"]["probability_upper"])
    assert Fraction(key["complete_issuance_to_common_hnf_gate_reference_tv_upper"])>=min(Fraction(1),pre+conv+tail)
    assert Fraction(key["actual_issuance_abort_upper_excluding_infrastructure"])>=min(Fraction(1),pre+conv+2*tail)
    assert report["raw_gate_covers_repaired_user_gate"]
    assert report["query_ledgers"][0]["service_abort_upper_conditional_on_no_infrastructure_failure"]=="0"
    for row in report["query_ledgers"]:
        assert row["full_service_abort_upper"] is None
        assert row["reference_is_not_a_proved_security_game_simulator"]
    assert report["successful_issued_key_entropy"]["available"]
    assert report["security_claim"]=="none" and not report["parameters_are_formal"]
