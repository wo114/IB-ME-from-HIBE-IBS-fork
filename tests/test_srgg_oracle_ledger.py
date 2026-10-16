from fractions import Fraction

import pytest

from experiments.research.candidates.srgg.oracle_ledger import (
    hnf_reference_comparison, service_ledger, signature_norm_bound,
)


def test_common_norm_gate_does_not_add_the_same_abort_twice():
    result = hnf_reference_comparison(sampler_tv_including_abort="1/1000",
        raw_convolution_tv="1/10000", ideal_union_norm_reject="1/10")
    assert Fraction(result["complete_issuance_to_common_hnf_gate_reference_tv_upper"]) < Fraction(12,10000)
    assert Fraction(result["actual_issuance_abort_upper_excluding_infrastructure"]) > Fraction(1,10)
    assert result["abort_atom_retained"] and not result["success_conditioned"]
    assert not result["source_psf_sampledom_correspondence_established"]


def test_missing_bridge_is_not_fabricated():
    assert not hnf_reference_comparison(sampler_tv_including_abort=0,raw_convolution_tv=None)["available"]
    value = hnf_reference_comparison(sampler_tv_including_abort=0,raw_convolution_tv=0)
    assert "actual_issuance_abort_upper_excluding_infrastructure" not in value


def sign_bound(**kwargs):
    args = dict(dimension=40,degree=8,response_squared_cap=40*10**8,
        perturbation_largest_squared_width=10**8,perturbation_smoothing_epsilon=Fraction(1,2**80),
        scalar_squared_width=9,scalar_smoothing_epsilon=Fraction(1,2**80),
        signing_stacked_spectral_squared_upper=1000)
    return signature_norm_bound(**dict(args,**kwargs))


def test_response_radius_allocation_preserves_triangle_inequality_exactly():
    result = sign_bound()
    assert Fraction(result["ideal_sequential_sign_attempt_norm_reject_upper"]) < Fraction(1,1000)
    selected = result["selected_allocation"]
    alpha = Fraction(selected["radius_fraction_alpha"])
    assert Fraction(selected["perturbation_norm_squared_cap"]) == alpha**2*40*10**8
    assert Fraction(selected["centered_scalar_norm_squared_cap"])*2000 == (1-alpha)**2*40*10**8
    assert not result["signature_gaussian_identified"]


def test_uniform_norm_bound_degrades_with_witness_norm_and_rejects_bad_dimensions():
    good = Fraction(sign_bound()["ideal_sequential_sign_attempt_norm_reject_upper"])
    bad = Fraction(sign_bound(signing_stacked_spectral_squared_upper=10**12)["ideal_sequential_sign_attempt_norm_reject_upper"])
    assert good < bad
    with pytest.raises(ValueError):
        sign_bound(dimension=41)


@pytest.mark.parametrize("bad", [True,0.5,0,-1])
def test_norm_inputs_are_positive_exact_rationals(bad):
    with pytest.raises(ValueError):
        sign_bound(response_squared_cap=bad)


def ledger(**kwargs):
    args = dict(new_identities=16,signing_queries=1,max_sign_attempts=16,
        issuance_to_reference_tv="1/1000",sign_attempt_to_reference_tv="1/10000",
        issuance_abort="1/1000",sign_sampling_abort="1/1000000",sign_norm_reject="1/2")
    return service_ledger(**dict(args,**kwargs))


def test_service_retry_budget_retains_history_condition_and_missing_infrastructure_model():
    result = ledger()
    assert Fraction(result["actual_signature_operation_abort_upper_excluding_infrastructure"]) >= Fraction(16,1000000)+Fraction(1,2**16)
    assert result["full_service_abort_upper"] is None
    assert result["requires_uniform_conditional_bounds_and_fresh_attempt_entropy"]
    with_infrastructure = ledger(infrastructure_abort="1/100")
    assert with_infrastructure["full_service_abort_upper"] is not None


def test_cached_reads_do_not_consume_additional_statistical_budget():
    result = ledger(new_identities=0,signing_queries=0,infrastructure_abort=0)
    assert Fraction(result["transcript_to_hnf_key_and_sequential_sign_reference_tv_upper"]) == 0
    assert Fraction(result["full_service_abort_upper"]) == 0
    assert Fraction(ledger(signing_queries=2**40)["transcript_to_hnf_key_and_sequential_sign_reference_tv_upper"]) == 1


@pytest.mark.parametrize("bad", [True,-1,"2",0.5])
def test_invalid_probability_is_rejected(bad):
    with pytest.raises((ValueError,TypeError)):
        hnf_reference_comparison(sampler_tv_including_abort=bad,raw_convolution_tv=0)
