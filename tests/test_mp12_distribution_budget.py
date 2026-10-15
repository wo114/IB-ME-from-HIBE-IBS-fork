"""Independent normalization, accumulation and optimistic-domain controls."""

from fractions import Fraction
from itertools import product

import pytest

from ibme.lattice.matrix_sampling.mp12_bounds import (
    convolution_tv_upper, coset_norm_tail_upper, sample_distribution_budget,
)
from experiments.research.structured_feasibility import feasibility_screen, optimistic_interval


def test_normalization_bound_covers_extreme_two_normalizer_factors():
    # Exhaust endpoints of the two independent shifted-lattice mass ratios,
    # then normalize a nonuniform four-point target independently of the code.
    eps = Fraction(1, 16)
    t = (1+eps)/(1-eps)
    target = (Fraction(1, 10), Fraction(2, 10), Fraction(3, 10), Fraction(4, 10))
    for factors in product((1/t, t), repeat=4):
        unnormalized = tuple(p*f for p,f in zip(target, factors))
        total = sum(unnormalized)
        tv = sum(abs(p-x/total) for p,x in zip(target, unnormalized))/2
        assert tv <= convolution_tv_upper(4)
    assert 2*eps < convolution_tv_upper(4) < 3*eps


def test_perturbation_budget_includes_exhaustion_even_with_exact_oracles():
    result = sample_distribution_budget(dimension=5, epsilon_bits=128, max_trials=1,
        proposal_scalar_tv=0, bernoulli_weight_error=0, gadget_tv_total=0,
        target_smoothing_verified=False)
    assert Fraction(result["modeled_sample_TV_including_abort_upper"]) > Fraction(3, 4)
    assert result["ideal_coset_norm_abort_upper"] is None
    assert result["security_claim"] == "none" and result["backend_admitted"] is False


def test_small_coordinate_errors_are_not_mistaken_for_whole_tree_exponents():
    result = sample_distribution_budget(dimension=88, epsilon_bits=128, max_trials=512,
        proposal_scalar_tv=Fraction(1, 2**128), bernoulli_weight_error=Fraction(1, 2**256),
        gadget_tv_total=Fraction(1, 2**128), target_smoothing_verified=True)
    assert Fraction(result["modeled_sample_TV_including_abort_upper"]) > Fraction(1, 2**113)
    assert 160*coset_norm_tail_upper(88, 128) < Fraction(1, 2**128)


@pytest.mark.parametrize("kwargs", [dict(dimension=True), dict(max_trials=0),
    dict(proposal_scalar_tv=0.0), dict(gadget_tv_total="-1/2"),
    dict(bernoulli_weight_error="2"), dict(target_smoothing_verified=1),
    dict(proposal_scalar_tv="1e-1000000000")])
def test_invalid_or_inexact_probability_inputs_fail(kwargs):
    values = dict(dimension=5, epsilon_bits=128, max_trials=512,
        proposal_scalar_tv=0, bernoulli_weight_error=0, gadget_tv_total=0,
        target_smoothing_verified=True)
    values.update(kwargs)
    with pytest.raises(ValueError):
        sample_distribution_budget(**values)


def test_largest_norm_bound_remains_json_serializable_without_global_limit_changes():
    assert len(str(coset_norm_tail_upper(8192, 256))) < 4300


def test_full_domain_screen_cannot_turn_an_optimistic_interval_into_admission():
    result = feasibility_screen()
    assert result["evaluated_intervals"] == 2*127*60
    assert result["complete_HG_necessary_n_upper"] == 5
    for row in result["rows"]:
        if row["n"] >= 6:
            assert row["combined_not_excluded_q_bits"] == []
    assert optimistic_interval(5, 48)["interval_not_excluded"]
    assert not optimistic_interval(5, 49)["resource_necessary_conditions"]
    assert optimistic_interval(6, 39)["resource_necessary_conditions"]
    assert not optimistic_interval(6, 39)["conditional_noise_necessary_condition"]
    assert not result["secret_list_enumeration"]["unique_recovery_or_payload_distinguishing_proved"]
    assert (result["security_claim"], result["backend_admitted"], result["parameters_are_formal"]) == ("none", False, False)
