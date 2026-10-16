"""Exact finite laws/counterexamples; no empirical Gaussian security claim."""

from fractions import Fraction

import pytest

from experiments.research.candidates.srgg.algebra import (
    Params, PublicRelation, constant, matvec, reconstruct_vector,
)
from experiments.research.candidates.srgg.issuance_analysis import (
    condition_domain_on_image, condition_success, conditional_tv_upper,
    finite_gaussian_hnf_counterexample, finite_raw_extraction_law, issuance_law,
    rare_success_counterexample, reference_decoder_comparison,
    service_abort_upper, tail_law, total_variation, transcript_tv_upper,
)


def fixture():
    p = Params(degree=2, rank=1, p=5, base=3, digits=1)
    zero = constant(p, 0)
    public = PublicRelation(p, ((zero,),), ((constant(p, 5),),))
    return p, zero, public


def test_conditional_kernel_composition_retains_abort_and_raw_head_mixture():
    p, zero, public = fixture()
    target = (constant(p, 1),)
    trapdoor = ((zero,), (zero,))
    perturbations = {(zero, zero, zero): Fraction(1, 2),
                     (constant(p, 1), zero, zero): Fraction(1, 2)}

    def kernel(residual):
        if residual == target:
            return {(zero,): Fraction(1, 4),
                    (constant(p, 3),): Fraction(1, 2), None: Fraction(1, 4)}
        assert residual == (zero,)
        return {(zero,): Fraction(1, 2), (constant(p, 3),): Fraction(1, 2)}

    raw = finite_raw_extraction_law(public, trapdoor, target, perturbations, kernel)
    assert raw[None] == Fraction(1, 8)
    assert len(raw) == 5
    decoded = issuance_law(public, target, raw)
    short = (constant(p, 1), zero, zero)
    long = (constant(p, 1), zero, constant(p, 3))
    assert decoded == {short: Fraction(3, 8), long: Fraction(1, 2), None: Fraction(1, 8)}
    assert issuance_law(public, target, raw, user_norm_squared=1) == {
        short: Fraction(3, 8), None: Fraction(5, 8)}
    for witness in decoded:
        if witness is not None:
            assert matvec(p, public.a, witness, p.modulus) == target


def test_hnf_law_tv_equals_tail_law_tv_but_can_erase_raw_tv():
    p, zero, public = fixture()
    target = (zero,)
    base = (zero, zero, zero)
    changed_head = (constant(p, -1), zero, zero)
    changed_tail = (zero, constant(p, 1), zero)
    left = {base: Fraction(1, 2), changed_tail: Fraction(1, 2)}
    right = {changed_head: Fraction(3, 4), changed_tail: Fraction(1, 4)}
    assert total_variation(left, right) == Fraction(3, 4)
    assert total_variation(tail_law(public, left), tail_law(public, right)) == Fraction(1, 4)
    assert total_variation(issuance_law(public, target, left),
                           issuance_law(public, target, right)) == Fraction(1, 4)
    assert issuance_law(public, target, {base: Fraction(1)}) == issuance_law(
        public, target, {changed_head: Fraction(1)})


def test_domain_conditioning_and_decoder_wrap_bound_are_distinct():
    p, zero, public = fixture()
    origin = (zero, zero, zero)
    wrapped = (constant(p, p.modulus), zero, zero)
    other_image = (constant(p, 1), zero, zero)
    image_mass, conditional = condition_domain_on_image(public, (zero,), {
        origin: Fraction(1, 4), wrapped: Fraction(1, 4), other_image: Fraction(1, 2)})
    assert image_mass == Fraction(1, 2)
    assert conditional == {origin: Fraction(1, 2), wrapped: Fraction(1, 2)}
    result = reference_decoder_comparison(public, (zero,), conditional)
    assert result["head_wrap_probability"] == Fraction(1, 2)
    assert result["full_reference_to_decoded_tv"] == Fraction(1, 2)
    assert result["coupling_bound_holds"]
    with pytest.raises(ValueError, match="full exact-preimage"):
        reference_decoder_comparison(public, (zero,), {other_image: Fraction(1)})


def test_finite_gaussian_hnf_counterexample_has_nonzero_exact_distance():
    result = finite_gaussian_hnf_counterexample()
    assert result["raw_state_count"] == 10
    assert result["repaired_state_count"] == 2
    # A rational mass comparison, with no fitted histogram or floating point.
    assert Fraction(1, 25) < result["repaired_to_finite_exact_gaussian_tv"] < Fraction(1, 20)
    assert not result["is_actual_srgg_sampler_law"]


@pytest.mark.parametrize("epsilon", [Fraction(1, 100), Fraction(1, 2), Fraction(99, 100)])
def test_norm_conditioning_can_amplify_tv_to_one(epsilon):
    result = rare_success_counterexample(epsilon)
    assert result["before_filter_tv"] == epsilon
    assert result["including_abort_after_filter_tv"] == epsilon
    assert result["success_left"] == result["success_right"] == epsilon
    assert result["conditioned_on_success_tv"] == result["conditional_tv_upper"] == 1


def test_conditioning_bound_over_all_small_three_atom_laws_and_shared_events():
    laws = [{0: Fraction(a, 4), 1: Fraction(b, 4), 2: Fraction(4-a-b, 4)}
            for a in range(5) for b in range(5-a)]
    for left in laws:
        for right in laws:
            distance = total_variation(left, right)
            for mask in range(1, 8):
                accepted = {i for i in range(3) if (mask >> i) & 1}
                left_filtered = {i: left[i] for i in accepted}
                right_filtered = {i: right[i] for i in accepted}
                alpha, beta = sum(left_filtered.values()), sum(right_filtered.values())
                if alpha and beta:
                    left_cond = {i: mass / alpha for i, mass in left_filtered.items()}
                    right_cond = {i: mass / beta for i, mass in right_filtered.items()}
                    assert total_variation(left_cond, right_cond) <= conditional_tv_upper(distance, alpha, beta)


def test_service_budget_counts_distinct_issuances_and_immediate_sampling_aborts():
    common = {"signing_queries": 3, "issuance_abort": Fraction(1, 100),
              "signing_sampling_abort": Fraction(1, 1000),
              "signing_norm_reject": Fraction(1, 2), "max_sign_attempts": 4,
              "infrastructure_abort": Fraction(1, 200)}
    assert service_abort_upper(new_identities=2, **common) == (
        Fraction(2, 100) + 3*(Fraction(4, 1000) + Fraction(1, 16)) + Fraction(1, 200))
    # Cached identity requests have no repeated issuance term.
    assert service_abort_upper(new_identities=2, **common) - service_abort_upper(
        new_identities=0, **common) == Fraction(2, 100)
    assert transcript_tv_upper(new_identities=2, signing_queries=3,
        issuance_tv_including_abort=Fraction(1, 100),
        signing_tv_including_abort=Fraction(1, 1000),
        infrastructure_divergence=Fraction(1, 200)) == Fraction(7, 250)
    assert service_abort_upper(new_identities=2**40, **common) == 1


def test_invalid_laws_fibers_and_zero_conditioning_fail_explicitly():
    p, zero, public = fixture()
    raw = (zero, zero, zero)
    with pytest.raises(ValueError, match="sum to one"):
        issuance_law(public, (zero,), {raw: Fraction(1, 2)})
    with pytest.raises(ValueError, match="exact integer or Fraction"):
        issuance_law(public, (zero,), {raw: 1.0})
    with pytest.raises(ValueError, match="outside canonical"):
        issuance_law(public, (zero,), {(constant(p, 1), zero, zero): Fraction(1)})
    with pytest.raises(ValueError, match="gadget kernel violates"):
        finite_raw_extraction_law(public, ((zero,), (zero,)), (zero,), {raw: Fraction(1)},
                                  lambda _v: {(constant(p, 1),): Fraction(1)})
    with pytest.raises(ValueError, match="zero-probability"):
        condition_success({None: Fraction(1)})
    with pytest.raises(ValueError, match="positive"):
        conditional_tv_upper(Fraction(1), 0, 1)
    with pytest.raises(ValueError, match="must not contain abort"):
        condition_domain_on_image(public, (zero,), {None: Fraction(1)})
