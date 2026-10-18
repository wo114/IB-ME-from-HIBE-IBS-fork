"""Exact finite evidence for the global mixed-domain conditional identity."""

from fractions import Fraction
from itertools import product

import pytest

from experiments.research.candidates.srgg.mixed_domain import (
    build_report, conditional_atom_upper, conditional_preimage_law,
    filter_with_abort, image_law, image_uniformity_bound, mixed_domain_law,
    repaired_union_law,
)


def _tv_to_uniform(image, q, head):
    return sum(abs(image.get(h, 0)-Fraction(1, q**head))
               for h in product(range(q), repeat=head))/2


@pytest.mark.parametrize("raw,a,q,p", [
    ({(-1, 0): Fraction(1, 6), (5, 1): Fraction(1, 3),
      (0, -1): Fraction(1, 2)}, ((1, 2),), 5, 2),
    ({(-1, 0, 0): Fraction(1, 6), (5, -6, 1): Fraction(1, 3),
      (0, 1, -1): Fraction(1, 2)}, ((1, 0, 3), (0, 1, -2)), 5, 2),
    ({(8, -9): Fraction(1, 3), (-8, 6): Fraction(2, 3)},
     ((1, 3),), 4, 4),
])
def test_every_finite_target_has_exact_conditional_union_identity(raw, a, q, p):
    head = len(a)
    domain = mixed_domain_law(raw, head=head, p=p, modulus=q)
    image = image_law(domain, a, modulus=q)
    for h in product(range(q), repeat=head):
        if h not in image:
            with pytest.raises(ValueError, match="zero probability"):
                conditional_preimage_law(domain, a, h, modulus=q)
            with pytest.raises(ValueError, match="zero probability"):
                repaired_union_law(raw, a, h, p=p, modulus=q)
            continue
        conditional, image_mass = conditional_preimage_law(domain, a, h, modulus=q)
        repaired, union_mass = repaired_union_law(raw, a, h, p=p, modulus=q)
        assert image_mass == image[h]
        assert union_mass == p**head*image_mass
        assert conditional == repaired
        # The same rejection map preserves equality, with failure explicit.
        for cap in (0, 1, 4, 100):
            gate = lambda point: sum(x*x for x in point) <= cap
            left = filter_with_abort(conditional, gate)
            right = filter_with_abort(repaired, gate)
            assert left == right and sum(left.values()) == 1


def test_head_aliases_merge_without_changing_conditional_weights():
    raw = {(-1, 1): Fraction(1, 4), (4, 1): Fraction(3, 4)}
    domain = mixed_domain_law(raw, head=1, p=2, modulus=5)
    assert domain == {(-1, 1): Fraction(1, 2), (0, 1): Fraction(1, 2)}
    conditional, mass = conditional_preimage_law(domain, ((1, 2),), (1,), modulus=5)
    assert conditional == {(-1, 1): Fraction(1)} and mass == Fraction(1, 2)
    repaired, union_mass = repaired_union_law(raw, ((1, 2),), (1,), p=2, modulus=5)
    assert repaired == conditional and union_mass == 1


def test_one_global_domain_works_for_distinct_public_matrices_and_targets():
    raw = {(1, 2, -1): Fraction(1, 3), (-5, 6, 4): Fraction(2, 3)}
    domain = mixed_domain_law(raw, head=2, p=3, modulus=3)
    for a in (((1, 0, 1), (0, 1, 2)), ((4, 3, -8), (0, 4, 7))):
        image = image_law(domain, a, modulus=3)
        # p=Q makes the independent error exactly uniform over the image.
        assert image == {h: Fraction(1, 9) for h in product(range(3), repeat=2)}
        for h in image:
            conditional, _ = conditional_preimage_law(domain, a, h, modulus=3)
            repaired, union_mass = repaired_union_law(raw, a, h, p=3, modulus=3)
            assert conditional == repaired and union_mass == 1


def test_error_convolution_contracts_tv_but_does_not_automatically_uniformize():
    raw = {(0, 0): Fraction(1, 2), (1, 1): Fraction(1, 3),
           (4, -1): Fraction(1, 6)}
    a = ((1, 2),)
    original_image = image_law(raw, a, modulus=5)
    mixed = mixed_domain_law(raw, head=1, p=2, modulus=5)
    mixed_image = image_law(mixed, a, modulus=5)
    assert 0 < _tv_to_uniform(mixed_image, 5, 1) < _tv_to_uniform(original_image, 5, 1)
    assert _tv_to_uniform(mixed_image, 5, 1) == Fraction(3, 20)


def test_global_norm_conditioning_changes_uniform_image_and_abort_is_explicit():
    raw = {(0, 0): Fraction(1)}
    domain = mixed_domain_law(raw, head=1, p=5, modulus=5)
    a = ((1, 0),)
    image = image_law(domain, a, modulus=5)
    assert _tv_to_uniform(image, 5, 1) == 0
    gate = lambda point: sum(x*x for x in point) == 0
    gated = filter_with_abort(domain, gate)
    assert gated == {(0, 0): Fraction(1, 5), None: Fraction(4, 5)}
    global_success_law = {(0, 0): Fraction(1)}
    biased_image = image_law(global_success_law, a, modulus=5)
    assert _tv_to_uniform(biased_image, 5, 1) == Fraction(4, 5)
    for h in ((1,), (2,), (3,), (4,)):
        conditional, _ = conditional_preimage_law(domain, a, h, modulus=5)
        assert filter_with_abort(conditional, gate) == {None: Fraction(1)}
    bound = image_uniformity_bound(0, unconditional_norm_reject=Fraction(4, 5))
    assert Fraction(bound["globally_success_conditioned_image_to_uniform_tv_upper_exact"]) == Fraction(4, 5)
    assert not bound["per_target_norm_reject_certified"]


def test_squared_norm_envelope_for_even_and_odd_moduli_and_wrapped_heads():
    for q in (2, 3, 4, 5, 11):
        for p in (1, q):
            for point in ((0, 0, 0), (19, -24, 3), (-30, 16, -2)):
                domain = mixed_domain_law({point: Fraction(1)}, head=2, p=p, modulus=q)
                envelope = 2*sum(x*x for x in point)+4*(p-1)**2
                assert all(sum(x*x for x in y) <= envelope for y in domain)


def test_generic_atom_bound_is_a_supplied_assumption_certificate_only():
    result = conditional_atom_upper(unwrapped_domain_atom_upper=Fraction(1, 2**256),
        canonical_head_wrap_upper=Fraction(1, 2**256),
        target_image_probability_lower=Fraction(1, 2**32))
    assert Fraction(result["conditional_max_atom_upper_exact"]) == Fraction(1, 2**223)
    assert result["conditional_min_entropy_bits_lower"] == 223
    assert not result["supplied_assumptions_verified_here"]
    assert not result["oneway_or_signature_security_certified"]
    result = conditional_atom_upper(unwrapped_domain_atom_upper=Fraction(1, 4),
        canonical_head_wrap_upper=Fraction(1, 4),
        target_image_probability_lower=Fraction(1, 10))
    assert result["conditional_max_atom_upper_exact"] == "1"
    assert result["conditional_min_entropy_bits_lower"] == 0


@pytest.mark.parametrize("raw,kwargs", [
    ({(0,): 0.5, (1,): 0.5}, {}),
    ({(0,): Fraction(1, 2)}, {}),
    ({(True,): 1}, {}),
    ({(0,): 1}, {"head": True}),
    ({(0,): 1}, {"head": 2}),
    ({(0,): 1}, {"p": 6}),
    ({(0,): 1}, {"p": 0}),
    ({(0,)*64: 1}, {"head": 64, "p": 5}),
    ({None: 1}, {}),
])
def test_finite_reference_type_normalization_and_enumeration_limits(raw, kwargs):
    options = dict(head=1, p=2, modulus=5)
    options.update(kwargs)
    with pytest.raises(ValueError):
        mixed_domain_law(raw, **options)


@pytest.mark.parametrize("a,target", [
    (((2, 0),), (0,)), (((1,),), (0,)),
    (((1, 0),), (5,)), (((1, 0),), (True,)),
])
def test_nonidentity_head_dimension_and_noncanonical_target_are_rejected(a, target):
    with pytest.raises(ValueError):
        repaired_union_law({(0, 0): 1}, a, target, p=2, modulus=5)


@pytest.mark.parametrize("mass,wrap,image", [
    (0, 0, Fraction(1, 2)), (Fraction(1, 2), 0, 0),
    (0.1, 0, Fraction(1, 2)), (Fraction(1, 2), -1, Fraction(1, 2)),
])
def test_invalid_entropy_assumptions_do_not_emit_a_certificate(mass, wrap, image):
    with pytest.raises(ValueError):
        conditional_atom_upper(unwrapped_domain_atom_upper=mass,
            canonical_head_wrap_upper=wrap, target_image_probability_lower=image)


def test_report_has_conditional_identity_without_gaussian_or_security_claims():
    report = build_report()
    assert report["finite_public_example"]
    assert all(row["conditional_laws_identical"] for row in report["finite_public_example"])
    assert not report["global_domain_depends_on_target_or_trapdoor"]
    assert not report["finite_example_is_actual_srgg_sampler_law"]
    assert not report["gaussian_secret_SIG_or_oneway_correspondence_established"]
    assert report["security_claim"] == "none"
    assert not report["backend_admitted"] and not report["parameters_are_formal"]
