"""Independent finite checks of latent gates, abort and retained H1 targets."""
from fractions import Fraction
from itertools import product

import pytest

from experiments.research.candidates.srgg.public_pairs import (
    build_report, compare_public_and_uniform_pairs, conditional_issuer_law,
    gated_public_pair_law, latent_pair_law, total_variation,
)


@pytest.mark.parametrize("q", [2, 3, 4, 5])
@pytest.mark.parametrize("p_kind", ["one", "full"])
def test_all_targets_match_independent_union_oracle_with_both_norm_gates(q, p_kind):
    p = 1 if p_kind == "one" else q
    points = tuple(product(range(q), repeat=2))+((q, 0),)
    denominator = len(points)*(len(points)+1)//2
    raw = {u: Fraction(i+1, denominator) for i, u in enumerate(points)}
    a = ((1, 2),)
    for raw_cap, user_cap in ((0, 0), (1, 2), (2*q*q, 2*q*q)):
        public = gated_public_pair_law(raw, a, p=p, modulus=q,
            raw_norm_cap=raw_cap, user_norm_cap=user_cap)
        for h in range(q):
            expected, total = {}, Fraction(0)
            # Deliberately do not call a helper for forward/repair/gates.
            for u, mass in raw.items():
                e = (h-u[0]-2*u[1]) % q
                if e >= p:
                    continue
                y = ((u[0]+e+q//2) % q-q//2, u[1])
                key = y if (u[0]**2+u[1]**2 <= raw_cap
                            and y[0]**2+y[1]**2 <= user_cap) else None
                expected[key] = expected.get(key, 0)+mass
                total += mass
            expected = {k: m/total for k, m in expected.items()}
            actual, union_mass = conditional_issuer_law(raw, a, (h,), p=p,
                modulus=q, raw_norm_cap=raw_cap, user_norm_cap=user_cap)
            assert actual == expected and union_mass == total
            image_mass = sum(m for (target, _k), m in public.items() if target == (h,))
            assert total == p*image_mass
            assert {k: m/image_mass for (target, k), m in public.items()
                    if target == (h,)} == expected
        result = compare_public_and_uniform_pairs(raw, a, p=p, modulus=q,
            raw_norm_cap=raw_cap, user_norm_cap=user_cap)
        assert result["joint_pair_tv_exact"] == result["image_tv_to_uniform_exact"]


def test_raw_norm_gate_cannot_be_reconstructed_from_canonical_Y():
    raw = {(0,): Fraction(1, 2), (3,): Fraction(1, 2)}
    law = latent_pair_law(raw, ((1,),), p=1, modulus=3)
    assert {atom[3] for atom in law} == {(0,)}
    assert {atom[1] for atom in law} == {(0,), (3,)}
    actual = gated_public_pair_law(raw, ((1,),), p=1, modulus=3,
        raw_norm_cap=0, user_norm_cap=0)
    assert actual == {((0,), (0,)): Fraction(1, 2), ((0,), None): Fraction(1, 2)}
    # A predicate of Y alone must accept both paths or reject both; neither
    # law equals the honest half-failure output.
    assert total_variation(actual, {((0,), (0,)): 1}) == Fraction(1, 2)
    assert total_variation(actual, {((0,), None): 1}) == Fraction(1, 2)


def test_dropping_target_on_abort_can_strictly_hide_pair_distance():
    raw = {(0,): Fraction(3, 4), (1,): Fraction(1, 4)}
    result = compare_public_and_uniform_pairs(raw, ((1,),), p=1, modulus=2,
        raw_norm_cap=0, user_norm_cap=0)
    assert Fraction(result["joint_pair_tv_exact"]) == Fraction(1, 4)
    # A separate example: every key fails, but the h marginal is still visible.
    raw = {(2,): Fraction(3, 4), (3,): Fraction(1, 4)}
    public = gated_public_pair_law(raw, ((1,),), p=1, modulus=2,
        raw_norm_cap=0, user_norm_cap=0)
    honest = {((0,), None): Fraction(1, 2), ((1,), None): Fraction(1, 2)}
    assert total_variation(public, honest) == Fraction(1, 4)
    assert total_variation({None: 1}, {None: 1}) == 0


def test_fixed_cached_failure_is_different_from_resampling_conditional_pair():
    conditional, _ = conditional_issuer_law(
        {(0,): Fraction(1, 2), (3,): Fraction(1, 2)}, ((1,),), (0,),
        p=1, modulus=3, raw_norm_cap=0, user_norm_cap=0)
    cached = {(key, key): mass for key, mass in conditional.items()}
    fresh = {(first, second): a*b for first, a in conditional.items()
             for second, b in conditional.items()}
    assert total_variation(cached, fresh) == Fraction(1, 2)
    assert ((0,), None) not in cached and (None, (0,)) not in cached


def test_two_head_coordinates_and_aliases_are_retained_until_both_gates():
    raw = {(0, 0, 1): Fraction(1, 3), (4, -4, 1): Fraction(2, 3)}
    a = ((1, 0, 2), (0, 1, 3))
    for cap in (0, 1, 20, 100):
        result = compare_public_and_uniform_pairs(raw, a, p=4, modulus=4,
            raw_norm_cap=cap, user_norm_cap=cap)
        assert result["target_count"] == 16
        assert result["joint_pair_tv_exact"] == "0"


@pytest.mark.parametrize("options", [
    {"raw_norm_cap": True}, {"user_norm_cap": -1}, {"p": 0},
    {"p": 4}, {"modulus": True}, {"raw_norm_cap": 1.0},
])
def test_invalid_exact_inputs_rejected(options):
    kwargs = dict(p=1, modulus=3, raw_norm_cap=1, user_norm_cap=1)
    kwargs.update(options)
    with pytest.raises(ValueError):
        gated_public_pair_law({(0,): 1}, ((1,),), **kwargs)


def test_missing_fiber_is_not_filled_with_an_invented_conditional_key():
    with pytest.raises(ValueError, match="zero-probability"):
        compare_public_and_uniform_pairs({(0,): 1}, ((1,),), p=1, modulus=3,
            raw_norm_cap=1, user_norm_cap=1)


def test_enumeration_and_normalization_limits_fail_explicitly():
    with pytest.raises(ValueError, match="resource limit"):
        latent_pair_law({(0,)*8: 1}, tuple(tuple(int(i == j)
            for j in range(8)) for i in range(8)), p=4, modulus=4)
    with pytest.raises(ValueError, match="resource limit"):
        compare_public_and_uniform_pairs({(0,): 1}, ((1,),), p=1, modulus=4097,
            raw_norm_cap=1, user_norm_cap=1)
    with pytest.raises(ValueError):
        total_variation({None: 0.5}, {None: 1})
    with pytest.raises(ValueError, match="normalized"):
        total_variation({None: Fraction(1, 2)}, {None: 1})


def test_report_is_finite_evidence_and_does_not_grant_security():
    report = build_report()
    assert len(report["finite_public_examples"]) == 7
    assert any(Fraction(row["joint_pair_tv_exact"]) > 0
               for row in report["finite_public_examples"])
    assert report["raw_gate_is_not_a_Y_predicate_counterexample"][
        "honest_abort_probability_exact"] == "1/2"
    assert report["actual_entropy_bytes"] == 0
    assert not report["actual_IBS_reduction_established"]
    assert report["security_claim"] == "none" and not report["backend_admitted"]
