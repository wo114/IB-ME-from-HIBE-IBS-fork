"""Exact compression/fork bounds and finite conditional nonzero controls."""

from dataclasses import replace
from fractions import Fraction
from itertools import product

import pytest

from experiments.research.luo_module_security_screen import (
    compression_bounds, conditional_cube_guess_bound, finite_budget_checks,
    hint_correction, nonzero_conditions, public_high_lift, witness_rows,
)
from ibme.ibs.luo_module import LuoModuleParams
from ibme.ibs.luo_module_math import Rounding, negacyclic_schoolbook


def test_actual_hint_and_error_bounds_include_signed_strict_response():
    p = LuoModuleParams()
    b = compression_bounds(p)
    assert b["sign_z"] == 31462359039
    assert b["extraction_z"] == 125376
    assert b["dropped_low_product"] == 8589934592
    assert b["hint_correction"] == 30541982721
    assert b["uncompressed_error"] == 39131917313 > b["sign_z"]
    assert hint_correction(0, 1, p) == -30541982721
    assert hint_correction(p.q - 1, 0, p) == 1


def test_public_lift_retains_the_1024_carry():
    p = LuoModuleParams()
    assert public_high_lift(0, p) == (0, 0)
    assert public_high_lift(1023, p) == (1023 * 2**28, 0)
    assert public_high_lift(1024, p) == (p.q - 1, -62464)
    assert p.rounding().power2round(1024 * 2**28 % p.q) == 0  # Zero low part is wrong at the carry.
    for high in (1025, -1, True, 1.0):
        with pytest.raises(ValueError): public_high_lift(high, p)


@pytest.mark.parametrize("q", [17, 31, 41, 97])
def test_every_small_hint_has_bounded_centered_correction(q):
    for alpha in range(2, q // 2 + 1, 2):
        if (q - 1) % alpha:
            continue
        rounding = Rounding(q, alpha, 3)
        for r, h in product(range(q), (0, 1)):
            high = rounding.use_hint(h, r)
            delta = alpha * high - r
            candidates = (delta - q, delta, delta + q)
            centered = min(candidates, key=abs)
            assert abs(centered) <= alpha + 1
            assert (r + centered) % q == alpha * high % q


def test_witness_dimensions_and_bounds_do_not_drop_error_or_public_t():
    rows = {row["name"]: row for row in witness_rows(LuoModuleParams())}
    known = rows["known-identity-tight"]
    fresh = rows["fresh-identity-augmented"]
    loose = rows["all-branches-relaxed"]
    assert known["block_infinity_bounds"] == [62940766206, 78279882754]
    assert fresh["block_infinity_bounds"] == [62924718078, 78263834626, 128]
    assert (known["coefficient_rows"], known["coefficient_columns"]) == (2816, 5376)
    assert fresh["coefficient_columns"] == loose["coefficient_columns"] == 5632
    assert loose["uniform_screen_bound"] == 78279890946
    assert all(row["below_q_half"] for row in rows.values())
    assert loose["uniform_screen_bound"] >= max(known["block_infinity_bounds"] + fresh["block_infinity_bounds"])


def test_fresh_branch_sparse_product_nonzero_without_modular_invertibility():
    # Integer cyclotomic rings are domains. We need nonzero small products,
    # not the false assertion that all sparse challenges are units modulo q.
    for n, weight, q in ((2, 1, 17), (4, 1, 17), (4, 2, 17)):
        challenges = [poly for poly in product((-1, 0, 1), repeat=n) if sum(map(abs, poly)) == weight]
        for left, right, c in product(challenges, repeat=3):
            if left == right:
                continue
            delta = tuple(a - b for a, b in zip(left, right))
            result = negacyclic_schoolbook(delta, c)
            assert any(result) and max(map(abs, result)) <= 2 * weight < q
            assert any(x % q for x in result)
    # Unrestricted R_q can have zero divisors even though the integer ring is a domain.
    assert negacyclic_schoolbook((-4, 1), (4, 1)) == (-17, 0)


@pytest.mark.parametrize("tries", [1, 2, 4])
def test_average_label_guess_bound_by_exhaustive_injective_targets(tries):
    cube = list(product((-1, 0, 1), repeat=2))
    labels = {0: [], 1: [], 2: []}
    for index, value in enumerate(cube): labels[index % 3].append(value)
    successes = 0
    for label, values in labels.items():
        delta = ((1, 0), (0, 1), (-1, 1))[label]
        targets = [negacyclic_schoolbook(x, delta) for x in values[:tries]]
        successes += sum(negacyclic_schoolbook(x, delta) in targets for x in values)
    assert Fraction(successes, len(cube)) <= conditional_cube_guess_bound(2, 1, 3, tries)
    # This is an average probability, not a universal posterior probability.
    assert conditional_cube_guess_bound(2, 1, 3, 4) == 1


def test_nonzero_certificate_is_explicitly_conditional_and_uses_1025_labels():
    n = nonzero_conditions(LuoModuleParams())
    known, fresh = n["known_identity"], n["fresh_identity"]
    assert known["uniform_key_cube_dimensions"] == 5376
    assert known["public_label_dimensions"] == 2816 and known["labels_per_coefficient"] == 1025
    assert known["average_bound_log2"] < -60000
    assert known["exact_bound_at_most_2pow_minus128"] and not known["pointwise_posterior_claim"]
    assert "simulation" in known["hypothesis"]
    assert fresh["bound_below_q"] and fresh["invertible_mod_q_challenge_not_required"]


def test_known_fork_can_have_zero_witness_without_the_entropy_hypothesis():
    sid, y, c, fork_c = (1, -1), (0, 1), (1, 0), (0, 1)
    first, second = negacyclic_schoolbook(sid, c), negacyclic_schoolbook(sid, fork_c)
    response = tuple(a + b for a, b in zip(first, y))
    forked = tuple(a + b for a, b in zip(second, y))
    difference = tuple(b - a for a, b in zip(c, fork_c))
    secret_difference = negacyclic_schoolbook(sid, difference)
    assert c != fork_c and tuple(b - a - s for a, b, s in zip(response, forked, secret_difference)) == (0, 0)


@pytest.mark.parametrize("args", [(True, 1, 3), (0, 1, 3), (2, 0, 3), (2, 1, 0), (2, 1, 3, 0), (32769, 1, 3)])
def test_bad_finite_cube_inputs_rejected(args):
    with pytest.raises(ValueError): conditional_cube_guess_bound(*args)


def test_finite_budget_planning_is_not_unconditional_availability():
    result = finite_budget_checks(LuoModuleParams())
    extract = result["extraction"]
    assert 15 < extract["ideal_new_hash_planning_expected_trials"] < 16
    assert extract["central_region_abort_upper_log2"] > -128  # Loose upper bound, not an observed failure.
    assert extract["ideal_planning_abort_upper_log2"] < extract["central_region_abort_upper_log2"]
    assert result["signing_remaining_rejections_not_bounded_here"]
    assert replace(LuoModuleParams(), kappa=49).kappa == 49
