"""Independent entropy enumeration and exact parameter constraints."""

from collections import Counter
from fractions import Fraction
from itertools import product

import pytest

from experiments.research.luo_joint_parameter_screen import (
    plan_masks, public_uniform_bound_squared, public_uniformity,
    resource_projection, select_flexible_hint_modulus, select_hint_modulus, witness_bounds,
)
from experiments.research.luo_parameter_screen import (
    ESTIMATOR_COMMIT, lwe_attack_goal, screening_rows, verify_estimator_checkout,
)


def test_dual_cost_is_not_a_key_recovery_cost():
    assert lwe_attack_goal("dual") == "decisional_distinguisher"
    assert lwe_attack_goal("dual_hybrid") == "distinguishing_with_partial_secret_guess"
    assert lwe_attack_goal("usvp") == "heuristic_secret_search"
    assert lwe_attack_goal("unknown") == "unclassified_no_key_recovery_claim"


@pytest.mark.parametrize("q,m,columns", [(5, 2, 1), (5, 2, 2), (17, 2, 1)])
def test_column_hybrid_lhl_bound_against_exact_public_distribution(q, m, columns):
    # Enumerate every public A, every ternary secret, and every output. No RNG,
    # estimator or implementation distribution sampler enters this check.
    domain = tuple(product((-1, 0, 1), repeat=m))
    exact_tv = Fraction(0)
    for a in product(range(q), repeat=m):
        images = Counter(sum(x * y for x, y in zip(a, s)) % q for s in domain)
        for target in product(range(q), repeat=columns):
            numerator = 1
            for value in target:
                numerator *= images[value]
            probability = Fraction(numerator, len(domain)**columns)
            exact_tv += abs(probability - Fraction(1, q**columns)) / (2 * q**m)
    assert exact_tv**2 <= public_uniform_bound_squared(1, m, columns, q, 1)
    if len(domain) < q:
        assert exact_tv >= 1 - Fraction(len(domain), q)


def test_exact_statistical_gate_and_support_deficit():
    _, tiny, _ = screening_rows()[0]
    weak = public_uniformity(tiny)
    assert not weak["exact_arithmetic_sufficient"]
    assert weak["one_column_support_ratio_log2"] < 0
    assert weak["support_distance_lower_bound"] == "1-2^(support_ratio_log2)"
    # Prime q=3, large ternary secret domain, two independent public columns.
    p = {**tiny, "n": 1, "m": 4, "k": 2, "q": 3}
    assert public_uniformity(p, target_bits=2)["exact_arithmetic_sufficient"]
    assert not public_uniformity({**p, "m": 3}, target_bits=2)["exact_arithmetic_sufficient"]


@pytest.mark.parametrize("args", [(1, 2, 1, 2, 1), (1, 2, 1, 3, 2), (True, 2, 1, 5, 1)])
def test_residue_collisions_or_wrong_types_are_not_certified(args):
    with pytest.raises(ValueError):
        public_uniform_bound_squared(*args)


def test_theorem_statement_does_not_cover_the_larger_event_e_bound():
    _, p, _ = screening_rows()[0]
    bounds = witness_bounds(p)
    assert bounds["theorem_statement"] == 4104
    assert bounds["event_E_prime"] == 4104
    assert bounds["event_E"] == bounds["screening_bound"] == 4608


def test_mask_planning_includes_secret_size_and_budgets():
    g1, g2 = plan_masks(8, 4, 2, 1)
    assert (g1, g2) == (28, 195)
    larger_g1, larger_g2 = plan_masks(8, 4, 2, 2)
    assert larger_g1 > g1 and larger_g2 > g2
    with pytest.raises(ValueError):
        plan_masks(8, 4, 5, 1)


def test_fixed_hint_bit_interval_and_search_budget():
    prime_set = {41, 61, 71, 101}
    result = select_hint_modulus(10, 6, prime_set.__contains__, max_ratio=12)
    assert result["primes_within_interval"] == [dict(ratio=4, q=41), dict(ratio=6, q=61)]
    assert result["first_prime_at_or_above_lower_bound"]["q"] == 41
    with pytest.raises(RuntimeError):
        select_hint_modulus(10, 6, lambda _: False, max_ratio=12)
    with pytest.raises(ValueError):
        select_hint_modulus(11, 6, prime_set.__contains__)


@pytest.mark.parametrize("alpha,q,root", [
    (4984012800, 14952038401, 10351923329),
    (9768665088, 117223981057, 39979055194),
    (31470387200, 1132933939201, 186865222933),
])
def test_exact_modulus_and_ntt_root_witnesses(alpha, q, root):
    assert (q - 1) % alpha == 0 and q > 2 * alpha
    assert q % 512 == 1
    assert pow(root, 512, q) == 1 and pow(root, 256, q) == q - 1


def test_flexible_modulus_preserves_bit_length_and_hint_divisibility():
    # Small independently known prime progression, selected near the upper end.
    result = select_flexible_hint_modulus(512, 13, {7681}.__contains__)
    selected = result["selected"]
    assert selected["q"] == 7681
    assert selected["q_bit_length"] == 13
    assert (selected["q"] - 1) % (2 * selected["gamma3"]) == 0
    assert selected["q"] > 4 * selected["gamma3"]


def test_flexible_modulus_aborts_instead_of_fabricating_a_prime():
    with pytest.raises(RuntimeError):
        select_flexible_hint_modulus(512, 12, lambda _: False, max_trials=1)


def test_signed_z_size_uses_the_actual_strict_verification_bound():
    _, p, _ = screening_rows()[0]
    p = {**p, "gamma2": 2**63}
    result = resource_projection(p)
    assert result["signed_z_coefficient_bytes"] == 8
    assert result["z_within_int64"]
    assert not result["current_backend_executable"]


@pytest.mark.parametrize("revision,dirty", [("0" * 40, ""), (ESTIMATOR_COMMIT, " M estimator/lwe.py")])
def test_wrong_tool_revision_or_dirty_checkout_is_rejected(monkeypatch, tmp_path, revision, dirty):
    import experiments.research.luo_parameter_screen as screen
    answers = iter((revision, dirty))
    monkeypatch.setattr(screen.subprocess, "check_output", lambda *args, **kwargs: next(answers))
    with pytest.raises(ValueError, match="clean, pinned"):
        verify_estimator_checkout(tmp_path)
