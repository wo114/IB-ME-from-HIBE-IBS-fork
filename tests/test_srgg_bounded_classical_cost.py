"""Independent exact owner optimizations and premise/ledger boundary checks."""
from dataclasses import fields, replace
from fractions import Fraction as F
from itertools import product
import json

import pytest

from experiments.research.candidates.srgg.bounded_classical_cost import (
    IBSLedger, Premises, ibs_ledger_bound, owner_split_lower,
    residual_owner_lower, run_success_lower,
)
from experiments.research.candidates.srgg.classical_cost import owner_fork_cost
from experiments.research.candidates.srgg import bounded_classical_cost as bounded_cost


def unpack(value):
    return None if value is None else F(int(value["numerator_hex"], 16), int(value["denominator_hex"], 16))


def all_premises():
    return Premises(**{field.name: True for field in fields(Premises)})


def zero_ledger():
    # This is an explicitly chosen arithmetic fixture, never a measured ledger.
    return IBSLedger(**{field.name: F(0) for field in fields(IBSLedger)})


@pytest.mark.parametrize("degree,expected", [(2, F(7, 16)), (4, F(39, 64)), (8, F(735, 1024))])
def test_q1_linear_tail_is_required_and_its_minimum_is_attained(degree, expected):
    # At total owner mass 1, independently minimize b²-(1+kappa)b+1
    # by completing the square. This refutes applying the q>=2 formula at q=1.
    kappa = F(1, 2**(degree//2))
    b = (1+kappa)/2
    a = 1-b
    exact = a+b*b-b*kappa
    assert exact == expected
    assert owner_split_lower(sign_success=a, free_success=b, free_queries=1, degree=degree) == exact
    assert residual_owner_lower(residual_success=1, free_queries=1, degree=degree) == exact
    assert exact < 1-kappa


@pytest.mark.parametrize("degree", [2, 4, 8, 512])
@pytest.mark.parametrize("q", [1, 2, 3, 128])
def test_uniform_bound_is_below_every_independently_enumerated_owner_split(degree, q):
    kappa = F(1, 2**(degree//2))
    for total in range(17):
        t = F(total, 16)
        lower = residual_owner_lower(residual_success=t, free_queries=q, degree=degree)
        for free in range(total+1):
            b, a = F(free, 16), F(total-free, 16)
            independent = a+max(F(0), b*b/q-b*kappa)
            assert 0 <= lower <= independent <= 1


@pytest.mark.parametrize("degree", [2, 4, 8, 512])
@pytest.mark.parametrize("q", [1, 2, 128])
def test_envelope_attains_the_independent_quadratic_minimizer(degree, q):
    kappa = F(1, 2**(degree//2))
    for t in (F(0), F(1, 17), F(1, 2), F(3, 4), F(1)):
        # The minimizer follows from completing a square, not a scan over
        # the implementation's returned branch or any float optimization.
        b = min(t, q*(1+kappa)/2)
        independently_attained = t-b+max(F(0), b*b/q-b*kappa)
        assert residual_owner_lower(residual_success=t, free_queries=q, degree=degree) == independently_attained


@pytest.mark.parametrize("degree,q", [(2, 1), (4, 1), (8, 2), (512, 128)])
def test_convex_averaging_and_monotonicity_across_all_breakpoints(degree, q):
    kappa = F(1, 2**(degree//2))
    grid = {F(x, 16) for x in range(17)}
    grid.update(point for point in (q*kappa, q*(1+kappa)/2) if 0 <= point <= 1)
    ordered = sorted(grid)
    previous = F(0)
    for point in ordered:
        value = residual_owner_lower(residual_success=point, free_queries=q, degree=degree)
        assert value >= previous
        previous = value
    for x, y in product(ordered, repeat=2):
        lhs = residual_owner_lower(residual_success=(x+3*y)/4, free_queries=q, degree=degree)
        rhs = (residual_owner_lower(residual_success=x, free_queries=q, degree=degree)
            +3*residual_owner_lower(residual_success=y, free_queries=q, degree=degree))/4
        assert lhs <= rhs


@pytest.mark.parametrize("degree,q", [(2, 1), (4, 1), (8, 2), (512, 128)])
def test_actual_owner_bound_dominates_frozen_fair_choice_bound(degree, q):
    for numerator in range(33):
        p = F(numerator, 32)
        old = owner_fork_cost(advantage=p, free_queries=q, degree=degree, simulation_tv=0)
        fair_lower = F(old["fair_owner_solver_short_kernel_success_lower_exact"])
        adaptive_lower = run_success_lower(success=p, free_queries=q, degree=degree)
        assert adaptive_lower >= 2*fair_lower


def test_unseen_success_requires_full_challenge_guessing():
    assert run_success_lower(success=F(1, 16), free_queries=1, degree=4) == 0
    assert run_success_lower(success=1, free_queries=2, degree=4) == F(105, 512)
    # A single eta class gives zero good forks despite a positive full-c
    # collision-based expression, independently counted over all n4 replies.
    accepting = [c for c in range(16) if ((c & 3) ^ (c >> 2)) == 0]
    count = sum(1 for c, d in product(accepting, repeat=2)
                if ((c & 3) ^ (c >> 2)) != ((d & 3) ^ (d >> 2)))
    assert count == 0
    b = F(len(accepting), 16)
    assert b*b-b/F(16) > 0
    assert owner_split_lower(sign_success=0, free_success=b, free_queries=1, degree=4) == 0


def test_ledger_counts_both_endpoints_before_hidden_identity_division():
    ledger = replace(zero_ledger(), delta0=F(1, 16), epsilon_image=F(1, 128),
        delta_pub=F(1, 256), delta_sim=F(1, 512), delta_known=F(1, 1024))
    result = ibs_ledger_bound(advantage=F(3, 4), identity_queries=4, sign_attempts=3,
        free_queries=2, degree=8, ledger=ledger, premises=all_premises())
    independent_loss = F(1, 16)+4*(F(1, 128)+F(1, 256))+3*(F(1, 512)+F(1, 1024))
    p = (F(3, 4)-independent_loss)/4
    assert unpack(result["numerator_loss_upper"]) == independent_loss
    assert unpack(result["target_Run_success_lower"]) == p
    t = p-F(1, 256)
    assert unpack(result["actual_owner_extraction_success_lower"]) == t*t/2-t/16
    assert result["security_claim"] == "none"
    assert result["parameters_are_formal"] is result["backend_admitted"] is False
    assert result["nist_security_category"] is None
    assert result["actual_entropy_bytes"] == 0 and result["draw_performed"] is False
    assert result["complete_production_game_correspondence_proved"] is False


@pytest.mark.parametrize("name", [field.name for field in fields(IBSLedger)])
def test_any_unknown_ledger_item_stays_null_even_if_its_count_is_zero(name):
    ledger = replace(zero_ledger(), **{name: None})
    result = ibs_ledger_bound(advantage=1, identity_queries=1, sign_attempts=0,
        free_queries=1, degree=8, ledger=ledger, premises=all_premises())
    assert result["unresolved_ledger_terms"] == (name,)
    assert result["numerator_loss_upper"] is None
    assert result["target_Run_success_lower"] is result["actual_owner_extraction_success_lower"] is None


@pytest.mark.parametrize("name", [field.name for field in fields(Premises)])
@pytest.mark.parametrize("value", [False, None])
def test_any_unassumed_correspondence_cannot_produce_a_bound(name, value):
    premises = replace(all_premises(), **{name: value})
    result = ibs_ledger_bound(advantage=1, identity_queries=1, sign_attempts=1,
        free_queries=1, degree=8, ledger=zero_ledger(), premises=premises)
    assert result["unassumed_premises"] == (name,)
    assert unpack(result["numerator_loss_upper"]) == 0
    assert result["target_Run_success_lower"] is result["actual_owner_extraction_success_lower"] is None


def test_vacuous_numeric_ledger_still_explicit_and_large_exact_json_is_supported():
    ledger = replace(zero_ledger(), delta0=1, delta_zk=1)
    result = ibs_ledger_bound(advantage=1, identity_queries=8, sign_attempts=8,
        free_queries=128, degree=512, ledger=ledger, premises=all_premises())
    assert unpack(result["numerator_loss_upper"]) == 9
    assert unpack(result["target_Run_success_lower"]) == 0
    tiny = replace(zero_ledger(), commitment_collision=F(1, 2**36351))
    record = ibs_ledger_bound(advantage=1, identity_queries=1, sign_attempts=1,
        free_queries=128, degree=512, ledger=tiny, premises=all_premises())
    restored = json.loads(json.dumps(record))
    assert unpack(restored["ledger"]["commitment_collision"]) == F(1, 2**36351)


@pytest.mark.parametrize("field,value", [
    ("success", True), ("success", 0.5), ("success", -1), ("success", "2"),
    ("free_queries", False), ("free_queries", 0), ("free_queries", 2**65),
    ("degree", True), ("degree", 3), ("degree", 8192),
])
def test_probability_apis_require_exact_bounded_inputs(field, value):
    args = dict(success=F(1, 2), free_queries=2, degree=8)
    args[field] = value
    with pytest.raises(ValueError):
        run_success_lower(**args)


def test_disjoint_masses_and_explicit_premise_and_ledger_types():
    with pytest.raises(ValueError):
        owner_split_lower(sign_success=F(3, 4), free_success=F(1, 2), free_queries=1, degree=4)
    with pytest.raises(ValueError):
        replace(all_premises(), ideal_classical_free_h2=1)
    with pytest.raises(ValueError):
        replace(zero_ledger(), delta0=0.25)
    with pytest.raises(TypeError):
        IBSLedger()
    with pytest.raises(TypeError):
        Premises()


@pytest.mark.parametrize("text", [
    "1e-1000000000", "1E+1000000000", " 1/2", "1/2 ", "1 /2", "1/ 2",
    "1/0", "1/-2", "00", "01/2", "0.5", "", "+", "-", "1_0/20",
    "\uff11/2", "1/2\n", "1/"+"9"*4097, "9"*4097, "9"*8195,
])
def test_bad_or_overlarge_text_is_rejected_before_fraction_constructor(monkeypatch, text):
    calls = []

    def forbidden(value):
        calls.append(value)
        raise AssertionError("Fraction constructor must not be reached")

    monkeypatch.setattr(bounded_cost, "Fraction", forbidden)
    with pytest.raises(ValueError):
        bounded_cost.run_success_lower(success=text, free_queries=1, degree=8)
    assert calls == []


@pytest.mark.parametrize("text,value", [("0", F(0)), ("+0", F(0)), ("-0", F(0)),
    ("1", F(1)), ("+1", F(1)), ("1/2", F(1, 2)), ("+1/2", F(1, 2))])
def test_exact_bounded_rational_text_and_sign_boundaries(text, value):
    assert run_success_lower(success=text, free_queries=1, degree=8) == run_success_lower(
        success=value, free_queries=1, degree=8)


@pytest.mark.parametrize("value", [True, False, "-1", "-1/2", "2/1", "3/2"])
def test_negative_positive_overflow_and_boolean_probabilities_are_rejected(value):
    with pytest.raises(ValueError):
        run_success_lower(success=value, free_queries=1, degree=8)


def test_fraction_inputs_keep_large_exact_denominators_and_resource_boundary():
    denominator = 2**(bounded_cost.MAX_RATIONAL_BITS-1)
    assert run_success_lower(success=F(1, denominator), free_queries=1, degree=8) == 0
    with pytest.raises(ValueError):
        run_success_lower(success=F(1, 2**bounded_cost.MAX_RATIONAL_BITS), free_queries=1, degree=8)
    with pytest.raises(ValueError):
        run_success_lower(success=2**bounded_cost.MAX_RATIONAL_BITS, free_queries=1, degree=8)
