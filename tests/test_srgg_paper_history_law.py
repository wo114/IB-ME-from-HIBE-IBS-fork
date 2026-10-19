"""Exact tiny laws for the conditional adaptive-history lemma."""
from fractions import Fraction

import pytest

from experiments.research.candidates.srgg.paper_history_law import (
    MAX_QUERY_CAP, conditional_history_bound, current_source_schur_history_status,
)


def _tv(left, right):
    return sum(abs(left.get(k, 0) - right.get(k, 0))
               for k in left.keys() | right.keys()) / 2


def _two_step_law(first, second):
    # The second request depends on the first observed branch.  Abort and
    # fault are distinct atoms, not a single silently discarded failure.
    return {(branch, outcome): first[branch] * probability
            for branch in first for outcome, probability in second[branch].items()}


def test_adaptive_two_step_bound_keeps_abort_and_fault_atoms():
    real_first = {"extract": Fraction(3, 4), "sign": Fraction(1, 4)}
    ref_first = {"extract": Fraction(1, 2), "sign": Fraction(1, 2)}
    real_second = {
        "extract": {"key": Fraction(3, 4), "abort": Fraction(1, 4)},
        "sign": {"signature": Fraction(3, 4), "fault": Fraction(1, 4)},
    }
    ref_second = {
        "extract": {"key": Fraction(1, 2), "abort": Fraction(1, 2)},
        "sign": {"signature": Fraction(1, 2), "fault": Fraction(1, 2)},
    }
    assert _tv(real_first, ref_first) == Fraction(1, 4)
    assert all(_tv(real_second[b], ref_second[b]) == Fraction(1, 4)
               for b in real_first)
    complete_tv = _tv(_two_step_law(real_first, real_second),
                      _two_step_law(ref_first, ref_second))
    assert complete_tv == Fraction(5, 16)

    receipt = conditional_history_bound(
        query_cap=2, initial_joint_tv=0, full_step_kernel_tv=Fraction(1, 4))
    assert receipt["full_history_tv_upper_including_abort_fault"] == "1/2"
    assert complete_tv <= Fraction(receipt["full_history_tv_upper_including_abort_fault"])
    assert receipt["conditioned_success_history_tv_upper"] is None
    assert receipt["premises_verified_by_this_function"] is False


def test_success_conditioning_needs_positive_common_probability():
    # Equal 3/4 success masses; the conditional TV reaches delta/s exactly.
    real = {("ok", "a"): Fraction(1, 2),
            ("ok", "b"): Fraction(1, 4), ("fault",): Fraction(1, 4)}
    ref = {("ok", "a"): Fraction(1, 4),
           ("ok", "b"): Fraction(1, 2), ("fault",): Fraction(1, 4)}
    assert _tv(real, ref) == Fraction(1, 4)
    real_ok = {k: v / Fraction(3, 4) for k, v in real.items() if k[0] == "ok"}
    ref_ok = {k: v / Fraction(3, 4) for k, v in ref.items() if k[0] == "ok"}
    assert _tv(real_ok, ref_ok) == Fraction(1, 3)
    receipt = conditional_history_bound(query_cap=1, initial_joint_tv=0,
        full_step_kernel_tv=Fraction(1, 4),
        success_probability_lower=Fraction(3, 4))
    assert receipt["conditioned_success_history_tv_upper"] == "1/3"
    assert conditional_history_bound(query_cap=1, initial_joint_tv=0,
        full_step_kernel_tv=Fraction(1, 4),
        success_probability_lower=0)["conditioned_success_history_tv_upper"] is None


def test_missing_source_schur_premises_remain_null_even_at_large_cap():
    receipt = current_source_schur_history_status()
    assert receipt["query_cap"] == 1 << 40
    assert receipt["full_history_tv_upper_including_abort_fault"] is None
    assert receipt["conditioned_success_history_tv_upper"] is None
    assert receipt["source_schur_application_certified"] is False
    assert len(receipt["missing_inputs"]) == 3
    assert conditional_history_bound(query_cap=1, initial_joint_tv=0,
        full_step_kernel_tv=None)["full_history_tv_upper_including_abort_fault"] is None
    assert conditional_history_bound(query_cap=1, initial_joint_tv=None,
        full_step_kernel_tv=0)["full_history_tv_upper_including_abort_fault"] is None


def test_large_budget_is_exact_and_zero_budget_uses_only_initial_law():
    receipt = conditional_history_bound(query_cap=MAX_QUERY_CAP,
        initial_joint_tv=0, full_step_kernel_tv=Fraction(1, 2**192))
    assert receipt["full_history_tv_upper_including_abort_fault"] == str(Fraction(1, 2**152))
    zero = conditional_history_bound(query_cap=0, initial_joint_tv=Fraction(1, 7),
        full_step_kernel_tv=None)
    assert zero["full_history_tv_upper_including_abort_fault"] == "1/7"
    assert zero["mathematical_bound_given_premises"] is True


@pytest.mark.parametrize("kwargs", [
    {"query_cap": True, "initial_joint_tv": 0, "full_step_kernel_tv": 0},
    {"query_cap": MAX_QUERY_CAP + 1, "initial_joint_tv": 0, "full_step_kernel_tv": 0},
    {"query_cap": 1, "initial_joint_tv": 0.0, "full_step_kernel_tv": 0},
    {"query_cap": 1, "initial_joint_tv": 0, "full_step_kernel_tv": -1},
    {"query_cap": 1, "initial_joint_tv": 0, "full_step_kernel_tv": 0,
     "success_probability_lower": Fraction(3, 2)},
])
def test_invalid_inputs_do_not_create_a_history_claim(kwargs):
    with pytest.raises(ValueError):
        conditional_history_bound(**kwargs)
