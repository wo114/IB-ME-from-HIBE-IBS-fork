"""Exact small-oracle probability checks, not a cryptographic attack run."""
from fractions import Fraction as F
from itertools import product
import json

import pytest

from experiments.research.candidates.srgg.classical_cost import (
    build_report, owner_fork_cost, programming_collision_cost,
)


def eta(c):
    return (c & 3) ^ (c >> 2)


def model_run(tape, replies, policy):
    """Two free entries, with an intervening tape/prefix-defined program.

    Collision abort is retained. The programmed entry is assumed to have
    actually returned its response; this finite model checks probabilities
    only. Ring relations and valid-response extraction are tested elsewhere.
    """
    a, b = replies
    if (a+tape) % 16 == 15:
        return None
    # The second input depends on a: replay must preserve the pivot prefix.
    inputs = (("free", 0), ("free", 1, a))
    choice = (a+2*b+tape+policy) % 17
    if choice == 0:
        return ("sign", ("program", a, tape), (a+tape) % 16)
    if choice == 1:
        return None
    i = (a+b+policy) % 2
    return (i, inputs[i], replies[i])


@pytest.mark.parametrize("policy", range(4))
def test_replayable_programmed_oracle_fork_bound_by_independent_enumeration(policy):
    space = tuple(product(range(2), range(16), range(16)))
    a = b = fork = F(0)
    for tape, first, second in space:
        result = model_run(tape, (first, second), policy)
        if result is None:
            continue
        if result[0] == "sign":
            a += F(1, len(space))
            continue
        b += F(1, len(space))
        pivot = result[0]
        suffixes = tuple(product(range(16), repeat=2-pivot))
        for suffix in suffixes:
            replies = suffix if pivot == 0 else (first,)+suffix
            again = model_run(tape, replies, policy)
            if again is not None and again[0] == pivot:
                assert again[1] == result[1]
                if eta(again[2]) != eta(result[2]):
                    fork += F(1, len(space)*len(suffixes))
    fork_lower = b*b/2-b/4
    assert fork_lower > 0
    assert fork >= fork_lower
    # Compare the exact fair-choice solver with the general conservative
    # theorem, independently of how the successful mass splits into owners.
    cost = owner_fork_cost(advantage=a+b, free_queries=2, degree=4)
    assert (a+fork)/2 >= F(cost["fair_owner_solver_short_kernel_success_lower_exact"])


def test_single_free_query_model_has_a_positive_uniform_owner_solver_lower_bound():
    # The unified bound is deliberately more conservative than the fork-only
    # bound. This separate exact experiment makes both bounds nonvacuous.
    a, b = F(1, 16), F(14, 16)
    accepting = tuple(range(1, 15))
    exact_fork = sum(F(1, 256) for c, d in product(accepting, repeat=2)
                     if eta(c) != eta(d))
    assert exact_fork >= b*b-b/4 > 0
    cost = owner_fork_cost(advantage=a+b, free_queries=1, degree=4)
    lower = F(cost["fair_owner_solver_short_kernel_success_lower_exact"])
    assert 0 < lower <= (a+exact_fork)/2


def test_accepting_one_effective_coset_refutes_using_full_challenge_collision_rate():
    accepting = [c for c in range(16) if eta(c) == 0]
    epsilon = F(len(accepting), 16)
    actual_good_fork = sum(F(1, 256) for c, d in product(accepting, repeat=2)
                          if eta(c) != eta(d))
    assert actual_good_fork == 0
    assert epsilon*epsilon-epsilon/F(16) > actual_good_fork
    assert max(F(0), epsilon*epsilon-epsilon/F(4)) == actual_good_fork


def test_oracle_owner_is_immutable_and_program_collision_aborts_without_overwrite():
    # A standalone model of the replay lemma's premises: rechecking a free
    # entry cannot turn it into a sign-owned entry, even with the same c.
    table, returned, free_replies = {}, set(), iter((3, 9))

    def query(point):
        if point not in table:
            table[point] = ("free", next(free_replies))
        return table[point][1]

    def program_and_return(point, c, z, accepted):
        if point in table or not accepted:
            raise RuntimeError("global bad: no programming or return")
        table[point] = ("sign", c)
        returned.add((point, c, z))

    assert query(("W0", "m")) == query(("W0", "m")) == 3
    before = dict(table)
    with pytest.raises(RuntimeError):
        program_and_return(("W0", "m"), 3, 0, True)
    assert table == before and not returned
    with pytest.raises(RuntimeError):
        program_and_return(("W1", "m"), 2, 0, False)
    assert table == before and not returned
    program_and_return(("W1", "m"), 2, 0, True)
    assert query(("W1", "m")) == 2
    assert table[("W1", "m")][0] == "sign"
    assert (("W1", "m"), 2, 0) in returned
    assert query(("W2", "m")) == 9


def test_owner_split_bound_holds_for_every_finite_partition_and_query_budget():
    # Directly enumerates mass splits; no sampling and no implementation's
    # case distinction are used to construct the independent lower envelope.
    for q in (1, 2, 3, 16):
        for u, v in product(range(33), repeat=2):
            if u+v > 32:
                continue
            a, b = F(u, 32), F(v, 32)
            exact_lower = (a+max(F(0), b*b/q-b/F(16)))/2
            report = owner_fork_cost(advantage=a+b, free_queries=q, degree=8)
            assert exact_lower >= F(report["fair_owner_solver_short_kernel_success_lower_exact"])


@pytest.mark.parametrize("field,value", [
    ("advantage", 1.1), ("advantage", True), ("advantage", -1),
    ("simulation_tv", "3/2"), ("free_queries", True), ("free_queries", 0),
    ("free_queries", 2**65), ("degree", 3), ("degree", False),
])
def test_cost_requires_exact_bounded_hypotheses(field, value):
    args = dict(advantage=F(1, 10), free_queries=1, degree=512, simulation_tv=0)
    args[field] = value
    with pytest.raises(ValueError):
        owner_fork_cost(**args)


def test_statistical_error_is_subtracted_before_quotient_forking_not_called_security():
    no_information = owner_fork_cost(advantage=F(1, 2**128), free_queries=2**40,
        degree=512, simulation_tv=F(1, 2**100))
    assert no_information["positive_conditional_lower_bound"] is False
    assert no_information["actual_matrix_hardness_established"] is False
    assert no_information["actual_IBS_simulation_distance_established"] is False
    useful = owner_fork_cost(advantage=F(1, 2**128), free_queries=2**40,
        degree=512, simulation_tv=F(1, 2**134))
    assert useful["positive_conditional_lower_bound"] is True
    assert F(useful["fair_owner_solver_short_kernel_success_lower_exact"]) < F(1, 2**298)


def test_collision_ledger_trades_unused_ideal_entropy_for_small_exact_fractions():
    row = programming_collision_cost(signing_queries=2**40, max_sign_attempts=16,
        free_entries=2**40, commitment_bits=36351)
    assert row["arithmetic_commitment_bits_used"] == 512
    assert F(row["conditional_programming_collision_upper_exact"]) < F(1, 2**423)
    assert row["finite_sampler_TV_multiplied_by_table_size"] is False
    zero = programming_collision_cost(signing_queries=0, max_sign_attempts=16,
        free_entries=1, commitment_bits=0)
    assert F(zero["conditional_programming_collision_upper_exact"]) == 0


def test_report_preserves_conditional_scope_and_source_hashes():
    report = build_report()
    deep = next(row for row in report["profiles"] if row["profile"] == "query-bounded-deep")
    large = deep["scenarios"][-1]
    assert large["total_distance_is_a_composition_hypothesis"] is True
    assert large["fixed_key_advantage_scenarios"][-1]["positive_conditional_lower_bound"] is True
    assert report["actual_entropy_bytes"] == 0
    assert report["security_claim"] == "none"
    assert report["backend_admitted"] is report["parameters_are_formal"] is False
    assert report["nist_security_category"] is None
    json.dumps(report)
