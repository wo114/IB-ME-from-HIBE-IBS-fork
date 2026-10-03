"""Independent expected outcomes for research checks, not cryptographic tests."""

from fractions import Fraction
from pathlib import Path
import runpy

import pytest


AUDIT = runpy.run_path(str(Path(__file__).resolve().parents[1] /
                          "experiments/research/primitive_gate_audit.py"))
distribution = AUDIT["branch_distribution"]
distance = AUDIT["total_variation"]


def test_two_messages_expose_joint_distribution_gap():
    queries = [("A", "first"), ("A", "second")]
    fixed = distribution(queries, fixed_identity=True)
    independent = distribution(queries, fixed_identity=False)
    assert fixed == {(0, 0): Fraction(1, 2), (1, 1): Fraction(1, 2)}
    assert independent == {bits: Fraction(1, 4) for bits in [(0, 0), (0, 1), (1, 0), (1, 1)]}
    assert distance(fixed, independent) == Fraction(1, 2)
    # Every single-response marginal remains uniform despite the joint gap.
    for result in [fixed, independent]:
        for position in [0, 1]:
            assert sum(p for bits, p in result.items() if bits[position] == 0) == Fraction(1, 2)


@pytest.mark.parametrize("queries", [[], [("A", "one")],
    [("A", "one"), ("A", "one")], [("A", "one"), ("B", "one")]])
def test_controls_do_not_introduce_a_gap(queries):
    fixed = distribution(queries, fixed_identity=True)
    independent = distribution(queries, fixed_identity=False)
    assert sum(fixed.values()) == sum(independent.values()) == 1
    assert distance(fixed, independent) == 0


def test_three_messages_have_three_quarters_distance():
    queries = [("A", str(i)) for i in range(3)]
    assert distance(distribution(queries, fixed_identity=True),
                    distribution(queries, fixed_identity=False)) == Fraction(3, 4)


def test_enumeration_limit_is_explicit():
    with pytest.raises(ValueError):
        distribution([("A", str(i)) for i in range(17)], fixed_identity=False)


def test_noncommutative_abb10_order():
    result = AUDIT["matrix_checks"]()["abb10_prefix_order"]
    assert result["sequential_A_H1inv_H2inv"] == [[0, 1]]
    assert result["A_inverse_H2H1"] == [[0, 1]]
    assert result["A_inverse_H1H2"] == [[6, 3]]


def test_full_rank_transformed_set_is_not_a_full_basis():
    result = AUDIT["matrix_checks"]()["abb10_full_basis"]
    assert result["B"] == [[4, 0]]
    assert result["B_R_T_A_mod_q"] == [[0, 0]]
    assert result["B_missed_vector_mod_q"] == [[0]]
    assert result["transformed_determinant"] == 14
    assert result["target_determinant"] == 7
    assert result["sublattice_index"] == 2


def test_plus_trapdoor_requires_negative_mp12_stack():
    result = AUDIT["matrix_checks"]()["foo_li_mp12_sign_convention"]
    assert result["A_id_b"] == [[6, 4]]
    assert result["F_negative_stack_mod_q"] == [[1, 2]]
    assert result["F_positive_stack_mod_q"] == [[4, 6]]


@pytest.mark.parametrize("left,right,q", [([[1, 2]], [[1, 2]], 7),
    ([[1], [1, 2]], [[1]], 7), ([[1]], [[1]], 1)])
def test_matrix_check_rejects_invalid_inputs(left, right, q):
    with pytest.raises(ValueError):
        AUDIT["multiply_mod"](left, right, q)
