"""Exact checks for the 2026-10-04 primitive admission review.

Only public branch bits and tiny integer matrices are modelled. This script does
not implement, attack, or establish the security of a lattice cryptosystem.
No randomness, Gaussian sampler, or production keys are used.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from fractions import Fraction
from itertools import product
from pathlib import Path


def branch_distribution(queries, *, fixed_identity: bool):
    """Enumerate a cached random bit per identity or per (identity, message).

    Foo--Li Figure 9 G0--G2 uses the former, G3--G5 the latter. Repeated
    identical queries reuse their bit in both models.
    """
    keys = [identity if fixed_identity else (identity, message)
            for identity, message in queries]
    distinct = list(dict.fromkeys(keys))
    if len(distinct) > 16:
        raise ValueError("This exact enumeration is limited to 16 distinct keys")
    counts = Counter()
    for assignment in product((0, 1), repeat=len(distinct)):
        oracle = dict(zip(distinct, assignment))
        counts[tuple(oracle[key] for key in keys)] += 1
    return {bits: Fraction(count, 2 ** len(distinct))
            for bits, count in sorted(counts.items())}


def total_variation(left, right):
    return sum((abs(left.get(bits, 0) - right.get(bits, 0))
                for bits in left.keys() | right.keys()), Fraction()) / 2


def multiply_mod(left, right, q):
    if q <= 1 or not left or not right:
        raise ValueError("Nonempty matrices and q > 1 are required")
    if any(len(row) != len(left[0]) for row in left):
        raise ValueError("Ragged left matrix")
    if any(len(row) != len(right[0]) for row in right):
        raise ValueError("Ragged right matrix")
    if len(left[0]) != len(right):
        raise ValueError("Incompatible matrix dimensions")
    return [[sum(a * b for a, b in zip(row, column)) % q
             for column in zip(*right)] for row in left]


def determinant_2(matrix):
    (a, b), (c, d) = matrix
    return a * d - b * c


def inverse_2_mod(matrix, q):
    (a, b), (c, d) = matrix
    factor = pow(determinant_2(matrix), -1, q)
    return [[d * factor % q, -b * factor % q],
            [-c * factor % q, a * factor % q]]


def matrix_checks():
    # Noncommuting identity-prefix matrices: R_id = H2 H1, not H1 H2.
    q, a = 7, [[1, 2]]
    h1, h2 = [[1, 1], [0, 1]], [[1, 0], [1, 1]]
    sequential = multiply_mod(multiply_mod(a, inverse_2_mod(h1, q), q),
                              inverse_2_mod(h2, q), q)
    product_form = multiply_mod(a, inverse_2_mod(multiply_mod(h2, h1, q), q), q)
    reversed_form = multiply_mod(a, inverse_2_mod(multiply_mod(h1, h2, q), q), q)

    # R is invertible mod q but not unimodular over Z. R T_A spans only
    # an index-2 sublattice of the target kernel lattice, despite full rank.
    kernel_a, basis, r = [[1, 0]], [[7, 0], [0, 1]], [[2, 0], [0, 1]]
    kernel_b = multiply_mod(kernel_a, inverse_2_mod(r, q), q)
    transformed = [[14, 0], [0, 1]]
    missed_vector = [[7], [0]]

    # Foo--Li's plus convention corresponds to the negative MP12 trapdoor.
    r_plus, gadget = [[1, 0], [2, 1]], [[1, 2]]
    ar = multiply_mod(a, r_plus, q)
    extension = [[(x + y) % q for x, y in zip(ar[0], gadget[0])]]
    f = [a[0] + extension[0]]
    negative_stack = [[-1, 0], [-2, -1], [1, 0], [0, 1]]
    positive_stack = [[1, 0], [2, 1], [1, 0], [0, 1]]
    return {
        "abb10_prefix_order": {
            "q": q, "A": a, "H1": h1, "H2": h2,
            "sequential_A_H1inv_H2inv": sequential,
            "A_inverse_H2H1": product_form,
            "A_inverse_H1H2": reversed_form,
            "correct_order_agrees": sequential == product_form,
            "reversed_order_differs": sequential != reversed_form,
        },
        "abb10_full_basis": {
            "q": q, "A": kernel_a, "T_A": basis, "R": r, "B": kernel_b,
            "R_T_A": transformed,
            "B_R_T_A_mod_q": multiply_mod(kernel_b, transformed, q),
            "target_determinant": q,
            "transformed_determinant": abs(determinant_2(transformed)),
            "sublattice_index": abs(determinant_2(transformed)) // q,
            "missed_kernel_vector": missed_vector,
            "B_missed_vector_mod_q": multiply_mod(kernel_b, missed_vector, q),
            "first_basis_coefficient_required": "1/2",
        },
        "foo_li_mp12_sign_convention": {
            "q": q, "A": a, "R_plus": r_plus, "G": gadget,
            "A_id_b": extension, "F": f,
            "F_negative_stack_mod_q": multiply_mod(f, negative_stack, q),
            "F_positive_stack_mod_q": multiply_mod(f, positive_stack, q),
        },
    }


def audit_report():
    cases = {
        "two_messages_same_identity": [("id-A", "m-0"), ("id-A", "m-1")],
        "three_messages_same_identity": [("id-A", f"m-{i}") for i in range(3)],
        "repeated_same_message_control": [("id-A", "m-0"), ("id-A", "m-0")],
        "different_identities_control": [("id-A", "m-0"), ("id-B", "m-0")],
    }
    findings = {}
    for name, queries in cases.items():
        fixed = branch_distribution(queries, fixed_identity=True)
        by_message = branch_distribution(queries, fixed_identity=False)
        all_equal = lambda dist: sum((p for bits, p in dist.items()
                                      if len(set(bits)) <= 1), Fraction())
        encode = lambda dist: {"".join(map(str, bits)): str(p)
                               for bits, p in dist.items()}
        findings[name] = {
            "queries": queries,
            "G2_fixed_identity_distribution": encode(fixed),
            "G3_per_message_distribution": encode(by_message),
            "G2_all_bits_equal_probability": str(all_equal(fixed)),
            "G3_all_bits_equal_probability": str(all_equal(by_message)),
            "bit_transcript_total_variation": str(total_variation(fixed, by_message)),
        }
    return {
        "schema_version": 1,
        "security_claim": "none",
        "method": "exact finite enumeration and modular/integer arithmetic",
        "monte_carlo_repetitions": 0,
        "scope": "proof-transcript consistency and algebra examples; no forgery attack",
        "foo_li_fig9_branch_checks": findings,
        "algebra_checks": matrix_checks(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Optional JSON destination")
    args = parser.parse_args()
    serialized = json.dumps(audit_report(), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(serialized, encoding="utf-8")
    else:
        print(serialized, end="")


if __name__ == "__main__":
    main()
