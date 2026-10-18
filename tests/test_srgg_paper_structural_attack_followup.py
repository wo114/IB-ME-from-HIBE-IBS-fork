"""Independent finite checks of the final-column 2Q kernel boundary."""
from fractions import Fraction
from itertools import product

import pytest

from experiments.research.candidates.srgg.paper_structural_attack_followup import (
    build_report, crt_component_lift_floors, final_column_shift,
    kernel_certificate,
)


def negacyclic_multiply(left, right):
    n = len(left)
    out = [0] * n
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            k = i + j
            out[k % n] += (-1 if k >= n else 1) * a * b
    return tuple(out)


@pytest.mark.parametrize("n,Q", [(4, 3), (8, 5), (16, 7)])
def test_universal_last_column_kernel_with_arbitrary_public_target(n, Q):
    zeta_star = (1,) + (0,) * (n//2-1) + (-1,) + (0,) * (n//2-1)
    h = tuple((7*i*i-11*i+3) % Q for i in range(n))
    for direction in (-1, 1):
        for i in range(n//2):
            delta = final_column_shift(n, Q, index=i, direction=direction)
            last = tuple(Q*a-2*b for a,b in zip(zeta_star,h))
            assert all(value % (2*Q) == 0 for value in negacyclic_multiply(last,delta))
            assert sum(x*x for x in delta) == 2*Q*Q


def test_restricted_last_column_Q_multiple_minimum_is_exact_by_exhaustion():
    n, Q = 4, 3
    zeta = (1,0,-1,0)
    qualifying = []
    for t in product(range(-2,3), repeat=n):
        if t == (0,)*n:
            continue
        if all(x % 2 == 0 for x in negacyclic_multiply(zeta,t)):
            qualifying.append(sum((Q*x)**2 for x in t))
    assert min(qualifying) == 2*Q*Q
    cert = kernel_certificate(n,Q,Fraction(5))
    assert cert["restricted_minimum_norm_squared"] == 2*Q*Q
    assert cert["witness_inside_single_signature_radius"]


def test_crt_component_coefficient_floor_is_exact_but_not_attack_cost():
    Q = 3*5*7
    floors = crt_component_lift_floors(Q)
    assert [r["nonzero_centered_coefficient_abs_lower"] for r in floors] == [35,21,15]
    for row in floors:
        m, floor = row["prime_power"], row["nonzero_centered_coefficient_abs_lower"]
        assert Q == m*floor
        assert all(floor % p == 0 for p in (3,5,7) if p != m)
        assert row["single_polynomial_factor_floor_is_sharp"] is None
        assert not row["global_short_solution_or_attack_cost_inferred"]


@pytest.mark.parametrize("args", [(1,3), (3,3), (514,3), (4,2), (4,0), (4,2**33)])
def test_invalid_sizes_are_rejected(args):
    with pytest.raises(ValueError):
        final_column_shift(*args)


@pytest.fixture(scope="module")
def report():
    pytest.importorskip("sage.all", reason="original n512 backend requires WSL Sage")
    return build_report()


def test_all_original_rows_have_exact_restricted_kernel_but_no_attack_cost(report):
    assert [r["profile"] for r in report["rows"]] == ["PARAM-I","PARAM-II","PARAM-III"]
    for d,row in zip((2,3,4),report["rows"]):
        assert (row["n"],row["d"],row["w"],row["Q"]) == (512,d,2,15744063)
        assert row["universal_for_every_public_A_and_identity_h"]
        assert row["restricted_minimum_norm_squared"] == 2*15744063**2
        assert row["witness_inside_single_signature_radius"]
        assert row["explicit_construction_BKZ_calls"] == 0
        assert [x["prime_power"] for x in row["CRT_component_lift_floors"]] == [3,961,43,127]
        assert row["full_ring_HNF_MSIS_attack_cost"] is None
        assert row["CRT_subfield_attack_cost"] is None
        assert row["successful_replacement_probability"] is None
        assert row["security_claim"] == "none"
        assert row["backend_admitted"] is False
        assert row["parameters_are_formal"] is False
        assert row["nist_security_category"] is None


def test_one_actual_default_param_i_signature_passes_kernel_and_object_checks_but_not_norm(report):
    probe = report["one_actual_signature_probe"]["probe"]
    assert report["one_actual_signature_probe"]["profile"] == "PARAM-I"
    assert probe["valid_original_required_and_checked"]
    assert probe["published_last_column_checked"] and probe["all_rows_kernel_checked"]
    assert probe["canonical_alternative_object"] and probe["distinct_canonical_signature"]
    assert probe["recovered_commitment_equal"]
    assert probe["tested_pair_positions"] == 256
    assert probe["eligible_pair_positions"] == 0
    assert probe["best_shift_norm_squared"] > probe["signature_norm_squared_cap"]
    assert probe["best_replacement_accepted"] is False
    assert probe["success_probability"] is None
    assert not probe["private_material_exported"]
    assert all(route["actual_attack_cost"] is None for route in report["routes"])
    assert report["full_ring_HNF_MSIS_attack_cost"] is None
    assert report["CRT_subfield_attack_cost"] is None
    assert report["accepted_setup_root_structural_attack_cost"] is None
    assert report["security_claim"] == "none"
