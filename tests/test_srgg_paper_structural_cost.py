"""Public algebra checks for the original SRGG short-kernel cost receipt."""
from fractions import Fraction
import json
from pathlib import Path

import pytest

from experiments.research.candidates.srgg.paper_structural_cost import (
    build_report, one_shift_norm, row_certificate, subring_projection_obstruction,
)
from experiments.research.candidates.srgg.paper_profiles import profiles


def test_all_original_rows_have_the_exact_universal_q_kernel():
    expected = ((2, 4096, 4608), (3, 6144, 6656), (4, 8192, 8704))
    for source, (d, a_count, response_count) in zip(profiles, expected):
        row = row_certificate(source)
        q, gamma = source.Q, Fraction(source.gamma)
        assert row["original_inputs"]["d"] == d
        assert row["original_inputs"]["gamma_exact_rational"] == str(gamma)
        assert row["original_inputs"]["gamma_published_decimal"] == str(source.gamma)
        assert row["original_inputs"]["response_coefficient_count"] == response_count
        kernel = row["Q_MSIS_short_kernel"]
        assert kernel["zero_mod_Q_for_every_public_matrix"]
        assert kernel["euclidean_norm"] == q and q < 2 * gamma
        assert kernel["sparse_construction_public_matrix_reads"] == 0
        assert kernel["sparse_construction_BKZ_calls"] == 0
        assert row["actual_2Q_verification"]["eligible_shift_coordinates"] == a_count
        assert row["actual_2Q_verification"]["witness_inside_original_signature_norm_ball"]
        assert [item["residue_factor_degree"] for item in row["CRT"]] == [256, 32, 256, 8]
        assert [item["residue_factor_count"] for item in row["CRT"]] == [2, 16, 2, 64]
        assert all(item["Qe0_is_zero_in_component"] for item in row["CRT"])


def test_best_single_coordinate_shift_formula_is_exact_and_conditional():
    q = 31
    values = (7, -20, 0, 5)
    norm2 = sum(x*x for x in values)
    cap = 2000
    exact = min(sum((x + sign*q if i == j else x)**2
                    for i, x in enumerate(values))
                for j in range(len(values)) for sign in (-1, 1))
    result = one_shift_norm(norm_squared=norm2,
                            max_abs_a_coordinate=max(abs(x) for x in values),
                            modulus=q, norm_cap=cap)
    assert result["best_single_shift_norm_squared"] == exact
    assert result["accepted_by_norm_gate"] == (exact <= cap)
    assert not one_shift_norm(norm_squared=cap, max_abs_a_coordinate=0,
                              modulus=q, norm_cap=cap)["accepted_by_norm_gate"]
    assert one_shift_norm(norm_squared=0, max_abs_a_coordinate=0,
                          modulus=q, norm_cap=q*q)["accepted_by_norm_gate"]


@pytest.mark.parametrize("kwargs", [
    {"norm_squared": -1}, {"norm_squared": True},
    {"max_abs_a_coordinate": -1}, {"max_abs_a_coordinate": 6},
    {"modulus": 0}, {"modulus": 8}, {"norm_cap": -1},
    {"norm_cap": 3},
])
def test_shift_gate_rejects_invalid_claims(kwargs):
    values = {"norm_squared": 25, "max_abs_a_coordinate": 5,
              "modulus": 7, "norm_cap": 25}
    values.update(kwargs)
    with pytest.raises(ValueError):
        one_shift_norm(**values)


def test_actual_sage_ring_verification_block_has_universal_q_kernel():
    pytest.importorskip("sage.all")
    from experiments.research.candidates.srgg.paper_algebra import PaperRing
    from experiments.research.candidates.srgg.paper_parameters import PaperParams

    p = PaperParams("PARAM-I")
    ring = PaperRing(p)
    zero, one = ring.constant(0), ring.constant(1)
    x = tuple(1 if i == 1 else 0 for i in range(p.degree))
    # Nonidentity public column: no assumption about the actual seeded Ahat.
    rows = tuple(tuple(one if i == j else x if j == p.rank else zero
                       for j in range(p.columns)) for i in range(p.rank))
    for column in (0, p.rank):
        shift = tuple(ring.constant(p.modulus) if j == column else zero
                      for j in range(p.columns))
        doubled = tuple(tuple(ring.scale(a, 2, 2*p.modulus) for a in row)
                        for row in rows)
        assert ring.matvec(rows, shift, p.modulus) == (zero,) * p.rank
        assert ring.matvec(doubled, shift, 2*p.modulus) == (zero,) * p.rank


def test_sparse_subring_projection_is_not_a_ring_map():
    obstruction = subring_projection_obstruction(degree=512)
    assert obstruction["counterexample"]["s"] == "X^63"
    assert obstruction["counterexample"]["P_a_times_s"] == "Y"
    assert not obstruction["naive_coefficient_projection_is_ring_homomorphism"]
    pytest.importorskip("sage.all")
    from experiments.research.candidates.srgg.paper_algebra import PaperRing
    from experiments.research.candidates.srgg.paper_parameters import PaperParams

    ring = PaperRing(PaperParams("PARAM-I"))
    a = tuple(int(i == 1) for i in range(512))
    s = tuple(int(i == 63) for i in range(512))
    product = ring.multiply(a, s)
    project = lambda poly: tuple(poly[64*i] for i in range(8))
    assert project(a) == project(s) == (0,) * 8
    assert project(product) == (0, 1, 0, 0, 0, 0, 0, 0)


@pytest.mark.parametrize("degree,subring", [(0, 8), (512, 0), (512, 512),
                                             (256, 3), (True, 8), (1024, 8)])
def test_subring_input_is_bounded(degree, subring):
    with pytest.raises(ValueError):
        subring_projection_obstruction(degree=degree, subring_degree=subring)


def test_report_keeps_attack_and_security_scope_explicit():
    report = build_report()
    assert len(report["rows"]) == 3
    assert report["real_signature_trials"] == report["BKZ_executions"] == 0
    assert report["formal_security_bits"] is None
    for row in report["rows"]:
        assert row["actual_full_ring_HNF_or_structural_CVP_cost"] is None
        assert row["actual_CRT_or_subfield_attack_cost"] is None
        assert row["actual_accepted_setup_root_attack_success"] is None
        assert row["actual_2Q_verification"]["valid_signature_replacement_probability"] is None
        assert not row["author_report"]["author_BKZ_costs_reproduced"]
        assert row["security_claim"] == "none"
        assert row["backend_admitted"] is False
        assert row["parameters_are_formal"] is False
        assert row["nist_security_category"] is None
    json.dumps(report)


def test_frozen_receipt_is_exactly_regenerated_from_current_sources():
    root = Path(__file__).resolve().parents[1]
    receipt = root / "docs/research/team-b-delivery/2026-10-18-srgg-structural-cost/structural-cost.json"
    assert json.loads(receipt.read_text(encoding="utf-8")) == build_report()
