"""Recompute the bounded but ineffective original literal-width fallback."""

from fractions import Fraction

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

from experiments.research.candidates.srgg.paper_schur_literal_fallback_audit import build_report


def test_original_literal_product_failure_is_a_real_mathematical_receipt():
    report = build_report()
    assert report["security_claim"] == "none"
    assert report["exact_algorithm34_to_ideal_joint_tv_upper"] is None
    assert [row["profile"] for row in report["rows"]] == ["PARAM-I", "PARAM-II", "PARAM-III"]
    for row in report["rows"]:
        for phase in ("master", "signature"):
            cert = row[phase]
            assert cert["whole_chain_bound_nontrivial"] is False
            assert cert["mathematical_algorithm34_to_ideal_sequential_discrete_tv_upper_exact"] == "1"
            assert 0 < Fraction(cert["single_leaf_tv_complement_lower_dyadic_exact"]) < Fraction(1, 10**10)
            assert cert["all_accepted_setup_roots_covered"] is False
