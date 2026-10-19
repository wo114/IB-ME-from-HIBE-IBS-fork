"""Frozen fixed-root SRGG reports stay source-bound and scope-limited."""
from fractions import Fraction
from pathlib import Path

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

from experiments.research.candidates.srgg.paper_schur_joint_bound_audit import (
    ROOT, _read_authentic_finite, build_report,
)


FINITE = ROOT / "docs/research/team-b-delivery/2026-10-18-srgg-finite-chain/finite-fixed-root.json"


def test_fixed_root_joint_bound_distinguishes_strong_and_weak_mathematical_bridges():
    report = build_report(FINITE)
    assert len(report["rows"]) == 6
    assert report["security_claim"] == "none"
    assert report["backend_admitted"] is False
    assert report["parameters_are_formal"] is False
    assert report["accepted_setup_root_distribution_bound"] is None
    assert report["full_issuance_signature_history_tv"] is None
    assert sum(row[phase]["finite_vs_joint_integer_gaussian_tv_dyadic_bits"] is not None
               for row in report["rows"] for phase in ("master", "signature")) == 6
    for row in report["rows"]:
        for phase in ("master", "signature"):
            bound = row[phase]["finite_vs_joint_integer_gaussian_tv_dyadic_upper"]
            exact = row[phase]["finite_vs_joint_integer_gaussian_tv_upper_exact"]
            assert row[phase]["fixed_root_combined_tv_bound_nontrivial"]
            assert exact is not None and 0 < Fraction(exact) < 1
            if row["interpretation"] == "table-standard-deviation":
                assert bound is not None
            else:
                assert bound is None
                assert Fraction(1, 2) < Fraction(exact)
                assert row[phase]["mathematical_algorithm34_vs_ideal_sequential"]["schema"] == (
                    "IBME/SRGG-SCHUR-LITERAL-FOURIER-MOMENT/1")


def test_finite_receipt_byte_tampering_is_rejected(tmp_path):
    data = FINITE.read_bytes()
    altered = tmp_path / "altered-finite.json"
    altered.write_bytes(data.replace(b'"security_claim": "none"',
                                     b'"security_claim": "full"', 1))
    assert altered.read_bytes() != data
    with pytest.raises(ValueError, match="receipt bytes changed"):
        _read_authentic_finite(altered)


def test_finite_receipt_source_hashes_match_current_tree():
    raw, report = _read_authentic_finite(FINITE)
    assert raw and len(report["rows"]) == 6
    assert all(row["private_material_exported"] is False for row in report["rows"])
