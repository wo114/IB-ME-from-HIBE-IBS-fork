"""Public-boundary tests for the SRGG numerical stability audit."""

import json

import pytest

pytest.importorskip("sage.all", reason="SRGG numerical audit requires the specified WSL Sage")

from experiments.research.candidates.srgg.numeric_audit import audit


def test_numeric_audit_reports_diagnostics_without_secret_material():
    report = audit(precision_samples=2, hnf_repetitions=2)
    encoded = json.dumps(report, sort_keys=True)
    assert report["schema"] == "IBME/SRGG-NUMERIC-STABILITY-AUDIT/1"
    assert report["security_claim"] == "none"
    assert report["backend_admitted"] is False
    assert report["parameters_are_formal"] is False
    assert len(report["precision_coupling"]) == 2
    assert all(row["paired_successes"] == 2 for row in report["precision_coupling"])
    assert report["hnf_key_aggregate"]["successful_reconstructions"] == 2
    assert "private_shape" not in encoded
    assert "raw_vector" not in encoded
    assert "seed_material" not in encoded
