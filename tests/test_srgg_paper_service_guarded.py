"""Guarded source-Schur issuer path: initialize, first key, reopen.

The original v1 issuer/backend files are frozen evidence and are not modified.
This test exercises the corrected live path and its complete-gate record.
Run in the designated WSL Sage environment.
"""
from __future__ import annotations

import pytest

from experiments.research.candidates.srgg.paper_parameters import PaperParams
from ibme.ibs.srgg_paper_service_guarded import GuardedSourceSchurIssuer


def test_guarded_issuer_initializes_and_issues_under_complete_gates(tmp_path):
    params = PaperParams("PARAM-I", "table-standard-deviation")
    issuer = GuardedSourceSchurIssuer(tmp_path / "issuer")
    public = issuer.initialize(params, max_users=1)
    key = issuer.key_extract(b"Alice")
    assert key.identity == b"Alice"
    assert key.public_key == public
    extras = issuer.backend.last_master_gate_extras
    assert extras is not None
    assert extras["c_gate"]["certified"] is True
    assert extras["object_guard"]["raw_and_key_within_256bit_object_guard"] is True
    assert issuer.backend.gate_rejections == 0


def test_guarded_issuer_reopens_the_same_state(tmp_path):
    params = PaperParams("PARAM-I", "table-standard-deviation")
    path = tmp_path / "issuer"
    first = GuardedSourceSchurIssuer(path)
    public = first.initialize(params, max_users=1)
    key = first.key_extract(b"Alice")

    reopened = GuardedSourceSchurIssuer(path, expected_public=public,
                                        expected_params=params)
    assert reopened.key_extract(b"Alice").to_bytes() == key.to_bytes()
    with pytest.raises(Exception):
        reopened.key_extract(b"Bob")
