"""Default paper issuer: guarded source-Schur backend, initialize/reopen.

The separate guarded-service module was removed; `FixedIssuer` now defaults to
the guarded `SourceSchurBackend`.  Run in the designated WSL Sage environment.
"""
from __future__ import annotations

import pytest

from experiments.research.candidates.srgg.paper_parameters import PaperParams
from experiments.research.candidates.srgg.paper_schur_backend import SourceSchurBackend
from ibme.ibs.srgg_paper_service import FixedIssuer


def test_default_issuer_is_guarded_source_schur(tmp_path):
    params = PaperParams("PARAM-I", "table-standard-deviation")
    issuer = FixedIssuer(tmp_path / "issuer")
    assert isinstance(issuer.backend, SourceSchurBackend)
    public = issuer.initialize(params, max_users=1)
    key = issuer.key_extract(b"Alice")
    assert key.identity == b"Alice"
    assert key.public_key == public
    extras = issuer.backend.last_master_gate_extras
    assert extras is not None
    assert extras["c_gate"]["certified"] is True
    assert extras["object_guard"]["raw_and_key_within_256bit_object_guard"] is True
    assert issuer.backend.gate_rejections == 0


def test_default_issuer_reopens_the_same_state(tmp_path):
    params = PaperParams("PARAM-I", "table-standard-deviation")
    path = tmp_path / "issuer"
    first = FixedIssuer(path)
    public = first.initialize(params, max_users=1)
    key = first.key_extract(b"Alice")

    reopened = FixedIssuer(path, expected_public=public, expected_params=params)
    assert reopened.key_extract(b"Alice").to_bytes() == key.to_bytes()
    with pytest.raises(Exception):
        reopened.key_extract(b"Bob")
