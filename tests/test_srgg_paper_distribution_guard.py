"""Guarded distribution-chain tests for the standalone SRGG paper backend.

Run in the repository WSL Sage environment:

    PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q \
        tests/test_srgg_paper_distribution_guard.py

The tests bind the uniform conditional bounds to the frozen six-root receipts
and exercise the guard's positive control (a tampered stored factor must be
rejected by the independent audit).  They do not establish any security claim.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ibme.core.randomness import DeterministicRandom
from experiments.research.candidates.srgg.paper_distribution_guard import (
    GateFailure,
    SourceSchurBackend,
    require_gates,
    uniform_issuance_bound,
    uniform_phase_bound,
    uniform_sign_call_bound,
)
from experiments.research.candidates.srgg.paper_parameters import PaperParams

ROOT = Path(__file__).resolve().parents[1]
JOINT = ROOT / "docs/research/team-b-delivery/2026-10-18-srgg-finite-chain/joint-fixed-root.json"
PROFILE = "PARAM-I"
INTERPRETATION = "table-standard-deviation"
SEED = b"paper-baseline-PARAM-I-table-standard-deviation"


def _root(seed=SEED, interpretation=INTERPRETATION):
    params = PaperParams(PROFILE, interpretation)
    backend = SourceSchurBackend(rng=DeterministicRandom(seed))
    public, master = backend.setup(params)
    return params, backend, public, master


def test_uniform_master_bound_matches_frozen_receipt_and_second_root():
    frozen = json.loads(JOINT.read_text(encoding="utf-8"))
    row = next(item for item in frozen["rows"]
               if item["profile"] == PROFILE and item["interpretation"] == INTERPRETATION)
    _params, backend, _public, master = _root()
    bound = uniform_phase_bound(backend._master_plan(_params, master.witness), INTERPRETATION)
    assert bound["closed"] is True
    assert bound["joint_tv_exact"] == row["master"]["finite_vs_joint_integer_gaussian_tv_upper_exact"]
    assert bound["gate_floor"] == "64"

    second_seed = b"uniformity-PARAM-I-table-standard-deviation"
    params2, backend2, _pub2, master2 = _root(seed=second_seed)
    bound2 = uniform_phase_bound(backend2._master_plan(params2, master2.witness), INTERPRETATION)
    assert bound2["closed"] is True
    assert bound2["joint_tv_exact"] == bound["joint_tv_exact"]


def test_guarded_setup_and_sign_bound_is_uniform_on_gated_key():
    params, backend, _public, master = _root()
    key = backend.key_extract(master, b"Alice")
    sign = uniform_phase_bound(backend._sign_plan(key), INTERPRETATION)
    assert sign["closed"] is True
    call = uniform_sign_call_bound(params, backend, key, INTERPRETATION)
    assert call["closed"] is True
    assert call["one_sign_call_tv_dyadic_upper"] == "2^-19"
    assert backend.last_master_gate_audit is not None
    assert backend.last_sign_gate_audit is not None
    assert backend.last_master_gate_extras["c_gate"]["certified"] is True
    assert backend.last_master_gate_extras["object_guard"][
        "raw_and_key_within_256bit_object_guard"] is True


def test_uniform_issuance_bound_matches_frozen_source_receipt():
    params, backend, _public, master = _root()
    plan = backend._master_plan(params, master.witness)
    bound = uniform_issuance_bound(params, backend, plan, INTERPRETATION)
    assert bound["closed"] is True
    assert bound["complete_law_tv_dyadic_upper"] == "2^-25"
    assert bound["c_gate_certified"] is True
    assert bound["finite_key_object_guard"] is True


def test_literal_density_issuance_stays_null():
    params, backend, _public, master = _root(interpretation="literal-density-width")
    plan = backend._master_plan(params, master.witness)
    bound = uniform_issuance_bound(params, backend, plan, "literal-density-width")
    assert bound["closed"] is False
    assert bound["complete_law_tv_upper_including_abort"] is None
    assert bound["blocker"]


def test_audit_rejects_tampered_stored_factor():
    params, backend, _public, master = _root()
    plan = backend._master_plan(params, master.witness)
    leaf = plan.leaves[0]
    field = leaf.field
    factors = list(leaf.factors)
    factors[0] = factors[0] + field(1) / field(2**100)
    leaf.factors = tuple(factors)
    with pytest.raises(GateFailure):
        require_gates(plan)


def test_security_fields_are_pinned():
    params, backend, _public, master = _root()
    key = backend.key_extract(master, b"Alice")
    call = uniform_sign_call_bound(params, backend, key, INTERPRETATION)
    assert call["closed"] is True
    assert backend.security_claim == "none"
    assert backend.backend_admitted is False
    assert backend.parameters_are_formal is False
    assert backend.nist_security_category is None
