"""Portable checks for the Lai PLWE parameter candidates."""
from __future__ import annotations

from experiments.research.candidates.lai.target_parameters import (
    CANDIDATES,
    SELECTED,
    audit,
    margin_proxy,
    sizes,
    validate_candidate,
)


def test_candidates_are_well_formed():
    assert {c.name for c in CANDIDATES} == {
        "a-point-256-2p31", "c1-1024-2p35", "c2-2048-2p38", "c3-2048-2p39"}
    for candidate in CANDIDATES:
        row = validate_candidate(candidate)
        assert row["q_is_prime"] is True
        assert row["q_mod_2n"] == 1
        assert candidate.q < 2 ** 40
        assert candidate.k == candidate.q.bit_length()
        assert sizes(candidate)["ring_element"] == candidate.params.coefficient_bytes * candidate.n


def test_selected_candidate_is_c2_and_meets_128_bits():
    result = audit()
    assert result["selected"] == SELECTED == "c2-2048-2p38"
    rows = {row["name"]: row for row in result["rows"]}
    assert rows[SELECTED]["selected"] is True
    assert rows[SELECTED]["security_bits"]["classical"] >= 128
    assert rows[SELECTED]["security_bits"]["quantum"] >= 128
    assert rows["c3-2048-2p39"]["security_bits"]["quantum"] >= 128
    assert rows["c1-1024-2p35"]["security_bits"]["classical"] < 128
    assert rows["a-point-256-2p31"]["security_bits"]["classical"] < 128


def test_margins_and_sizes_are_ordered():
    c2 = next(c for c in CANDIDATES if c.name == "c2-2048-2p38")
    c3 = next(c for c in CANDIDATES if c.name == "c3-2048-2p39")
    assert margin_proxy(c2) > 1
    assert margin_proxy(c3) > margin_proxy(c2)
    assert sizes(c2)["level2_secret"] > sizes(c2)["level1_secret"]
    assert sizes(c2)["ciphertext"] > 0


def test_audit_keeps_security_flags_false():
    result = audit()
    assert result["security_claim"] == "none"
    assert result["backend_admitted"] is False
    assert result["parameters_are_formal"] is False
    assert result["security_model"]["excluded"].startswith("bdd_hybrid")
