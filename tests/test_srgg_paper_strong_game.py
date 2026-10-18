"""Paper strong-game freshness and public Q-shift execution checks."""
from dataclasses import replace
from fractions import Fraction

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

from experiments.research.candidates.srgg.paper_algebra import (
    PaperRing, identity_target, message_challenge, public_matrix,
)
from experiments.research.candidates.srgg.paper_objects import (
    PublicKey, Signature, SigningKey,
)
from experiments.research.candidates.srgg.paper_parameters import PaperParams
from experiments.research.candidates.srgg.paper_profiles import profiles
from experiments.research.candidates.srgg.paper_strong_game import (
    MESSAGE, NoRead, q_shift_replacement, replay_original_row, squared_norm,
)
from experiments.research.candidates.srgg.paper_schur_backend import SourceSchurBackend


def algebra_fixture():
    """Public zero-witness algebra, not a sampled Setup/signature claim."""
    p = PaperParams("PARAM-I")
    ring, seed = PaperRing(p), bytes(range(32))
    a_hat = public_matrix(p, seed)
    witness = tuple(tuple(ring.constant(0) for _ in range(p.rank * p.digits))
                    for _ in range(2 * p.rank))
    public = PublicKey(p, seed, a_hat, ring.build_public(a_hat, witness))
    identity, message = b"algebra-fixture", b"fixture-message"
    target = identity_target(public, identity)
    tail = [ring.constant(0) for _ in range(p.rank)]
    for poly in target:
        digits = [[] for _ in range(p.digits)]
        for coefficient in poly:
            error = (coefficient + p.p // 2) % p.p - p.p // 2
            state = (coefficient - error) // p.p
            for column in digits:
                digit = (state + p.base // 2) % p.base - p.base // 2
                column.append(digit)
                state = (state - digit) // p.base
        tail.extend(tuple(column) for column in digits)
    key = SigningKey(public, identity, tuple(tail))
    commitment = (ring.constant(0),) * p.rank
    challenge = message_challenge(public, commitment, message)
    response = ring.response(key.full, (ring.constant(0),) * (p.columns + 1),
                             ring.constant(0), challenge)
    signature = Signature(public.context, response, challenge)
    assert SourceSchurBackend(rng=NoRead()).verify(public, identity, message, signature)
    return public, identity, message, signature


def test_public_replacement_is_exact_and_canonically_distinct():
    public, identity, message, signature = algebra_fixture()
    replacement, record = q_shift_replacement(public, identity, message, signature)
    assert replacement is not None
    assert record["identity_block_2I_checked"]
    assert record["tested_basis_positions"] == public.params.rank * public.params.degree
    assert record["eligible_basis_positions"] > 0
    assert record["replacement_valid"] and record["recovered_commitment_equal"]
    assert record["canonical_signature_distinct"]
    assert record["fresh_under_exact_signature_sEUF_game"]
    assert not record["fresh_under_paper_G0_fresh_message_game"]
    assert replacement.challenge == signature.challenge
    assert replacement.context == signature.context
    assert replacement.to_bytes() != signature.to_bytes()
    assert Signature.from_bytes(replacement.to_bytes()).to_bytes() == replacement.to_bytes()
    assert squared_norm(replacement.response) == record["replacement"]["norm_squared"]
    assert squared_norm(replacement.response) <= public.params.signature_norm_cap
    with pytest.raises(ValueError, match="valid public signing-oracle"):
        q_shift_replacement(public, identity, message + b"!", signature)
    with pytest.raises(ValueError, match="valid public signing-oracle"):
        q_shift_replacement(public, identity, message,
                            replace(signature, challenge=(0,) * public.params.degree))


def test_single_basis_norm_formula_matches_both_signs_and_inclusive_gate():
    for item in profiles:
        p = PaperParams(item.name)
        q, cap = p.modulus, p.signature_norm_cap
        assert Fraction(item.gamma) ** 2 >= cap
        assert q < 2 * Fraction(item.gamma)
        for old_norm, coefficient in ((0, 0), (cap, 0), (cap - q*q, 1234),
                                      (cap - 2*q*q, -q), (cap, -2*q)):
            toward = -q if coefficient >= 0 else q
            away = -toward
            new_norm = old_norm + 2 * coefficient * toward + q*q
            other_norm = old_norm + 2 * coefficient * away + q*q
            assert new_norm <= other_norm
            assert new_norm == old_norm + q*q - 2*q*abs(coefficient)
            assert (new_norm <= cap) == (cap - old_norm >= q*q - 2*q*abs(coefficient))


def test_real_paper_ii_source_signature_has_a_public_strong_replacement():
    row = replay_original_row("PARAM-II", "table-standard-deviation")
    probe = row["probe"]
    assert row["identity_bytes"] == 5 and row["message_bytes"] == len(MESSAGE) == 32
    assert row["signature_queries"] == 1
    assert row["setup_attempts"] >= 1 and row["sign_attempts"] >= 1
    assert row["published_gamma"] == "63653172.0"
    assert probe["replacement_valid"] is True
    assert probe["canonical_signature_distinct"] is True
    assert probe["recovered_commitment_equal"] is True
    assert probe["fresh_under_exact_signature_sEUF_game"] is True
    assert probe["fresh_under_paper_G0_fresh_message_game"] is False
    assert probe["replacement"]["original_signature_sha256"] != probe[
        "replacement"]["replacement_signature_sha256"]


def test_real_paper_i_sample_has_no_single_basis_shift_without_claiming_security():
    row = replay_original_row("PARAM-I", "table-standard-deviation")
    probe = row["probe"]
    assert probe["original_valid"] is True
    assert probe["tested_basis_positions"] == 1024
    assert probe["eligible_basis_positions"] == 0
    assert probe["replacement"] is None
    assert probe["best_shift_excess_over_cap"] > 0
    assert probe["fresh_under_exact_signature_sEUF_game"] is False
    assert probe["security_claim"] == "none"
