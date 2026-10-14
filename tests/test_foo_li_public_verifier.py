"""Public-only Figure 2 verification, cross-checked with the issuer."""

import pytest

pytest.importorskip("sage.all", reason="Use prescribed WSL Sage environment")

from ibme.core.randomness import DeterministicRandom
from experiments.research.foo_li_public_verifier import PublicVerifier
from experiments.research.foo_li_runtime_reference import (
    DOMAINS, ResearchConfig, ResearchSession, ShakeOracleCandidate,
)
from experiments.research.gaussian_reference import SamplingAbort
from experiments.research.online_gaussian_reference import OnlineOptions


def research_session():
    config = ResearchConfig(options=OnlineOptions(tail_bits=24, mass_bits=64,
        precision_bits=128, gaussian_abort_bits=24, max_uniform_trials=64))
    result = ResearchSession.setup(config, b"public-verification-epoch",
        rng=DeterministicRandom(b"public-verifier-master"))
    assert result.status == "ok"
    session = result.value
    assert session.extract(b"Alice", seed_rng=DeterministicRandom(b"public-verifier-user")).status == "ok"
    return session


def public_rows(session):
    return [[int(x) for x in row] for row in session.generated.public.rows()]


def test_public_only_verification_and_independent_matrix_copy():
    session = research_session()
    public = public_rows(session)
    verifier = PublicVerifier(session.config, session.epoch, public)
    assert verifier.context == session.context
    assert not any(hasattr(verifier, name) for name in ("generated", "master", "k1", "k2", "users"))

    signatures = []
    for message in (b"", b"one", b"two", b"a\x00b"):
        outcome = session.sign_raw(b"Alice", message)
        assert outcome.status == "ok"
        assert session.verify(b"Alice", message, outcome.value)
        assert verifier.verify(b"Alice", message, outcome.value)
        signatures.append((message, outcome.value))

    # The verifier owns canonical public data and keeps working after the issuer goes away.
    public[0][0] = (public[0][0]+1) % verifier.config.q
    assert public != public_rows(session)
    del session
    assert all(verifier.verify(b"Alice", message, signature) for message, signature in signatures)


def test_public_and_issuer_oracles_and_rejection_agree():
    session = research_session()
    verifier = PublicVerifier(session.config, session.epoch, public_rows(session))
    for identity in (b"Alice", b"Bob"):
        for bit in (0, 1):
            assert verifier.identity_matrix(identity, bit) == session.identity_matrix(identity, bit)
        for message in (b"", b"m", b"another"):
            assert verifier.syndrome(identity, message) == session.syndrome(identity, message)

    valid = session.sign_raw(b"Alice", b"m").value
    invalid = (valid[0][:-1], valid[1])
    for signature in (valid, invalid, (valid[0], True), ((10**9,)+valid[0][1:], valid[1])):
        for identity, message in ((b"Alice", b"m"), (b"Bob", b"m"), (b"Alice", b"other")):
            assert verifier.verify(identity, message, signature) == session.verify(identity, message, signature)


def test_public_key_validation_and_hash_abort():
    session = research_session()
    rows = public_rows(session)
    with pytest.raises(ValueError):
        PublicVerifier(session.config, session.epoch, rows[:-1])
    out_of_range = public_rows(session)
    out_of_range[0][0] = session.config.q
    with pytest.raises(ValueError):
        PublicVerifier(session.config, session.epoch, out_of_range)

    class FailingPublicOracle(ShakeOracleCandidate):
        def stream(self, domain, context, fields, length):
            if domain == DOMAINS[2]:
                raise SamplingAbort("public matrix hash exhausted")
            return super().stream(domain, context, fields, length)

    verifier = PublicVerifier(session.config, session.epoch, rows, oracle=FailingPublicOracle())
    signature = session.sign_raw(b"Alice", b"m").value
    assert not verifier.verify(b"Alice", b"m", signature)
