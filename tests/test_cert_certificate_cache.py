"""Portable cache wiring tests; the engine double is not crypto evidence."""
from dataclasses import replace
from hashlib import shake_256

import pytest

from ibme.ibs.certified.backend import CertifiedIBS
from ibme.ibs.certified.objects import (
    CertifiedPublicKey, CertifiedSignature, application_message, certificate_message,
)
from ibme.ibs.certified.params import CertifiedIBSParams


def tag(public, message):
    return shake_256(public + message).digest(2420)


@pytest.fixture
def fixture(monkeypatch):
    class Engine:
        def __init__(self):
            self.calls = []
            self.error = None

        def verify(self, public, message, signature):
            self.calls.append((public, message, signature))
            if self.error:
                raise self.error
            return signature == tag(public, message)

    engine = Engine()
    monkeypatch.setattr('ibme.ibs.certified.backend.ordinary', lambda params: engine)
    public = CertifiedPublicKey(CertifiedIBSParams(), b'A' * 1312)

    def signature(message=b'message', identity=b'alice', user=b'U' * 1312, pk=public):
        cert = tag(pk.authority_public, certificate_message(pk, identity, user))
        signed = tag(user, application_message(pk, identity, user, cert, message))
        return CertifiedSignature('ml-dsa-44', pk.context, user, cert, signed)

    return engine, public, signature


def test_reuses_certificate_but_verifies_each_new_message(fixture):
    engine, public, signature = fixture
    backend = CertifiedIBS()
    assert backend.verify(public, b'alice', b'one', signature(b'one'))
    assert backend.verify(public, b'alice', b'two', signature(b'two'))
    assert len(engine.calls) == 3
    assert not backend.verify(public, b'alice', b'changed', signature(b'two'))
    assert len(engine.calls) == 4


def test_identity_user_root_and_certificate_are_not_interchangeable(fixture):
    engine, public, signature = fixture
    backend = CertifiedIBS()
    honest = signature()
    assert backend.verify(public, b'alice', b'message', honest)
    for pk, identity, sig in (
        (public, b'bob', honest),
        (public, b'alice', replace(honest, user_public=b'V' * 1312)),
        (public, b'alice', replace(honest, certificate=b'X' * 2420)),
        (replace(public, authority_public=b'B' * 1312), b'alice', honest),
        (replace(public, params=replace(public.params, identity_bytes=65)), b'alice', honest),
    ):
        assert not backend.verify(pk, identity, b'message', sig)
    assert backend.certificate_cache_info()['entries'] == 1


def test_false_and_exceptions_are_not_cached(fixture):
    engine, public, signature = fixture
    backend = CertifiedIBS()
    invalid = replace(signature(), certificate=b'X' * 2420)
    for _ in range(2):
        assert not backend.verify(public, b'alice', b'message', invalid)
    assert len(engine.calls) == 2
    engine.error = RuntimeError('native unavailable')
    with pytest.raises(RuntimeError, match='native unavailable'):
        backend.verify(public, b'alice', b'message', signature())
    engine.error = None
    assert backend.verify(public, b'alice', b'message', signature())
    assert len(engine.calls) == 5


def test_disabled_and_bounded_lru(fixture):
    engine, public, signature = fixture
    backend = CertifiedIBS(certificate_cache_entries=0)
    for _ in range(2):
        assert backend.verify(public, b'alice', b'message', signature())
    assert len(engine.calls) == 4
    backend.configure_certificate_cache(1)
    assert backend.verify(public, b'alice', b'message', signature())
    assert backend.verify(public, b'bob', b'message', signature(identity=b'bob'))
    assert backend.certificate_cache_info()['entries'] == 1
    before = len(engine.calls)
    assert backend.verify(public, b'alice', b'message', signature())
    assert len(engine.calls) == before + 2
    backend.clear_certificate_cache()
    assert backend.certificate_cache_info()['entries'] == 0


@pytest.mark.parametrize('capacity', [-1, 257, True, 1.5, None])
def test_invalid_capacity_rejected(capacity):
    with pytest.raises(ValueError, match='capacity'):
        CertifiedIBS(certificate_cache_entries=capacity)
