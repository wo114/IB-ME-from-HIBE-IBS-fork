"""Contract-level tests for the Lai A-point HIBE research backend.

Sage-only; Windows skips the module.  Research parameters, no security claim.
"""
from __future__ import annotations

import pytest

pytest.importorskip("sage.all")

from ibme.assembly.catalog import algorithm_catalog
from ibme.assembly.registry import default_registry
from ibme.core.errors import (
    EncodingError,
    InvalidParameterError,
    SerializationError,
)
from ibme.core.randomness import DeterministicRandom
from ibme.hibe.lai.registration import ciphertext_size
from ibme.hibe.lai import (
    LaiCiphertext,
    LaiHIBE,
    LaiLevel1SecretKey,
    LaiLevel2SecretKey,
    LaiMasterSecret,
    LaiParams,
    LaiPublicKey,
)

RCV = b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa"
PHI = b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba"
OTHER = b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8"
WRONG = b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8"
SEED = b"lai-hibe-contract-v1"
PAYLOAD = b"0123456789abcdef0123456789abcdef"


def rng(suffix: bytes) -> DeterministicRandom:
    return DeterministicRandom(SEED + b":" + suffix)


@pytest.fixture(scope="module")
def env():
    backend = LaiHIBE()
    params = LaiParams()
    pk, msk = backend.setup(params, rng=rng(b"setup"))
    sk1 = backend.extract(msk, RCV, rng=rng(b"extract"))
    sk2 = backend.derive(sk1, PHI, rng=rng(b"derive"))
    return backend, params, pk, msk, sk1, sk2


@pytest.fixture(scope="module")
def ciphertext(env):
    backend, params, pk, msk, sk1, sk2 = env
    ct = backend.encrypt(pk, RCV, PHI, PAYLOAD, rng=rng(b"enc"))
    return ct


def test_roundtrip_matching(env, ciphertext):
    backend, params, pk, msk, sk1, sk2 = env
    assert backend.decrypt(sk2, ciphertext) == PAYLOAD


def test_roundtrip_empty_payload(env):
    backend, params, pk, msk, sk1, sk2 = env
    ct = backend.encrypt(pk, RCV, PHI, b"", rng=rng(b"enc-empty"))
    assert backend.decrypt(sk2, ct) == b""


def test_identity_mismatch_returns_none(env, ciphertext):
    backend, params, pk, msk, sk1, sk2 = env
    other1 = backend.extract(msk, OTHER, rng=rng(b"other"))
    wrong_child = backend.derive(sk1, WRONG, rng=rng(b"wrong-child"))
    other_child = backend.derive(other1, PHI, rng=rng(b"other-child"))
    assert backend.decrypt(wrong_child, ciphertext) is None
    assert backend.decrypt(other_child, ciphertext) is None


def test_serialization_roundtrip(env, ciphertext):
    backend, params, pk, msk, sk1, sk2 = env
    for obj in (pk, msk, sk1, sk2, ciphertext):
        clone = type(obj).from_bytes(obj.to_bytes())
        assert clone == obj
    assert backend.load_ciphertext(ciphertext.to_bytes()) == ciphertext
    assert len(ciphertext.to_bytes()) == ciphertext_size(params, 32, 86)


def test_malformed_and_truncated_rejected(env, ciphertext):
    backend, params, pk, msk, sk1, sk2 = env
    for obj in (pk, msk, sk1, sk2, ciphertext):
        raw = obj.to_bytes()
        with pytest.raises(SerializationError):
            type(obj).from_bytes(b"")
        with pytest.raises(SerializationError):
            type(obj).from_bytes(raw[:-1])
        with pytest.raises(SerializationError):
            type(obj).from_bytes(raw + b"\x00")


def test_ciphertext_has_no_identity_plaintext(ciphertext):
    raw = ciphertext.to_bytes()
    for identity in (RCV, PHI, OTHER, WRONG):
        assert identity not in raw
    for chunk in (RCV, PHI, PAYLOAD):
        for i in range(len(chunk) - 3):
            assert chunk[i:i + 4] not in raw


def test_key_binding(env):
    backend, params, pk, msk, sk1, sk2 = env
    assert backend.validate_key_binding(pk, msk) is True
    assert backend.validate_key_binding(pk, sk1) is True
    assert backend.validate_key_binding(pk, sk2) is True
    assert backend.validate_key_binding(object(), msk) is False
    assert backend.validate_key_binding(pk, object()) is False


def test_input_validation(env, ciphertext):
    backend, params, pk, msk, sk1, sk2 = env
    with pytest.raises(EncodingError):
        backend.extract(msk, b"", rng=rng(b"v1"))
    with pytest.raises(EncodingError):
        backend.derive(sk1, b"", rng=rng(b"v2"))
    with pytest.raises(EncodingError):
        backend.encrypt(pk, b"", PHI, b"x", rng=rng(b"v3"))
    with pytest.raises(EncodingError):
        backend.extract(msk, "alice", rng=rng(b"v4"))
    with pytest.raises(InvalidParameterError):
        backend.encrypt(pk, RCV, PHI, b"x" * 33, rng=rng(b"v5"))
    with pytest.raises(TypeError):
        backend.extract("not-msk", RCV)
    with pytest.raises(TypeError):
        backend.decrypt("not-sk", ciphertext)


def test_registry_and_catalog():
    spec = default_registry().get("hibe", "lai-ideal-hibe")
    assert spec.available is True
    assert spec.two_level is True and spec.key_binding is True
    assert set(spec.presets) == {"hybrid-research", "direct-research"}
    row = next(item for item in algorithm_catalog()["routes"]
               if item["id"] == "lai-ideal-hibe")
    assert row["adapter_available"] is True


def test_max_identity_binding(env):
    backend, params, pk, msk, sk1, sk2 = env
    long_id = b"\x42" * params.identity_bytes
    sk1_long = backend.extract(msk, long_id, rng=rng(b"long-extract"))
    sk2_long = backend.derive(sk1_long, PHI, rng=rng(b"long-derive"))
    ct = backend.encrypt(pk, long_id, PHI, PAYLOAD, rng=rng(b"long-enc"))
    assert sk1_long.identity == long_id
    assert sk2_long.parent_identity == long_id
    assert backend.decrypt(sk2_long, ct) == PAYLOAD
    assert len(ct.to_bytes()) == ciphertext_size(params, 32, 86)


def test_fixed_rng_reproducible(env):
    backend, params, pk, msk, sk1, sk2 = env
    first = backend.encrypt(pk, RCV, PHI, PAYLOAD, rng=rng(b"repro"))
    second = backend.encrypt(pk, RCV, PHI, PAYLOAD, rng=rng(b"repro"))
    assert first.to_bytes() == second.to_bytes()
    assert backend.decrypt(sk2, first) == PAYLOAD
