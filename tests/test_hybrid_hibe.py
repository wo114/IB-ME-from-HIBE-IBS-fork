"""Opaque seed/payload HIBE contract, exact KDF and capsule tolerance control."""

from dataclasses import replace
from hashlib import sha256
import hmac

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ibme.core.errors import IBMEError, InvalidParameterError, RandomnessError, SerializationError
from ibme.core.randomness import DeterministicRandom
from ibme.hibe.api import HIBEBackend, HIBEPublicKey, HIBEMasterSecret, HIBELevel1SecretKey, HIBELevel2SecretKey
from ibme.hibe.mock import (MockHIBE, MockHIBEPublicKey, MockHIBEMasterSecret,
                           MockHIBELevel1SecretKey, MockHIBELevel2SecretKey)
from ibme.protocol.baseline import BASELINE_MOCK_PARAMS
from ibme.protocol.hybrid_hibe import (HybridHIBE, HybridHIBEParams, HybridLimits, HybridCiphertext,
                                     HybridPublicKey, DOMAIN_KDF, SUITE, derive_dem_key,
                                     encoded_identity, encoded_identity_bytes)
from ibme.protocol.luo_hybrid import make_hybrid_abb10, RESEARCH_HIBE_PARAMS


def rng(label): return DeterministicRandom(b"hybrid-hibe-tests:" + label)


class SpyMock(MockHIBE):
    def __init__(self): self.payload_sizes = []

    def encrypt(self, pk, parent_id, child_id, payload, *, rng=None):
        self.payload_sizes.append(len(payload))
        return super().encrypt(pk, parent_id, child_id, payload, rng=rng)


def mock_backend():
    return HybridHIBE(SpyMock(), backend_id=b"mock-test", public_key_type=MockHIBEPublicKey,
                      master_type=MockHIBEMasterSecret, level1_type=MockHIBELevel1SecretKey,
                      level2_type=MockHIBELevel2SecretKey)


@pytest.fixture(scope="module")
def mock_env():
    b = mock_backend()
    params = HybridHIBEParams(replace(BASELINE_MOCK_PARAMS, max_message_bytes=32,
                                    identity_bytes=encoded_identity_bytes(64)),
                              HybridLimits(backend_id=b"mock-test"))
    public, master = b.setup(params, rng=rng(b"mock-setup"))
    parent = b.extract(master, b"Receiver", rng=rng(b"mock-parent"))
    child = b.derive(parent, b"Sender", rng=rng(b"mock-child"))
    return b, public, master, parent, child


@pytest.fixture(scope="module")
def real_env():
    b = make_hybrid_abb10()
    public, master = b.setup(RESEARCH_HIBE_PARAMS, rng=rng(b"real-setup"))
    parent = b.extract(master, b"Receiver", rng=rng(b"real-parent"))
    child = b.derive(parent, b"Sender", rng=rng(b"real-child"))
    return b, public, master, parent, child


def test_frozen_interface_and_bound_readers(mock_env):
    b, public, master, parent, child = mock_env
    assert isinstance(b, HIBEBackend) and isinstance(public, HIBEPublicKey)
    assert isinstance(master, HIBEMasterSecret) and isinstance(parent, HIBELevel1SecretKey)
    assert isinstance(child, HIBELevel2SecretKey)
    assert parent.identity == child.parent_identity == b"Receiver" and child.child_identity == b"Sender"
    for name, value in dict(hpk=public, hmsk=master, sk1=parent, sk2=child).items():
        loaded = b.component_decoders()[name].from_bytes(value.to_bytes())
        assert loaded.to_bytes() == value.to_bytes()
        if name != "hpk":
            assert "redacted" in repr(loaded)
            with pytest.raises(TypeError): hash(loaded)
    assert b.security_claim == "none" and not b.backend_admitted


@pytest.mark.parametrize("message", [b"", b"\0\xff", b"x" * 30000, b"x" * 65536], ids=["empty", "binary", "30kb", "64kb"])
def test_large_payload_only_32_bytes_reach_inner_hibe(mock_env, message):
    b, public, master, parent, child = mock_env
    cipher = b.encrypt(public, b"Receiver", b"Sender", message, rng=rng(b"large" + message[:1]))
    assert b.inner_backend.payload_sizes[-1] == 32
    assert len(cipher.body) == len(message) + 16
    assert b.decrypt(child, b.load_ciphertext(cipher.to_bytes())) == message
    assert b"Receiver" not in cipher.to_bytes() and b"Sender" not in cipher.to_bytes()


@pytest.mark.parametrize("message", [b"", b"\x00\xff" * 16384], ids=["empty", "32kb"])
def test_real_lattice_large_payload_and_serialization(real_env, message):
    b, public, master, parent, child = real_env
    cipher = b.encrypt(public, b"Receiver", b"Sender", message, rng=rng(b"real-encrypt"))
    loaded_child = b.load_level2_key(child.to_bytes())
    assert b.decrypt(loaded_child, b.load_ciphertext(cipher.to_bytes()), rng=rng(b"real-decrypt")) == message


@pytest.mark.parametrize("wrong_parent,wrong_child", [(False, True), (True, False), (True, True)])
def test_three_identity_mismatches(mock_env, wrong_parent, wrong_child):
    b, public, master, parent, child = mock_env
    cipher = b.encrypt(public, b"Receiver", b"Sender", b"payload", rng=rng(b"mismatch"))
    if wrong_parent: parent = b.extract(master, b"OtherReceiver")
    if wrong_parent or wrong_child: child = b.derive(parent, b"OtherSender" if wrong_child else b"Sender")
    assert b.decrypt(child, cipher) is None


@pytest.mark.parametrize("field", ["context", "capsule", "nonce", "body"])
def test_all_hybrid_fields_authenticated(mock_env, field):
    b, public, master, parent, child = mock_env
    cipher = b.encrypt(public, b"Receiver", b"Sender", b"payload", rng=rng(b"tamper"))
    raw = getattr(cipher, field)
    changed = replace(cipher, **{field: raw[:-1] + bytes([raw[-1] ^ 1])})
    assert b.decrypt(child, changed) is None


def test_real_low_bit_preserves_seed_but_hybrid_rejects(real_env):
    b, public, master, parent, child = real_env
    cipher = b.encrypt(public, b"Receiver", b"Sender", b"tolerance-control", rng=rng(b"low-bit"))
    original = b.inner_backend.load_ciphertext(cipher.capsule)
    changed_bytes = cipher.capsule[:-1] + bytes([cipher.capsule[-1] ^ 1])
    altered = b.inner_backend.load_ciphertext(changed_bytes)
    assert original.c1[-1] ^ altered.c1[-1] == 1
    seed = b.inner_backend.decrypt(child.inner, original, rng=rng(b"seed-dec"))
    assert isinstance(seed, bytes) and len(seed) == 32
    assert b.inner_backend.decrypt(child.inner, altered, rng=rng(b"seed-dec")) == seed
    # Same DEM key; the complete altered capsule is still a different AAD.
    assert b.decrypt(child, replace(cipher, capsule=changed_bytes), rng=rng(b"seed-dec")) is None


@pytest.mark.parametrize("kind", ["hpk", "hmsk", "sk1", "sk2", "ciphertext"])
@pytest.mark.parametrize("mutation", ["truncate", "append", "duplicate", "version"])
def test_strict_hybrid_object_formats(mock_env, kind, mutation):
    b, public, master, parent, child = mock_env
    if kind == "ciphertext":
        value = b.encrypt(public, b"Receiver", b"Sender", b"payload", rng=rng(b"format"))
        reader = b.load_ciphertext
    else:
        value = dict(hpk=public, hmsk=master, sk1=parent, sk2=child)[kind]
        reader = b.component_decoders()[kind].from_bytes
    raw = value.to_bytes()
    malformed = {"truncate": raw[:-1], "append": raw + b"\0", "duplicate": raw + raw,
                 "version": b"?" + raw[1:]}[mutation]
    with pytest.raises(IBMEError): reader(malformed)


def test_kdf_agrees_with_independent_rfc5869_hmac():
    seed, context = bytes(range(32)), bytes(range(64))
    prefix = lambda x: len(x).to_bytes(4, "big") + x
    prk = hmac.new(context, seed, sha256).digest()
    expected = hmac.new(prk, prefix(DOMAIN_KDF) + prefix(SUITE) + b"\x01", sha256).digest()
    assert derive_dem_key(seed, context) == expected
    assert derive_dem_key(seed, context[:-1] + b"x") != expected
    for bad_seed, bad_context in ((b"", context), (seed, b"")):
        with pytest.raises(InvalidParameterError): derive_dem_key(bad_seed, bad_context)


def test_aes256gcm_nist_cavs14_vector():
    # Keylen=256, IVlen=96, PTlen=AADlen=0, Taglen=128, Count=0:
    # https://github.com/pyca/cryptography/blob/main/vectors/cryptography_vectors/ciphers/AES/GCM/gcmEncryptExtIV256.rsp
    key = bytes.fromhex("b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4")
    nonce = bytes.fromhex("516c33929df5a3284ff463d7")
    expected = bytes.fromhex("bdc1ac884d332457a1d2664f168c76f0")
    assert AESGCM(key).encrypt(nonce, b"", b"") == expected
    assert AESGCM(key).decrypt(nonce, expected, b"") == b""


def test_cross_context_and_resource_limits(mock_env):
    b, public, master, parent, child = mock_env
    cipher = b.encrypt(public, b"Receiver", b"Sender", b"payload", rng=rng(b"contexts"))
    foreign = HybridPublicKey(replace(public.limits, max_payload_bytes=60000), public.inner)
    assert foreign.context != public.context
    assert b.decrypt(replace(child, public_key=foreign), cipher) is None
    limited = HybridPublicKey(replace(public.limits, max_payload_bytes=1), public.inner)
    class NoEntropy:
        def read(self, count): raise AssertionError("must reject before randomness")
    with pytest.raises(InvalidParameterError): b.encrypt(limited, b"Receiver", b"Sender", b"xx", rng=NoEntropy())
    assert b.decrypt(replace(child, public_key=limited), replace(cipher, context=limited.context)) is None
    for bad in (dict(identity_max_bytes=True), dict(max_payload_bytes=2**32), dict(max_capsule_bytes=0)):
        with pytest.raises(InvalidParameterError): HybridLimits(**bad)
    with pytest.raises(InvalidParameterError):
        HybridHIBEParams(replace(BASELINE_MOCK_PARAMS, max_message_bytes=31), HybridLimits(backend_id=b"mock-test"))
    with pytest.raises(SerializationError):
        b.load_public_key(HybridPublicKey(replace(public.limits, backend_id=b"other"), public.inner).to_bytes())


def test_wrong_entropy_and_programming_inputs(mock_env):
    b, public, master, parent, child = mock_env
    class Short:
        def read(self, count): return b"x"
    class Broken:
        def read(self, count): raise OSError("entropy unavailable")
    for source in (object(), Short(), Broken()):
        with pytest.raises(RandomnessError): b.encrypt(public, b"Receiver", b"Sender", b"", rng=source)
    with pytest.raises(TypeError): b.setup(BASELINE_MOCK_PARAMS)
    with pytest.raises(TypeError): b.decrypt(object(), object())
    with pytest.raises(IBMEError): b.encrypt(public, b"", b"Sender", b"")
    with pytest.raises(SerializationError): HybridCiphertext.from_bytes(object())


def test_same_entropy_replays_and_fresh_entropy_changes_capsule_and_nonce(mock_env):
    b, public, master, parent, child = mock_env
    source = rng(b"fresh")
    first = b.encrypt(public, b"Receiver", b"Sender", b"payload", rng=source)
    second = b.encrypt(public, b"Receiver", b"Sender", b"payload", rng=source)
    repeated = b.encrypt(public, b"Receiver", b"Sender", b"payload", rng=rng(b"fresh"))
    assert first.to_bytes() == repeated.to_bytes()
    assert first.nonce != second.nonce and first.capsule != second.capsule


def test_fixed_width_identity_encoding_is_injective_and_key_bound(mock_env):
    b, public, master, parent, child = mock_env
    identities = (b"A", b"A\0", b"\0A", b"A" * 64)
    encodings = [encoded_identity(identity, public.limits, role) for identity in identities for role in (b"P", b"C")]
    assert len(set(encodings)) == 8 and {len(x) for x in encodings} == {86}
    for identity in identities:
        key = b.extract(master, identity)
        assert key.identity == identity and len(key.inner.identity) == 86
        assert b.load_level1_key(key.to_bytes()).identity == identity
    with pytest.raises(SerializationError): replace(parent, identities=(b"Other",))
    with pytest.raises(SerializationError): replace(child, identities=(b"Receiver", b"Other"))


def test_real_capsule_shape_does_not_reveal_identity_lengths(real_env):
    b, public, master, parent, child = real_env
    cases = ((b"R", b"S"), (b"R" * 64, b"S"), (b"R", b"S" * 64), (b"R" * 64, b"S" * 64))
    ciphertexts = [b.encrypt(public, rcv, snd, b"same-length", rng=rng(b"length" + bytes([i])))
                   for i, (rcv, snd) in enumerate(cases)]
    assert len({len(ct.capsule) for ct in ciphertexts}) == 1
    assert len({len(ct.to_bytes()) for ct in ciphertexts}) == 1
    inner = [b.inner_backend.load_ciphertext(ct.capsule) for ct in ciphertexts]
    assert len({len(ct.c1) for ct in inner}) == 1
