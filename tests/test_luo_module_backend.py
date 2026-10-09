"""Luo §4 four algorithms, objects, lifecycle and public attack controls."""

from dataclasses import replace

import pytest

from ibme.core.errors import EncodingError, IBMEError, InvalidParameterError, RandomnessError, SerializationError
from ibme.core.hashing import hash_identity
from ibme.core.randomness import DeterministicRandom
from ibme.ibs.api import IBSBackend, IBSPublicKey, IBSMasterSecret, IBSSigningKey, IBSSignature
from ibme.ibs.luo_module import (
    LuoModuleParams, LuoModuleIBSBackend, LuoModulePublicKey, LuoModuleMasterSecret,
    LuoModuleSigningKey, LuoModuleSignature, LuoModuleSamplingAbort,
    DOMAIN_H1, challenge, message_challenge,
)


def tiny_params(**changes):
    values = dict(degree=8, k=2, l=1, q=769, root=27, kappa=1,
                  gamma1=16, gamma2=256, gamma3=128, dropped_bits=3)
    return LuoModuleParams(**{**values, **changes})


def backend(seed): return LuoModuleIBSBackend(rng=DeterministicRandom(seed))


@pytest.fixture(scope="module")
def small():
    b = backend(b"module-small-contract")
    pk, msk = b.setup(tiny_params())
    sk = b.key_extract(msk, b"Alice")
    return b, pk, msk, sk


@pytest.fixture(scope="module")
def large():
    b = backend(b"module-large-contract")
    pk, msk = b.setup(LuoModuleParams())
    sk = b.key_extract(msk, b"Alice")
    sig = b.sign(sk, b"reference")
    return b, pk, msk, sk, sig


def test_frozen_interfaces_and_public_only_roundtrip(large):
    b, pk, msk, sk, sig = large
    assert isinstance(b, IBSBackend) and isinstance(pk, IBSPublicKey)
    assert isinstance(msk, IBSMasterSecret) and isinstance(sk, IBSSigningKey) and isinstance(sig, IBSSignature)
    assert sk.identity_digest == hash_identity(b"Alice", 32)
    public = LuoModulePublicKey.from_bytes(pk.to_bytes())
    verifier = LuoModuleIBSBackend()  # No master, Extract calls or key directory.
    loaded = verifier.load_signature(public, sig.to_bytes())
    assert verifier.verify(public, b"Alice", b"reference", loaded)
    assert loaded.to_bytes() == sig.to_bytes()
    assert pk.params.q > 2**32 and pk.params.max_w1 == 1024
    assert pk.params.security_claim == "none" and not b.backend_admitted


def test_public_only_fresh_process_verify(large, tmp_path):
    import os
    from pathlib import Path
    import subprocess
    import sys
    _, pk, _, _, sig = large
    (tmp_path / "public.bin").write_bytes(pk.to_bytes())
    (tmp_path / "signature.bin").write_bytes(sig.to_bytes())
    # The new process receives no private state, key directory or test RNG.
    source = Path(__file__).resolve().parents[1] / "src"
    environment = {**os.environ, "PYTHONPATH": str(source), "PYTHONDONTWRITEBYTECODE": "1"}
    script = """from pathlib import Path
from ibme.ibs import LuoModulePublicKey, LuoModuleIBSBackend
p = LuoModulePublicKey.from_bytes(Path('public.bin').read_bytes())
b = LuoModuleIBSBackend()
s = b.load_signature(p, Path('signature.bin').read_bytes())
assert b.verify(p, b'Alice', b'reference', s)
assert not b.verify(p, b'other', b'reference', s)
assert not b.verify(p, b'Alice', b'changed', s)
print('public-only verification passed')
"""
    result = subprocess.run([sys.executable, "-B", "-c", script], cwd=tmp_path,
                            env=environment, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "public-only verification passed"


@pytest.mark.parametrize("identity,message", [(b"Bob", b""), ("发送者".encode(), b"\x00\xff"), (b"edge", b"x" * 4096)])
def test_real_large_parameters_multiple_identities_and_messages(large, identity, message):
    b, pk, msk, sk, sig = large
    key = b.key_extract(msk, identity)
    signature = b.sign(key, message)
    assert b.verify(pk, identity, message, signature)
    assert not b.verify(pk, identity, message + b"different", signature)
    assert not b.verify(pk, b"other", message, signature)


def test_persistent_identity_keys_restore_and_continue_signing(small, tmp_path):
    b, pk, msk, sk = small
    before = sk.to_bytes()
    b.sign(sk, b"first")
    assert b.key_extract(msk, b"Alice").to_bytes() == before and b.last_extract_attempts == 0
    path = tmp_path / "private-master"
    path.write_bytes(msk.to_bytes())
    restored = LuoModuleMasterSecret.from_bytes(path.read_bytes())
    copied_key = LuoModuleSigningKey.from_bytes(before)
    assert b.key_extract(restored, b"Alice").to_bytes() == copied_key.to_bytes() == before
    signature = b.sign(copied_key, b"continued")
    assert b.verify(pk, b"Alice", b"continued", signature)
    assert b"module-small-contract" not in restored.to_bytes()
    assert "redacted" in repr(sk) and "redacted" in repr(restored)
    with pytest.raises(TypeError): hash(msk)


@pytest.mark.parametrize("field", ["z", "c", "w1", "h"])
def test_large_signature_field_changes_are_rejected(large, field):
    b, pk, msk, sk, sig = large
    values = list(sig.c if field == "c" else getattr(sig, field))
    if field == "c":
        pos = next(i for i, value in enumerate(values) if value)
        values[pos] *= -1
    else:
        row = list(values[0])
        row[0] = (row[0] ^ 1) if field == "h" else row[0] + 1
        values[0] = tuple(row)
    altered = replace(sig, **{field: tuple(values)})
    assert not b.verify(pk, b"Alice", b"reference", altered)


@pytest.mark.parametrize("data", [None, "wrong", b"", b"unknown"])
def test_invalid_object_encodings_rejected(data):
    for parser in (LuoModulePublicKey.from_bytes, LuoModuleMasterSecret.from_bytes, LuoModuleSigningKey.from_bytes):
        with pytest.raises(SerializationError): parser(data)


@pytest.mark.parametrize("kind", ["public", "master", "key", "signature"])
@pytest.mark.parametrize("change", ["truncate", "append", "duplicate", "version"])
def test_all_object_framing_is_strict(small, kind, change):
    b, pk, msk, sk = small
    sig = b.sign(sk, b"framing")
    value, parser = {
        "public": (pk, LuoModulePublicKey.from_bytes),
        "master": (msk, LuoModuleMasterSecret.from_bytes),
        "key": (sk, LuoModuleSigningKey.from_bytes),
        "signature": (sig, lambda raw: b.load_signature(pk, raw)),
    }[kind]
    raw = value.to_bytes()
    if change == "truncate": raw = raw[:-1]
    elif change == "append": raw += b"\0"
    elif change == "duplicate": raw += raw
    else: raw = b"?" + raw[1:]
    with pytest.raises(IBMEError): parser(raw)


def test_bad_keys_fail_equations_and_signature_context_is_bound(small):
    b, pk, msk, sk = small
    changed = list(msk.s1[0]); changed[0] = 0 if changed[0] else 1
    with pytest.raises(SerializationError): replace(msk, s1=(tuple(changed),))
    changed = list(sk.z1[0]); changed[0] += 1
    with pytest.raises(SerializationError): replace(sk, z1=(tuple(changed),))
    pk2, _ = backend(b"different-public").setup(tiny_params())
    signature = b.sign(sk, b"different-context")
    assert not b.verify(pk2, b"Alice", b"different-context", signature)
    with pytest.raises(SerializationError): b.load_signature(pk2, signature.to_bytes())


@pytest.mark.parametrize("changes", [{"q": 771}, {"q": 2**64 - 1}, {"degree": 512}, {"degree": True},
                                      {"root": 1}, {"kappa": 9}, {"gamma3": 16}, {"dropped_bits": 2**63}])
def test_invalid_params_and_exponents_rejected_before_allocation(changes):
    p = tiny_params()
    with pytest.raises(InvalidParameterError): replace(p, **changes)


def test_challenge_weight_signs_domain_and_bounds(small):
    b, pk, msk, sk = small
    seen = set()
    for i in range(100):
        c = challenge(pk.params, DOMAIN_H1, i.to_bytes(4, "big"))
        assert sum(abs(x) for x in c) == pk.params.kappa and set(c) <= {-1, 0, 1}
        seen.add(c)
    assert len(seen) > 8


def test_entropy_and_uniform_budget_exhaustion():
    class Short:
        def read(self, count): return b""
    with pytest.raises(RandomnessError): backend_object = LuoModuleIBSBackend(rng=object())
    with pytest.raises(RandomnessError): LuoModuleIBSBackend(rng=Short()).setup(tiny_params())
    class FF:
        def read(self, count): return b"\xff" * count
    p = replace(tiny_params(), max_uniform_attempts=1)
    with pytest.raises(LuoModuleSamplingAbort): LuoModuleIBSBackend(rng=FF()).setup(p)


def test_cache_and_sign_budget_have_explicit_abort():
    p = replace(tiny_params(), max_cached_identities=1, max_sign_attempts=1)
    b = backend(b"module-budgets")
    pk, msk = b.setup(p)
    key = b.key_extract(msk, b"Alice")
    with pytest.raises(LuoModuleSamplingAbort): b.key_extract(msk, b"Bob")
    assert b.key_extract(msk, b"Alice") == key
    class Zero:
        def read(self, count): return b"\0" * count
    with pytest.raises(LuoModuleSamplingAbort): LuoModuleIBSBackend(rng=Zero()).sign(key, b"abort")


def test_zero_response_is_allowed_as_type_and_toy_public_search_can_forge(small):
    b, pk, msk, sk = small
    # Public-only finite FS challenge search. No secret, Extract or sign call.
    public = LuoModulePublicKey.from_bytes(pk.to_bytes())
    zeros_l = ((0,) * public.params.degree,) * public.params.l
    zeros_k = ((0,) * public.params.degree,) * public.params.k
    queries = 0
    accepted = False
    for i in range(64):
        message = b"public-search:" + i.to_bytes(2, "big")
        for position in range(public.params.degree):
            for sign in (-1, 1):
                c = tuple(sign if j == position else 0 for j in range(public.params.degree))
                signature = LuoModuleSignature(public.params, public.context, zeros_l, c, zeros_k, zeros_k)
                queries += 1
                if b.verify(public, b"never-issued", message, signature):
                    accepted = True
                    break
            if accepted: break
        if accepted: break
    assert accepted and queries <= 1024  # Tiny challenge domain=16, not secure.


def test_verify_rejects_programming_types_and_size_errors(small):
    b, pk, msk, sk = small
    sig = b.sign(sk, b"valid")
    for args in ((object(), b"Alice", b"valid", sig), (pk, b"", b"valid", sig),
                 (pk, b"Alice", object(), sig), (pk, b"Alice", b"valid", object())):
        assert b.verify(*args) is False
    with pytest.raises(TypeError): b.setup(None)
    with pytest.raises(TypeError): b.sign(object(), b"msg")
    with pytest.raises(EncodingError): b.key_extract(msk, b"")
    with pytest.raises(EncodingError): b.sign(sk, b"x" * (pk.params.message_max_bytes + 1))


def test_hash_budget_abort_keeps_its_resource_error_type(monkeypatch, small):
    import ibme.ibs.luo_module as module
    monkeypatch.setattr(module, "HASH_BYTES", 1)
    with pytest.raises(LuoModuleSamplingAbort): challenge(small[1].params, DOMAIN_H1, b"hash budget")


def test_private_cache_duplicate_reorder_and_invalid_identity_rejected(small):
    import ibme.ibs.luo_module as module
    b, pk, original, sk = small
    master = LuoModuleMasterSecret.from_bytes(original.to_bytes())
    first, second = b.key_extract(master, b"A"), b.key_extract(master, b"B")
    public, s1, s2, cache = module._unframe(master.to_bytes(), b"MASTER", 4)
    from ibme.core.encoding import encode_bytes
    for records in ((first, first), (second, first)):
        malformed = (2).to_bytes(4, "big") + b"".join(encode_bytes(key._local_bytes()) for key in records)
        with pytest.raises(SerializationError):
            LuoModuleMasterSecret.from_bytes(module._frame(b"MASTER", (public, s1, s2, malformed)))
    fields = module._unframe(first._local_bytes(), b"IDENTITY-STATE", 4)
    local = module._frame(b"IDENTITY-STATE", (b"", *fields[1:]))
    with pytest.raises(SerializationError):
        LuoModuleSigningKey.from_bytes(module._frame(b"SIGNING-KEY", (public, local)))


def test_real_module_ibs_connects_via_frozen_protocol_api_with_test_hibe(large):
    from ibme.hibe.mock import MockHIBE
    from ibme.protocol.baseline import BASELINE_MOCK_PARAMS, BaselineIBME, BOTTOM
    from ibme.protocol.byteauth import ByteAuthenticatedIBME
    b, pk, msk, sk, signature = large
    protocol = ByteAuthenticatedIBME(MockHIBE(), b, ots_rng=DeterministicRandom(b"module-protocol-ots"))
    public, master = protocol.setup(replace(BASELINE_MOCK_PARAMS, max_message_bytes=65536), ibs_params=LuoModuleParams())
    sender = protocol.skgen(master, b"Alice")
    receiver = protocol.rkgen(master, b"Bob")
    cipher = protocol.encrypt(public, sender, b"Bob", b"module integration")
    assert protocol.decrypt(public, receiver, b"Alice", cipher.to_bytes()) == b"module integration"
    assert protocol.decrypt(public, receiver, b"other", cipher) is BOTTOM
    wrong = protocol.rkgen(master, b"other")
    assert protocol.decrypt(public, wrong, b"Alice", cipher) is BOTTOM
    assert protocol.decrypt(public, wrong, b"other", cipher) is BOTTOM
    changed = replace(cipher, inner_bytes=cipher.inner_bytes[:-1] + bytes([cipher.inner_bytes[-1] ^ 1]))
    assert protocol.decrypt(public, receiver, b"Alice", changed) is BOTTOM
    # This HIBE is a TEST-ONLY component; no complete secure IBME is counted.
