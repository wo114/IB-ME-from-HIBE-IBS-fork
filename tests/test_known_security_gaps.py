"""Original acceptance targets and the repaired default byte-authentication path.

These are real attacks, not random invalid inputs. Strict XFAIL records an
unfixed education-instance gap, never a security pass. Use --runxfail to enforce
the acceptance targets. Two IBS authentication targets remain XFAIL; the c1
mutation is rejected by BYTEAUTH/1 and accepted by its unwrapped control.
These are not attacks on the generic construction.
"""

from types import SimpleNamespace
from dataclasses import replace

import pytest

from experiments.attacks.forge_ibs import forge_signature
from ibme.core.encoding import encode_bytes, encode_message
from ibme.core.randomness import DeterministicRandom
from ibme.core.lamport_ots import generate_lamport_key
from ibme.hibe.abb10 import ABB10HIBE
from ibme.ibs.sis_ibs import IBS_EDUCATION_PARAMS, SisIBSBackend
from ibme.protocol.baseline import (
    BASELINE_DEBUG_IBS_PARAMS,
    BASELINE_DEBUG_PARAMS,
    BOTTOM,
    BaselineIBME,
    Ciphertext,
    encode_signature,
)
from ibme.protocol.byteauth import (
    BYTEAUTH_DEBUG_PARAMS, ByteAuthenticatedIBME, authenticate_inner, encode_bound_message,
)


@pytest.fixture(scope="module")
def public_forgery():
    backend = SisIBSBackend(rng=DeterministicRandom(b"forge-demo"))
    public, _ = backend.setup(IBS_EDUCATION_PARAMS)
    identity, message = b"Alice", b"forged: never signed by Alice"
    # No key_extract or sign call: the attacker knows only public data.
    signature = forge_signature(public, identity, message)
    return backend, public, identity, message, signature


def _protocol(seed, *, byteauth=False):
    hibe, ibs = ABB10HIBE(), SisIBSBackend(rng=DeterministicRandom(seed + b":ibs"))
    protocol = (ByteAuthenticatedIBME(hibe, ibs, ots_rng=DeterministicRandom(seed + b":ots"))
                if byteauth else BaselineIBME(hibe, ibs))
    public, master = protocol.setup(
        BYTEAUTH_DEBUG_PARAMS if byteauth else BASELINE_DEBUG_PARAMS,
        ibs_params=BASELINE_DEBUG_IBS_PARAMS,
        rng=DeterministicRandom(seed + b":setup"),
    )
    receiver = protocol.rkgen(
        master, b"Bob", rng=DeterministicRandom(seed + b":receiver")
    )
    return SimpleNamespace(protocol=protocol, public=public, master=master,
                           receiver=receiver, seed=seed)


@pytest.fixture(scope="module")
def forged_protocol_result():
    scenario = _protocol(b"known-gap-forgery")
    message = b"public forgery"
    signature = forge_signature(
        scenario.public.ipk, b"Alice", encode_message(b"Bob", message)
    )
    payload = encode_signature(signature) + encode_bytes(message)
    # The authority issues only Bob's receiving key. Alice is never issued a
    # sending key; HIBE encryption is public and does not authenticate her.
    ciphertext = scenario.protocol.hibe_backend.encrypt(
        scenario.public.hpk, b"Bob", b"Alice", payload,
        rng=DeterministicRandom(scenario.seed + b":encrypt"),
    )
    result = scenario.protocol.decrypt(
        scenario.public, scenario.receiver, b"Alice", Ciphertext(ciphertext),
        rng=DeterministicRandom(scenario.seed + b":decrypt"),
    )
    if result is not BOTTOM and result != message:
        raise RuntimeError("Forged ciphertext recovered an unexpected payload")
    return result


@pytest.fixture(scope="module")
def tamper_evidence():
    scenario = _protocol(b"known-gap-integrity", byteauth=True)
    sender = scenario.protocol.skgen(scenario.master, b"Alice")
    message = b"\x00"
    ciphertext = scenario.protocol.encrypt(
        scenario.public, sender, b"Bob", message,
        rng=DeterministicRandom(scenario.seed + b":encrypt"),
    )
    decrypt_seed = scenario.seed + b":decrypt"
    original = scenario.protocol.decrypt(
        scenario.public, scenario.receiver, b"Alice", ciphertext,
        rng=DeterministicRandom(decrypt_seed),
    )
    if original != message:
        raise RuntimeError("Prerequisite failed: honest ciphertext did not decrypt")
    baseline = BaselineIBME(scenario.protocol.hibe_backend, scenario.protocol.ibs_backend)
    raw = ciphertext.inner_bytes
    modified = raw[:-1] + bytes([raw[-1] ^ 1])
    # v2 serialization ends in the last c1 coefficient. Flip only its low bit,
    # inside the Regev decoding tolerance, rather than corrupting a header.
    loaded = baseline.load_ciphertext(modified)
    original_inner = baseline.load_ciphertext(raw)
    if loaded.hibe_ct.c1[-1] ^ original_inner.hibe_ct.c1[-1] != 1:
        raise RuntimeError("Prerequisite failed: mutation is not a c1 low-bit flip")
    unchanged_envelope = baseline.decrypt(
        scenario.public, scenario.receiver, b"Alice", loaded,
        rng=DeterministicRandom(decrypt_seed),
    )
    expected = encode_bound_message(ciphertext.ots_key.commitment(), message)
    if unchanged_envelope != expected:
        raise RuntimeError("Prerequisite failed: the unwrapped c1 mutation did not preserve the plaintext")
    changed = replace(ciphertext, inner_bytes=modified)
    assert scenario.protocol.load_ciphertext(changed.to_bytes()).to_bytes() == changed.to_bytes()
    return scenario, ciphertext, changed, expected, unchanged_envelope


@pytest.fixture(scope="module")
def single_byte_tamper_result(tamper_evidence):
    scenario, original, changed, expected, unchanged = tamper_evidence
    return scenario.protocol.decrypt(scenario.public, scenario.receiver, b"Alice", changed,
                                     rng=DeterministicRandom(scenario.seed + b":decrypt"))


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="LEGACY-IBS-01: education SIS bound admits public linear forgery",
)
def test_public_linear_forgery_is_rejected(public_forgery):
    backend, public, identity, message, signature = public_forgery
    assert not backend.verify(public, identity, message, signature)


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="LEGACY-IBME-01: forged IBS payload authenticates an unissued sender",
)
def test_sender_impersonation_is_rejected(forged_protocol_result):
    assert forged_protocol_result is BOTTOM


def test_single_byte_ciphertext_tampering_is_rejected(single_byte_tamper_result):
    assert single_byte_tamper_result is BOTTOM


def test_unwrapped_c1_tolerance_remains_an_explicit_negative_control(tamper_evidence):
    scenario, original, changed, expected, unchanged = tamper_evidence
    assert unchanged == expected


def test_real_recipient_re_signing_with_a_new_key_is_rejected(tamper_evidence):
    scenario, original, changed, expected, unchanged = tamper_evidence
    attacker_key = generate_lamport_key(rng=DeterministicRandom(b"recipient-re-sign"))
    re_signed = authenticate_inner(scenario.public, changed.inner_bytes, attacker_key)
    assert re_signed.ots_key.verify(re_signed.signed_body(), re_signed.signature)
    assert scenario.protocol.decrypt(scenario.public, scenario.receiver, b"Alice", re_signed,
                                     rng=DeterministicRandom(scenario.seed + b":decrypt")) is BOTTOM


def test_unsafe_ibs_still_allows_byteauth_impersonation_negative_control():
    scenario = _protocol(b"known-gap-byteauth-forgery", byteauth=True)
    # Only Bob receives a key. No sender key is issued, accessed or queried.
    attacker_key = generate_lamport_key(rng=DeterministicRandom(b"attacker-ots"))
    envelope = encode_bound_message(attacker_key.public_key.commitment(), b"public forgery")
    signature = forge_signature(scenario.public.ipk, b"Alice", encode_message(b"Bob", envelope))
    payload = encode_signature(signature) + encode_bytes(envelope)
    hibe_ct = scenario.protocol.hibe_backend.encrypt(scenario.public.hpk, b"Bob", b"Alice", payload,
                     rng=DeterministicRandom(scenario.seed + b":encrypt"))
    ciphertext = authenticate_inner(scenario.public, Ciphertext(hibe_ct).to_bytes(), attacker_key)
    assert scenario.protocol.decrypt(scenario.public, scenario.receiver, b"Alice", ciphertext,
                 rng=DeterministicRandom(scenario.seed + b":decrypt")) == b"public forgery"
