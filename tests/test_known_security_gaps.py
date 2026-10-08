"""Executable security acceptance targets for the legacy education instance.

These are real attacks, not random invalid inputs. Strict XFAIL records an
unfixed education-instance gap, never a security pass. Use --runxfail to enforce
the acceptance targets. These are not attacks on the generic construction.
"""

from types import SimpleNamespace

import pytest

from experiments.attacks.forge_ibs import forge_signature
from ibme.core.encoding import encode_bytes, encode_message
from ibme.core.randomness import DeterministicRandom
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


@pytest.fixture(scope="module")
def public_forgery():
    backend = SisIBSBackend(rng=DeterministicRandom(b"forge-demo"))
    public, _ = backend.setup(IBS_EDUCATION_PARAMS)
    identity, message = b"Alice", b"forged: never signed by Alice"
    # No key_extract or sign call: the attacker knows only public data.
    signature = forge_signature(public, identity, message)
    return backend, public, identity, message, signature


def _protocol(seed):
    protocol = BaselineIBME(
        ABB10HIBE(), SisIBSBackend(rng=DeterministicRandom(seed + b":ibs"))
    )
    public, master = protocol.setup(
        BASELINE_DEBUG_PARAMS,
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
def single_byte_tamper_result():
    scenario = _protocol(b"known-gap-integrity")
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
    raw = ciphertext.to_bytes()
    modified = raw[:-1] + bytes([raw[-1] ^ 1])
    # v2 serialization ends in the last c1 coefficient. Flip only its low bit,
    # inside the Regev decoding tolerance, rather than corrupting a header.
    loaded = scenario.protocol.load_ciphertext(modified)
    if loaded.hibe_ct.c1[-1] ^ ciphertext.hibe_ct.c1[-1] != 1:
        raise RuntimeError("Prerequisite failed: mutation is not a c1 low-bit flip")
    result = scenario.protocol.decrypt(
        scenario.public, scenario.receiver, b"Alice", loaded,
        rng=DeterministicRandom(decrypt_seed),
    )
    if result is not BOTTOM and result != message:
        raise RuntimeError("Tampering changed the plaintext unexpectedly")
    return result


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


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="LEGACY-CT-01: CPA decoding tolerance lacks outer byte integrity",
)
def test_single_byte_ciphertext_tampering_is_rejected(single_byte_tamper_result):
    assert single_byte_tamper_result is BOTTOM
