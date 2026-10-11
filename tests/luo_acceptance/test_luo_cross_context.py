# -*- coding: utf-8 -*-
"""Step-17 C (1/4): cross-public-key/context regressions in both formats.

Endpoint rejection alone does not establish a failure layer; dedicated probes
live in test_layer_attribution.py. Teaching ABB10 Hybrid + Luo only:
security_claim: none / backend_admitted: false / parameters_are_formal: false.
"""
import pytest

from ibme.core.encoding import decode_bytes, encode_bytes, encode_message
from ibme.core.errors import SerializationError
from ibme.core.lamport_ots import generate_lamport_key
from ibme.core.randomness import DeterministicRandom
from ibme.ibs.luo_module import LuoModuleSignature, challenge
from ibme.protocol.baseline import BOTTOM, BaselineIBME, Ciphertext, encode_signature, parse_payload
from ibme.protocol.byteauth import authenticate_inner, encode_bound_message, public_context
from ibme.protocol.luo_hybrid import make_research_runtime, RESEARCH_HIBE_PARAMS, RESEARCH_IBS_PARAMS


def rng(label):
    return DeterministicRandom(b"step17-c1:" + label)


def build(fmt, tag):
    p, _ = make_research_runtime(signature_format=fmt, ibs_rng=rng(tag + b"ibs"),
                                 ots_rng=rng(tag + b"ots"))
    public, master = p.setup(RESEARCH_HIBE_PARAMS, ibs_params=RESEARCH_IBS_PARAMS, rng=rng(tag + b"setup"))
    sender = p.skgen(master, b"Alice")
    receiver = p.rkgen(master, b"Bob", rng=rng(tag + b"receiver"))
    return p, public, master, sender, receiver


@pytest.fixture(scope="module")
def envs():
    out = {}
    for fmt in ("reference", "compact"):
        out[fmt] = build(fmt, b"A-" + fmt.encode())
        out[fmt + "-B"] = build(fmt, b"B-" + fmt.encode())
    return out


@pytest.mark.parametrize("fmt", ["reference", "compact"])
def test_honest_control_roundtrip(envs, fmt):
    p, public, _, sender, receiver = envs[fmt]
    ct = p.encrypt(public, sender, b"Bob", b"control", rng=rng(fmt.encode() + b"-enc"))
    assert p.decrypt(public, receiver, b"Alice", ct, rng=rng(fmt.encode() + b"-dec")) == b"control"


@pytest.mark.parametrize("fmt", ["reference", "compact"])
def test_original_signature_under_other_public_key_rejected(envs, fmt):
    p, public, _, sender, _ = envs[fmt]
    pB, publicB, _, _, _ = envs[fmt + "-B"]
    signed = encode_message(b"Bob", b"m")
    sig = p.ibs_backend.sign(sender.signing_key, signed)
    assert p.ibs_backend.verify(public.ipk, b"Alice", signed, sig)  # honest control
    assert not pB.ibs_backend.verify(publicB.ipk, b"Alice", signed, sig)  # IBS context layer


@pytest.mark.parametrize("fmt", ["reference", "compact"])
def test_context_flipped_signature_bytes_rejected(envs, fmt):
    p, public, _, sender, _ = envs[fmt]
    signed = encode_message(b"Bob", b"m")
    sig = p.ibs_backend.sign(sender.signing_key, signed)
    raw = bytearray(sig.to_bytes())
    # Both wire formats have a 5-byte magic followed by length-prefixed
    # version, kind, parameters and public context. Locate the field explicitly.
    pos = 5
    for _ in range(3):
        _, pos = decode_bytes(bytes(raw), pos)
    context, end = decode_bytes(bytes(raw), pos)
    assert context == public.ipk.context and len(context) == 64
    raw[end - len(context) + 6] ^= 1
    with pytest.raises(SerializationError):
        p.ibs_backend.load_signature(public.ipk, bytes(raw))


@pytest.mark.parametrize("fmt", ["reference", "compact"])
def test_full_ciphertext_under_other_public_key_bottom(envs, fmt):
    p, public, _, sender, _ = envs[fmt]
    pB, publicB, _, _, receiverB = envs[fmt + "-B"]
    ct = p.encrypt(public, sender, b"Bob", b"replay", rng=rng(fmt.encode() + b"-ct"))
    assert pB.decrypt(publicB, receiverB, b"Alice", ct, rng=rng(fmt.encode() + b"-dec")) is BOTTOM
    # BYTEAUTH's public-context gate rejects this cross-system frame. The OTS
    # signature itself remains valid; the no-HIBE-call probe is in the layer tests.
    assert ct.context == public_context(public)
    assert public_context(public) != public_context(publicB)
    assert ct.ots_key.verify(ct.signed_body(), ct.signature)


@pytest.mark.parametrize("fmt", ["reference", "compact"])
def test_recipient_reencrypt_envelope_under_other_key_binding_rejects(envs, fmt):
    p, public, _, sender, receiver = envs[fmt]
    pB, publicB, _, _, receiverB = envs[fmt + "-B"]
    ct = p.encrypt(public, sender, b"Bob", b"bind", rng=rng(fmt.encode() + b"-b"))
    baseline = BaselineIBME(p.hibe_backend, p.ibs_backend)
    inner = baseline.load_ciphertext(ct.inner_bytes)
    child = p.hibe_backend.derive(receiver.level1_key, b"Alice", rng=rng(fmt.encode() + b"-c"))
    payload = p.hibe_backend.decrypt(child, inner.hibe_ct, rng=rng(fmt.encode() + b"-d"))
    assert isinstance(payload, bytes)  # proves the attacker reached the inner layer
    sig_raw, envelope = parse_payload(payload)
    sig = p.ibs_backend.load_signature(public.ipk, sig_raw)
    innerB = Ciphertext(pB.hibe_backend.encrypt(publicB.hpk, b"Bob", b"Alice",
                        encode_signature(sig) + encode_bytes(envelope), rng=rng(fmt.encode() + b"-e")))
    re_signed = authenticate_inner(publicB, innerB.to_bytes(),
                                   generate_lamport_key(rng=rng(fmt.encode() + b"-k")))
    assert re_signed.ots_key.verify(re_signed.signed_body(), re_signed.signature)
    assert pB.decrypt(publicB, receiverB, b"Alice", re_signed, rng=rng(fmt.encode() + b"-f")) is BOTTOM
    # This test establishes valid OTS plus endpoint rejection only. The separate
    # rewrapped-other-public-key layer test probes HIBE recovery and IBS loading.


@pytest.mark.parametrize("fmt", ["reference", "compact"])
def test_unissued_sender_spoof_with_valid_ots_rejected(envs, fmt):
    p, public, _, _, receiver = envs[fmt]
    attacker = generate_lamport_key(rng=rng(fmt.encode() + b"-atk"))
    envelope = encode_bound_message(attacker.public_key.commitment(), b"spoof")
    signed = encode_message(b"Bob", envelope)
    params = public.ipk.params
    c = challenge(params, b"step17:guess:v1", b"seed")
    sig = LuoModuleSignature(params, public.ipk.context, ((0,) * params.degree,) * params.l,
                             c, ((0,) * params.degree,) * params.k, ((0,) * params.degree,) * params.k)
    if fmt == "compact":
        from ibme.ibs.luo_module_codec import LuoModuleCompactSignature
        sig = LuoModuleCompactSignature(sig)
    loaded = p.ibs_backend.load_signature(public.ipk, sig.to_bytes())
    assert not p.ibs_backend.verify(public.ipk, b"Unissued", signed, loaded)
    inner = Ciphertext(p.hibe_backend.encrypt(public.hpk, b"Bob", b"Unissued",
                       encode_signature(loaded) + encode_bytes(envelope), rng=rng(fmt.encode() + b"-sp")))
    forged = authenticate_inner(public, inner.to_bytes(), attacker)
    assert forged.ots_key.verify(forged.signed_body(), forged.signature)
    assert p.decrypt(public, receiver, b"Unissued", forged, rng=rng(fmt.encode() + b"-sd")) is BOTTOM
