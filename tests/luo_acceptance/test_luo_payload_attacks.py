# -*- coding: utf-8 -*-
"""Step-17 C (2/4): payload mutations and unchanged-envelope/new-OTS attacks.

Parser/verification reachability is traced separately in test_layer_attribution.py.
Teaching ABB10 Hybrid + Luo only: security_claim: none /
backend_admitted: false / parameters_are_formal: false.
"""
import pytest

from ibme.core.encoding import encode_bytes, encode_message
from ibme.core.lamport_ots import generate_lamport_key
from ibme.core.randomness import DeterministicRandom
from ibme.protocol.baseline import (BOTTOM, DOMAIN_SIGNATURE, BaselineIBME, Ciphertext,
                                    encode_signature, parse_payload)
from ibme.protocol.byteauth import authenticate_inner, encode_bound_message, parse_bound_message
from ibme.protocol.luo_hybrid import make_research_runtime, RESEARCH_HIBE_PARAMS, RESEARCH_IBS_PARAMS


def rng(label):
    return DeterministicRandom(b"step17-c2:" + label)


@pytest.fixture(scope="module")
def env():
    p, _ = make_research_runtime(ibs_rng=rng(b"ibs"), ots_rng=rng(b"ots"))
    public, master = p.setup(RESEARCH_HIBE_PARAMS, ibs_params=RESEARCH_IBS_PARAMS, rng=rng(b"setup"))
    sender = p.skgen(master, b"Alice")
    receiver = p.rkgen(master, b"Bob", rng=rng(b"receiver"))
    cipher = p.encrypt(public, sender, b"Bob", b"payload attacks", rng=rng(b"enc"))
    return p, public, master, sender, receiver, cipher


def _reach_payload(p, public, receiver, cipher):
    baseline = BaselineIBME(p.hibe_backend, p.ibs_backend)
    inner = baseline.load_ciphertext(cipher.inner_bytes)
    child = p.hibe_backend.derive(receiver.level1_key, b"Alice", rng=rng(b"child"))
    payload = p.hibe_backend.decrypt(child, inner.hibe_ct, rng=rng(b"dec"))
    assert isinstance(payload, bytes)  # control: the attacker path recovers the payload
    return baseline, payload


def _wrap(p, public, payload, ots_secret):
    inner = Ciphertext(p.hibe_backend.encrypt(public.hpk, b"Bob", b"Alice", payload, rng=rng(b"wrap")))
    ct = authenticate_inner(public, inner.to_bytes(), ots_secret)
    assert ct.ots_key.verify(ct.signed_body(), ct.signature)
    return ct


@pytest.mark.parametrize("mutation", ["truncate", "append", "duplicate", "wrong-domain"])
def test_payload_mutations_with_valid_ots_rejected(env, mutation):
    p, public, _, _, receiver, cipher = env
    _, payload = _reach_payload(p, public, receiver, cipher)
    if mutation == "truncate":
        payload = payload[:-1]
    elif mutation == "append":
        payload = payload + b"\x00"
    elif mutation == "duplicate":
        payload = payload + payload
    else:
        payload = b"IBME:EVIL:v1" + payload[len(DOMAIN_SIGNATURE):]
    key = generate_lamport_key(rng=rng(b"k-" + mutation.encode()))
    ct = _wrap(p, public, payload, key)
    assert p.decrypt(public, receiver, b"Alice", ct, rng=rng(b"d")) is BOTTOM


def test_decodable_payload_with_flipped_challenge_reaches_verify_and_rejects(env):
    from dataclasses import replace
    p, public, _, _, receiver, cipher = env
    _, payload = _reach_payload(p, public, receiver, cipher)
    sig_raw, envelope = parse_payload(payload)
    signature = p.ibs_backend.load_signature(public.ipk, sig_raw)
    inner_sig = signature.signature if hasattr(signature, "signature") else signature
    changed = replace(inner_sig, c=tuple(-x for x in inner_sig.c))
    reloaded = p.ibs_backend.load_signature(public.ipk, changed.to_bytes())
    assert not p.ibs_backend.verify(public.ipk, b"Alice", encode_message(b"Bob", envelope), reloaded)
    key = generate_lamport_key(rng=rng(b"k-flip"))
    ct = _wrap(p, public, encode_signature(reloaded) + encode_bytes(envelope), key)
    assert p.decrypt(public, receiver, b"Alice", ct, rng=rng(b"d-flip")) is BOTTOM


def test_compact_envelope_unchanged_only_new_ots_rejected():
    """The unchanged envelope retains a valid IBS signature. BYTEAUTH rejects
    its mismatch with the replacement OTS commitment after IBS acceptance.
    The dedicated layer test traces the verifier during protocol decryption."""
    p, _ = make_research_runtime(signature_format="compact", ibs_rng=rng(b"c-ibs"),
                                 ots_rng=rng(b"c-ots"))
    public, master = p.setup(RESEARCH_HIBE_PARAMS, ibs_params=RESEARCH_IBS_PARAMS, rng=rng(b"c-setup"))
    sender = p.skgen(master, b"Alice")
    receiver = p.rkgen(master, b"Bob", rng=rng(b"c-receiver"))
    cipher = p.encrypt(public, sender, b"Bob", b"compact envelope", rng=rng(b"c-enc"))
    assert p.decrypt(public, receiver, b"Alice", cipher, rng=rng(b"c-dec")) == b"compact envelope"  # honest control
    baseline = BaselineIBME(p.hibe_backend, p.ibs_backend)
    inner = baseline.load_ciphertext(cipher.inner_bytes)
    child = p.hibe_backend.derive(receiver.level1_key, b"Alice", rng=rng(b"c-child"))
    payload = p.hibe_backend.decrypt(child, inner.hibe_ct, rng=rng(b"c-inner"))
    assert isinstance(payload, bytes)  # control: inner payload reachable
    sig_raw, envelope = parse_payload(payload)
    commitment, message = parse_bound_message(envelope)
    signature = p.ibs_backend.load_signature(public.ipk, sig_raw)
    assert p.ibs_backend.verify(public.ipk, b"Alice", encode_message(b"Bob", envelope), signature)
    assert message == b"compact envelope"
    attacker = generate_lamport_key(rng=rng(b"c-new"))
    assert attacker.public_key.commitment() != commitment
    inner_new = Ciphertext(p.hibe_backend.encrypt(public.hpk, b"Bob", b"Alice", payload, rng=rng(b"c-re")))
    ct = authenticate_inner(public, inner_new.to_bytes(), attacker)
    assert ct.ots_key.verify(ct.signed_body(), ct.signature)  # new OTS is valid
    assert p.decrypt(public, receiver, b"Alice", ct, rng=rng(b"c-red")) is BOTTOM  # BYTEAUTH commitment mismatch


def test_reference_envelope_unchanged_only_new_ots_rejected(env):
    """Reference counterpart: unchanged-envelope IBS acceptance, followed by
    a BYTEAUTH commitment mismatch; see the dedicated verifier-call probe."""
    p, public, _, _, receiver, cipher = env
    _, payload = _reach_payload(p, public, receiver, cipher)
    sig_raw, envelope = parse_payload(payload)
    commitment, message = parse_bound_message(envelope)
    signature = p.ibs_backend.load_signature(public.ipk, sig_raw)
    assert p.ibs_backend.verify(public.ipk, b"Alice", encode_message(b"Bob", envelope), signature)
    assert message == b"payload attacks"
    attacker = generate_lamport_key(rng=rng(b"r-new"))
    assert attacker.public_key.commitment() != commitment
    inner_new = Ciphertext(p.hibe_backend.encrypt(public.hpk, b"Bob", b"Alice", payload, rng=rng(b"r-re")))
    ct = authenticate_inner(public, inner_new.to_bytes(), attacker)
    assert ct.ots_key.verify(ct.signed_body(), ct.signature)
    assert p.decrypt(public, receiver, b"Alice", ct, rng=rng(b"r-red")) is BOTTOM


def test_same_bytes_ciphertext_replay_is_not_an_attack(env):
    p, public, _, _, receiver, cipher = env
    raw = cipher.to_bytes()
    assert p.decrypt(public, receiver, b"Alice", p.load_ciphertext(raw), rng=rng(b"d1")) == b"payload attacks"
    assert p.decrypt(public, receiver, b"Alice", raw, rng=rng(b"d2")) == b"payload attacks"
