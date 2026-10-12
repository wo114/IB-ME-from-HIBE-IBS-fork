# -*- coding: utf-8 -*-
"""Step-17 C (4/4): payload/limits and bare-capsule tampering regressions.

A 32-byte outer-payload roundtrip does not prove the inner seed size; the
public-call-boundary tests in test_layer_attribution.py measure that input.
Teaching ABB10 Hybrid + Luo only: security_claim: none /
backend_admitted: false / parameters_are_formal: false.
"""
from dataclasses import replace

import pytest

from ibme.core.encoding import encode_message
from ibme.core.errors import EncodingError, InvalidParameterError
from ibme.core.randomness import DeterministicRandom
from ibme.protocol.byteauth import encode_bound_message
from ibme.protocol.luo_hybrid import make_research_runtime, RESEARCH_HIBE_PARAMS, RESEARCH_IBS_PARAMS, MAX_APPLICATION_BYTES


def rng(label):
    return DeterministicRandom(b"step17-c4:" + label)


@pytest.fixture(scope="module")
def env():
    p, _ = make_research_runtime(ibs_rng=rng(b"ibs"), ots_rng=rng(b"ots"))
    public, master = p.setup(RESEARCH_HIBE_PARAMS, ibs_params=RESEARCH_IBS_PARAMS, rng=rng(b"setup"))
    sender = p.skgen(master, b"Alice")
    receiver = p.rkgen(master, b"Bob", rng=rng(b"receiver"))
    return p, public, master, sender, receiver


class NoEntropy:
    def read(self, count):
        raise AssertionError("must not reach randomness")


def test_identity_64_ok_65_rejected_before_randomness(env):
    p, public, master, sender, _ = env
    dk = p.rkgen(master, b"R" * 64, rng=rng(b"rk64"))
    ct = p.encrypt(public, sender, b"R" * 64, b"m", rng=rng(b"e64"))
    assert p.decrypt(public, dk, b"Alice", ct, rng=rng(b"d64")) == b"m"
    p2, _ = make_research_runtime(ibs_rng=NoEntropy(), ots_rng=NoEntropy())
    with pytest.raises(EncodingError):
        p2.rkgen(master, b"R" * 65, rng=NoEntropy())
    with pytest.raises(EncodingError):
        p2.encrypt(public, sender, b"R" * 65, b"m", rng=NoEntropy())


def test_message_3924_ok_3925_rejected_before_randomness(env):
    p, public, _, sender, receiver = env
    ct = p.encrypt(public, sender, b"Bob", b"x" * MAX_APPLICATION_BYTES, rng=rng(b"e"))
    assert p.decrypt(public, receiver, b"Alice", ct, rng=rng(b"d")) == b"x" * MAX_APPLICATION_BYTES
    p2, _ = make_research_runtime(ibs_rng=NoEntropy(), ots_rng=NoEntropy())
    with pytest.raises(InvalidParameterError):
        p2.encrypt(public, sender, b"Bob", b"x" * (MAX_APPLICATION_BYTES + 1), rng=NoEntropy())


def test_inner_payload_length_formula(env):
    p, public, _, sender, receiver = env
    from ibme.protocol.baseline import BaselineIBME, parse_payload
    ct = p.encrypt(public, sender, b"Bob", b"x" * MAX_APPLICATION_BYTES, rng=rng(b"pl"))
    baseline = BaselineIBME(p.hibe_backend, p.ibs_backend)
    inner = baseline.load_ciphertext(ct.inner_bytes)
    child = p.hibe_backend.derive(receiver.level1_key, b"Alice", rng=rng(b"c"))
    payload = p.hibe_backend.decrypt(child, inner.hibe_ct, rng=rng(b"d"))
    sig_raw, envelope = parse_payload(payload)
    assert len(payload) == len(sig_raw) + 108 + MAX_APPLICATION_BYTES


@pytest.mark.parametrize("fmt,expected_sig", [("reference", 29455), ("compact", 16063)])
def test_signature_and_payload_sizes(fmt, expected_sig):
    p, _ = make_research_runtime(signature_format=fmt, ibs_rng=rng(fmt.encode() + b"-i"),
                                 ots_rng=rng(fmt.encode() + b"-o"))
    public, master = p.setup(RESEARCH_HIBE_PARAMS, ibs_params=RESEARCH_IBS_PARAMS, rng=rng(fmt.encode() + b"-s"))
    sender = p.skgen(master, b"Alice")
    envelope = encode_bound_message(b"c" * 64, b"x" * MAX_APPLICATION_BYTES)
    sig = p.ibs_backend.sign(sender.signing_key, encode_message(b"Bob", envelope))
    assert len(sig.to_bytes()) == expected_sig
    from ibme.protocol.baseline import encode_signature
    from ibme.core.encoding import encode_bytes
    payload = encode_signature(sig) + encode_bytes(envelope)
    assert len(payload) == expected_sig + 108 + MAX_APPLICATION_BYTES


def test_hybrid_32_byte_outer_payload_roundtrip(env):
    p, public, _, _, receiver = env
    hibe = p.hibe_backend
    payload = b"s" * 32
    ct = hibe.encrypt(public.hpk, b"Bob", b"Alice", payload, rng=rng(b"cap"))
    child = hibe.derive(receiver.level1_key, b"Alice", rng=rng(b"ch"))
    assert hibe.decrypt(child, ct, rng=rng(b"dc")) == payload
    assert len(ct.body) == 32 + 16  # Outer payload plus GCM tag, not a seed-size probe.


def test_hybrid_payload_cap_is_65536(env):
    from ibme.protocol.hybrid_hibe import HybridLimits
    assert HybridLimits().max_payload_bytes == 65536


def test_compact_does_not_change_application_limit(env):
    from ibme.protocol.luo_hybrid import MAX_APPLICATION_BYTES as M
    assert M == 3924
    pc, _ = make_research_runtime(signature_format="compact", ibs_rng=rng(b"c-i"),
                                  ots_rng=rng(b"c-o"))
    public, master = pc.setup(RESEARCH_HIBE_PARAMS, ibs_params=RESEARCH_IBS_PARAMS, rng=rng(b"c-s"))
    sender = pc.skgen(master, b"Alice")
    receiver = pc.rkgen(master, b"Bob", rng=rng(b"c-r"))
    ct = pc.encrypt(public, sender, b"Bob", b"x" * M, rng=rng(b"c-e"))
    assert pc.decrypt(public, receiver, b"Alice", ct, rng=rng(b"c-d")) == b"x" * M


def test_bare_cpa_capsule_low_bit_preserves_seed_but_hybrid_aad_rejects(env):
    """Layered tamper acceptance (task C5): bare CPA ABB10 low-bit mutation may
    still recover the SAME 32 B value; Hybrid rejects it via the full-capsule
    AAD. Inner decapsulation happens FIRST, then the DEM tag check (hybrid_hibe
    decrypt order); we do not claim capsule changes are rejected before seed
    decapsulation."""
    p, public, _, _, receiver = env
    hibe = p.hibe_backend
    seed = b"s" * 32
    ct = hibe.encrypt(public.hpk, b"Bob", b"Alice", seed, rng=rng(b"lb"))
    original = hibe.inner_backend.load_ciphertext(ct.capsule)
    changed_bytes = ct.capsule[:-1] + bytes([ct.capsule[-1] ^ 1])
    altered = hibe.inner_backend.load_ciphertext(changed_bytes)
    assert original.c1[-1] ^ altered.c1[-1] == 1
    child = hibe.derive(receiver.level1_key, b"Alice", rng=rng(b"ch"))
    recovered = hibe.inner_backend.decrypt(child.inner, original, rng=rng(b"sd"))
    assert isinstance(recovered, bytes) and len(recovered) == 32
    assert hibe.inner_backend.decrypt(child.inner, altered, rng=rng(b"sd")) == recovered  # CPA tolerance
    assert hibe.decrypt(child, replace(ct, capsule=changed_bytes), rng=rng(b"sd")) is None  # AAD rejects
