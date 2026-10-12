"""Independent layer-attribution regressions for the step-17 Luo package.

These tests deliberately keep the teaching ABB10 Hybrid + Luo setting:
security_claim: none / backend_admitted: false / parameters_are_formal: false.
Public-call probes are implementation observations, not security proofs.
"""

from unittest.mock import patch

import pytest

from ibme.core.encoding import encode_message
from ibme.core.errors import SerializationError
from ibme.core.lamport_ots import generate_lamport_key
from ibme.core.randomness import DeterministicRandom
from ibme.protocol.baseline import BOTTOM, BaselineIBME, Ciphertext, parse_payload
from ibme.protocol.byteauth import authenticate_inner, parse_bound_message, public_context
from ibme.protocol.luo_hybrid import (
    RESEARCH_HIBE_PARAMS,
    RESEARCH_IBS_PARAMS,
    make_research_runtime,
)


def rng(label: bytes) -> DeterministicRandom:
    return DeterministicRandom(b"codex-step17-layer:" + label)


def system(fmt: str, label: bytes):
    protocol, _ = make_research_runtime(
        signature_format=fmt,
        ibs_rng=rng(label + b":ibs"),
        ots_rng=rng(label + b":ots"),
    )
    public, master = protocol.setup(
        RESEARCH_HIBE_PARAMS, ibs_params=RESEARCH_IBS_PARAMS,
        rng=rng(label + b":setup"),
    )
    sender = protocol.skgen(master, b"Alice")
    receiver = protocol.rkgen(master, b"Bob", rng=rng(label + b":receiver"))
    return protocol, public, sender, receiver


@pytest.mark.parametrize("fmt", ["reference", "compact"])
def test_cross_system_rejected_by_byteauth_context_before_hibe(fmt):
    pa, pka, sender, receiver_a = system(fmt, b"cross-a:" + fmt.encode())
    pb, pkb, _, receiver_b = system(fmt, b"cross-b:" + fmt.encode())
    ciphertext = pa.encrypt(pka, sender, b"Bob", b"cross-key", rng=rng(b"cross-enc"))
    assert pa.decrypt(pka, receiver_a, b"Alice", ciphertext, rng=rng(b"cross-dec")) == b"cross-key"
    assert ciphertext.context == public_context(pka)
    assert ciphertext.context != public_context(pkb)
    assert ciphertext.ots_key.verify(ciphertext.signed_body(), ciphertext.signature)
    # ByteAuthenticatedIBME.decrypt short-circuits on the context mismatch.
    with patch.object(pb.hibe_backend, "derive", side_effect=AssertionError("inner HIBE unexpectedly reached")) as derive:
        assert pb.decrypt(pkb, receiver_b, b"Alice", ciphertext, rng=rng(b"cross-b-dec")) is BOTTOM
        derive.assert_not_called()


@pytest.mark.parametrize("fmt", ["reference", "compact"])
def test_new_valid_ots_rejected_by_post_ibs_byteauth_commitment(fmt):
    protocol, public, sender, receiver = system(fmt, b"ots:" + fmt.encode())
    message = b"same signed envelope"
    ciphertext = protocol.encrypt(public, sender, b"Bob", message, rng=rng(b"ots-enc"))
    assert protocol.decrypt(public, receiver, b"Alice", ciphertext, rng=rng(b"ots-dec")) == message

    baseline = BaselineIBME(protocol.hibe_backend, protocol.ibs_backend)
    inner = baseline.load_ciphertext(ciphertext.inner_bytes)
    child = protocol.hibe_backend.derive(receiver.level1_key, b"Alice", rng=rng(b"ots-child"))
    payload = protocol.hibe_backend.decrypt(child, inner.hibe_ct, rng=rng(b"ots-inner"))
    assert isinstance(payload, bytes)
    signature_bytes, envelope = parse_payload(payload)
    signature = protocol.ibs_backend.load_signature(public.ipk, signature_bytes)
    assert protocol.ibs_backend.verify(public.ipk, b"Alice", encode_message(b"Bob", envelope), signature)
    old_commitment, recovered_message = parse_bound_message(envelope)
    assert recovered_message == message
    assert old_commitment == ciphertext.ots_key.commitment()

    replacement_key = generate_lamport_key(rng=rng(b"ots-new:" + fmt.encode()))
    assert replacement_key.public_key.commitment() != old_commitment
    replacement_inner = Ciphertext(protocol.hibe_backend.encrypt(
        public.hpk, b"Bob", b"Alice", payload, rng=rng(b"ots-rewrap:" + fmt.encode())
    ))
    attack = authenticate_inner(public, replacement_inner.to_bytes(), replacement_key)
    assert attack.ots_key.verify(attack.signed_body(), attack.signature)

    original_verify = protocol.ibs_backend.verify
    observed_results = []

    def observed_verify(*args, **kwargs):
        result = original_verify(*args, **kwargs)
        observed_results.append(result)
        return result

    with patch.object(protocol.ibs_backend, "verify", side_effect=observed_verify):
        assert protocol.decrypt(public, receiver, b"Alice", attack, rng=rng(b"ots-attack-dec")) is BOTTOM
    # The IBS verifier accepted the unchanged envelope.  The failure occurs
    # afterwards in ByteAuthenticatedIBME.decrypt's OTS commitment comparison.
    assert observed_results == [True]


@pytest.mark.parametrize("mutation", ["truncate", "append", "duplicate", "wrong-domain"])
def test_malformed_payload_reaches_parser_without_signature_loading(mutation):
    protocol, public, sender, receiver = system("reference", b"payload")
    ciphertext = protocol.encrypt(public, sender, b"Bob", b"original", rng=rng(b"payload-enc"))
    baseline = BaselineIBME(protocol.hibe_backend, protocol.ibs_backend)
    inner = baseline.load_ciphertext(ciphertext.inner_bytes)
    child = protocol.hibe_backend.derive(receiver.level1_key, b"Alice", rng=rng(b"payload-child"))
    payload = protocol.hibe_backend.decrypt(child, inner.hibe_ct, rng=rng(b"payload-inner"))
    assert isinstance(payload, bytes)

    if mutation == "truncate":
        changed = payload[:-1]
    elif mutation == "append":
        changed = payload + b"\0"
    elif mutation == "duplicate":
        changed = payload + payload
    else:
        changed = b"IBME:EVIL:v1" + payload[len(b"IBME:SIG:v1"):]
    with pytest.raises(SerializationError):
        parse_payload(changed)

    rewrapped = Ciphertext(protocol.hibe_backend.encrypt(
        public.hpk, b"Bob", b"Alice", changed, rng=rng(b"payload-rewrap:" + mutation.encode())
    ))
    assert protocol.hibe_backend.decrypt(child, rewrapped.hibe_ct, rng=rng(b"payload-probe")) == changed
    fresh_ots = generate_lamport_key(rng=rng(b"payload-ots:" + mutation.encode()))
    attack = authenticate_inner(public, rewrapped.to_bytes(), fresh_ots)
    assert attack.ots_key.verify(attack.signed_body(), attack.signature)

    import ibme.protocol.baseline as baseline_module

    with patch.object(baseline_module, "parse_payload", wraps=baseline_module.parse_payload) as parse_spy:
        with patch.object(protocol.ibs_backend, "load_signature", side_effect=AssertionError("signature load unexpectedly reached")) as load:
            assert protocol.decrypt(public, receiver, b"Alice", attack, rng=rng(b"payload-dec:" + mutation.encode())) is BOTTOM
            assert parse_spy.call_count == 1
            load.assert_not_called()


@pytest.mark.parametrize("fmt,expected_outer", [("reference", 33487), ("compact", 20095)])
def test_both_formats_public_call_boundary_sizes(fmt, expected_outer):
    protocol, public, sender, receiver = system(fmt, b"boundary:" + fmt.encode())
    message = b"x" * 3924
    with patch.object(protocol.hibe_backend, "encrypt", wraps=protocol.hibe_backend.encrypt) as outer:
        with patch.object(protocol.hibe_backend.inner_backend, "encrypt", wraps=protocol.hibe_backend.inner_backend.encrypt) as inner:
            ciphertext = protocol.encrypt(public, sender, b"Bob", message, rng=rng(b"boundary-enc:" + fmt.encode()))
    assert outer.call_count == inner.call_count == 1
    assert outer.call_args.args[1:3] == (b"Bob", b"Alice")
    assert len(outer.call_args.args[3]) == expected_outer
    assert len(inner.call_args.args[1]) == len(inner.call_args.args[2]) == 86
    assert len(inner.call_args.args[3]) == 32
    assert protocol.decrypt(public, receiver, b"Alice", ciphertext, rng=rng(b"boundary-dec:" + fmt.encode())) == message


@pytest.mark.parametrize("fmt", ["reference", "compact"])
def test_rewrapped_other_public_key_reaches_ibs_context_loader(fmt):
    pa, pka, sender, receiver_a = system(fmt, b"rewrap-a:" + fmt.encode())
    pb, pkb, _, receiver_b = system(fmt, b"rewrap-b:" + fmt.encode())
    original = pa.encrypt(pka, sender, b"Bob", b"rewrap", rng=rng(b"rewrap-source:" + fmt.encode()))
    baseline_a = BaselineIBME(pa.hibe_backend, pa.ibs_backend)
    original_inner = baseline_a.load_ciphertext(original.inner_bytes)
    child_a = pa.hibe_backend.derive(receiver_a.level1_key, b"Alice", rng=rng(b"rewrap-child-a:" + fmt.encode()))
    original_payload = pa.hibe_backend.decrypt(child_a, original_inner.hibe_ct, rng=rng(b"rewrap-decap-a:" + fmt.encode()))
    assert isinstance(original_payload, bytes)
    signature_bytes, _ = parse_payload(original_payload)
    with pytest.raises(SerializationError):
        pb.ibs_backend.load_signature(pkb.ipk, signature_bytes)

    new_inner = Ciphertext(pb.hibe_backend.encrypt(
        pkb.hpk, b"Bob", b"Alice", original_payload, rng=rng(b"rewrap-encrypt-b:" + fmt.encode())
    ))
    child_b = pb.hibe_backend.derive(receiver_b.level1_key, b"Alice", rng=rng(b"rewrap-child-b:" + fmt.encode()))
    assert pb.hibe_backend.decrypt(child_b, new_inner.hibe_ct, rng=rng(b"rewrap-decap-b:" + fmt.encode())) == original_payload
    new_ots = generate_lamport_key(rng=rng(b"rewrap-ots-b:" + fmt.encode()))
    attack = authenticate_inner(pkb, new_inner.to_bytes(), new_ots)
    assert attack.ots_key.verify(attack.signed_body(), attack.signature)
    with patch.object(pb.ibs_backend, "load_signature", wraps=pb.ibs_backend.load_signature) as load:
        assert pb.decrypt(pkb, receiver_b, b"Alice", attack, rng=rng(b"rewrap-protocol-b:" + fmt.encode())) is BOTTOM
    load.assert_called_once_with(pkb.ipk, signature_bytes)
