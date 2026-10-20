"""Application session plumbing, using TEST-ONLY mock primitives."""
from dataclasses import replace
import pickle

import pytest

from ibme.core.errors import InvalidParameterError
from ibme.core.encoding import encode_bytes
from ibme.core.lamport_ots import generate_lamport_key
from ibme.core.randomness import DeterministicRandom
from ibme.hibe.mock import MockHIBE
from ibme.ibs.mock import MockIBSBackend
from ibme.protocol.baseline import (
    BASELINE_MOCK_PARAMS, BOTTOM, BaselineIBME, Ciphertext, encode_message, encode_signature,
)
from ibme.protocol.byteauth import ByteAuthenticatedIBME, authenticate_inner, encode_bound_message
from ibme.protocol.prepared import prepare_receiver


def rng(label):
    return DeterministicRandom(b"TEST-ONLY-PREPARED-RECEIVER:"+label)


@pytest.fixture
def env():
    hibe, ibs = MockHIBE(), MockIBSBackend()
    protocol = ByteAuthenticatedIBME(hibe, ibs, ots_rng=rng(b"ots"))
    public, master = protocol.setup(BASELINE_MOCK_PARAMS, rng=rng(b"root"))
    sender = protocol.skgen(master, b"Alice")
    receiver = protocol.rkgen(master, b"Bob", rng=rng(b"receiver"))
    ciphertext = protocol.encrypt(public, sender, b"Bob", b"message", rng=rng(b"enc"))
    return protocol, public, master, sender, receiver, ciphertext


def test_prepare_once_then_full_decrypt_and_close(env, monkeypatch):
    protocol, public, master, sender, receiver, ct = env
    calls = []
    original = protocol.hibe_backend.derive

    def derive(*args, **kw):
        calls.append(args)
        return original(*args, **kw)

    monkeypatch.setattr(protocol.hibe_backend, "derive", derive)
    session = prepare_receiver(protocol, public, receiver, b"Alice", rng=rng(b"prepare"))
    assert len(calls) == 1
    for _ in range(3):
        assert session.decrypt(ct.to_bytes()) == b"message"
    assert len(calls) == 1
    info = session.info()
    assert info["decryptions"] == 3 and info["leaf_key_bytes"] > 0
    assert "redacted" in repr(session)
    with pytest.raises(TypeError):
        pickle.dumps(session)
    session.close()
    assert session.info()["closed"] is True
    with pytest.raises(RuntimeError, match="closed"):
        session.decrypt(ct)
    # Original protocol remains stateless and keeps deriving normally.
    assert protocol.decrypt(public, receiver, b"Alice", ct) == b"message"
    assert len(calls) == 2


def test_same_receiver_session_rejects_framing_and_wrong_addresses(env):
    protocol, public, master, sender, receiver, ct = env
    with prepare_receiver(protocol, public, receiver, b"Alice") as session:
        raw = ct.to_bytes()
        for bad in (raw[:-1], raw+b"!", raw+raw, b"?"+raw[1:]):
            assert session.decrypt(bad) is BOTTOM
        changed = replace(ct, signature=bytes([ct.signature[0]^1])+ct.signature[1:])
        assert session.decrypt(changed) is BOTTOM
        for wrong_receiver, wrong_sender in ((True, False), (False, True), (True, True)):
            other_sender = protocol.skgen(master, b"Carol") if wrong_sender else sender
            other_ct = protocol.encrypt(public, other_sender, b"Eve" if wrong_receiver else b"Bob",
                                        b"message", rng=rng(bytes([wrong_receiver, wrong_sender])))
            assert session.decrypt(other_ct) is BOTTOM
    assert session.info()["closed"]


def test_valid_outer_invalid_inner_reaches_ibs_verification(env, monkeypatch):
    protocol, public, master, sender, receiver, _ = env
    ots = generate_lamport_key(rng=rng(b"bad-inner-ots"))
    good = encode_bound_message(ots.public_key.commitment(), b"original")
    bad = encode_bound_message(ots.public_key.commitment(), b"modified")
    signature = protocol.ibs_backend.sign(sender.signing_key, encode_message(b"Bob", good))
    payload = encode_signature(signature)+encode_bytes(bad)
    inner = Ciphertext(protocol.hibe_backend.encrypt(public.hpk, b"Bob", b"Alice", payload,
                                                     rng=rng(b"bad-inner-hibe")))
    ct = authenticate_inner(public, inner.to_bytes(), ots)
    assert ct.ots_key.verify(ct.signed_body(), ct.signature)
    called = []
    verify = protocol.ibs_backend.verify

    def observed(*args):
        result = verify(*args)
        called.append(result)
        return result

    monkeypatch.setattr(protocol.ibs_backend, "verify", observed)
    with prepare_receiver(protocol, public, receiver, b"Alice") as session:
        assert session.decrypt(ct.to_bytes()) is BOTTOM
    assert called == [False]


def test_cross_root_and_wrong_leaf_fail_without_repair(env, monkeypatch):
    protocol, public, master, sender, receiver, _ = env
    other, _ = protocol.setup(BASELINE_MOCK_PARAMS, rng=rng(b"other-root"))
    with pytest.raises(InvalidParameterError, match="binding"):
        prepare_receiver(protocol, other, receiver, b"Alice")
    derive = protocol.hibe_backend.derive
    wrong_leaf = derive(receiver.level1_key, b"Carol")
    monkeypatch.setattr(protocol.hibe_backend, "derive", lambda *a, **k: wrong_leaf)
    with pytest.raises(InvalidParameterError, match="path"):
        prepare_receiver(protocol, public, receiver, b"Alice")


def test_baseline_supported_and_unknown_protocol_subclasses_rejected(env):
    protocol, public, master, sender, receiver, _ = env
    baseline = BaselineIBME(protocol.hibe_backend, protocol.ibs_backend)
    ct = baseline.encrypt(public, sender, b"Bob", b"baseline", rng=rng(b"base"))
    with prepare_receiver(baseline, public, receiver, b"Alice") as session:
        assert session.decrypt(ct.to_bytes()) == b"baseline"

    class ExtraChecks(ByteAuthenticatedIBME):
        pass

    with pytest.raises(TypeError, match="protocol"):
        prepare_receiver(ExtraChecks(protocol.hibe_backend, protocol.ibs_backend), public, receiver, b"Alice")


def test_hybrid_preparation_checks_advertised_root_and_real_key_binding():
    from test_hybrid_hibe import mock_backend
    from ibme.protocol.hybrid_hibe import HybridHIBEParams, HybridLimits, encoded_identity_bytes

    hibe = mock_backend()
    params = HybridHIBEParams(replace(BASELINE_MOCK_PARAMS, max_message_bytes=32,
                                     identity_bytes=encoded_identity_bytes(64)),
                              HybridLimits(backend_id=b"mock-test"))
    protocol = ByteAuthenticatedIBME(hibe, MockIBSBackend(), ots_rng=rng(b"hybrid-ots"))
    public, master = protocol.setup(params, ibs_params=BASELINE_MOCK_PARAMS, rng=rng(b"hybrid-root"))
    sender = protocol.skgen(master, b"Alice")
    receiver = protocol.rkgen(master, b"Bob", rng=rng(b"hybrid-receiver"))
    ct = protocol.encrypt(public, sender, b"Bob", b"hybrid", rng=rng(b"hybrid-enc"))
    with prepare_receiver(protocol, public, receiver, b"Alice") as session:
        assert session.decrypt(ct.to_bytes()) == b"hybrid"
    other, _ = protocol.setup(params, ibs_params=BASELINE_MOCK_PARAMS, rng=rng(b"hybrid-other"))
    with pytest.raises(InvalidParameterError, match="binding"):
        prepare_receiver(protocol, other, receiver, b"Alice")


def test_assembled_protocol_retains_suite_receiver_guards():
    from ibme.assembly import make_suite, build_runtime
    runtime = build_runtime(make_suite(hibe="mock", ibs="mock", allow_mock=True),
                            ibs_rng=rng(b"suite-ibs"), ots_rng=rng(b"suite-ots"))
    public, master = runtime.proto.setup(runtime.hibe_params, ibs_params=runtime.ibs_params, rng=rng(b"suite"))
    sender = runtime.proto.skgen(master, b"Alice")
    receiver = runtime.proto.rkgen(master, b"Bob", rng=rng(b"suite-rk"))
    ct = runtime.proto.encrypt(public, sender, b"Bob", b"suite", rng=rng(b"suite-enc"))
    with prepare_receiver(runtime.proto, public, receiver, b"Alice") as session:
        assert session.decrypt(ct.to_bytes()) == b"suite"
