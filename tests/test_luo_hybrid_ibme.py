"""Real lattice HIBE + module IBS + BYTEAUTH, public forgery and CLI persistence."""

from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from ibme.core.encoding import encode_bytes, encode_message
from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.core.lamport_ots import generate_lamport_key
from ibme.core.randomness import DeterministicRandom
from ibme.ibs.luo_module import LuoModuleSignature, challenge
from ibme.protocol.baseline import (BaselineIBME, BOTTOM, Ciphertext, PublicKey, MasterSecret,
                                    SenderKey, ReceiverKey, encode_signature, parse_payload)
from ibme.protocol.byteauth import authenticate_inner, encode_bound_message, parse_bound_message
from ibme.protocol.luo_hybrid import (make_research_runtime, RESEARCH_HIBE_PARAMS, RESEARCH_IBS_PARAMS,
                                     MAX_APPLICATION_BYTES, PROFILE_NAME)


def rng(label): return DeterministicRandom(b"luo-hybrid-tests:" + label)


@pytest.fixture(scope="module")
def env():
    p, readers = make_research_runtime(ibs_rng=rng(b"ibs"), ots_rng=rng(b"ots"))
    public, master = p.setup(RESEARCH_HIBE_PARAMS, ibs_params=RESEARCH_IBS_PARAMS, rng=rng(b"setup"))
    sender = p.skgen(master, b"Alice")
    receiver = p.rkgen(master, b"Bob", rng=rng(b"receiver"))
    cipher = p.encrypt(public, sender, b"Bob", b"honest message", rng=rng(b"encrypt"))
    return p, readers, public, master, sender, receiver, cipher


def test_full_real_components_and_restore(env):
    p, readers, public, master, sender, receiver, cipher = env
    loaded_public = PublicKey.from_bytes(public.to_bytes(), readers["hpk"], readers["ipk"])
    loaded_master = MasterSecret.from_bytes(master.to_bytes(), readers["hmsk"], readers["imsk"])
    loaded_sender = SenderKey.from_bytes(sender.to_bytes(), readers["sk"])
    loaded_receiver = ReceiverKey.from_bytes(receiver.to_bytes(), readers["sk1"])
    assert loaded_master.to_bytes() == master.to_bytes()
    assert loaded_master.imsk.cached_identities == (b"Alice",)
    assert p.skgen(loaded_master, b"Alice").to_bytes() == loaded_sender.to_bytes()
    assert p.decrypt(loaded_public, loaded_receiver, b"Alice", cipher.to_bytes(), rng=rng(b"decode")) == b"honest message"
    assert p.security_claim == "none" and not p.backend_admitted


@pytest.mark.parametrize("message", [b"", b"\x00\xff", b"x" * MAX_APPLICATION_BYTES], ids=["empty", "binary", "max-application"])
def test_real_protocol_message_cases(env, message):
    p, readers, public, master, sender, receiver, cipher = env
    fresh = p.encrypt(public, sender, b"Bob", message, rng=rng(b"message"))
    assert p.decrypt(public, receiver, b"Alice", fresh, rng=rng(b"message-dec")) == message


@pytest.mark.parametrize("wrong_receiver,wrong_sender", [(False, True), (True, False), (True, True)])
def test_real_protocol_three_mismatches(env, wrong_receiver, wrong_sender):
    p, readers, public, master, sender, receiver, cipher = env
    if wrong_receiver: receiver = p.rkgen(master, b"Carol", rng=rng(b"wrong-receiver"))
    assert p.decrypt(public, receiver, b"Carol" if wrong_sender else b"Alice", cipher, rng=rng(b"wrong-dec")) is BOTTOM


@pytest.mark.parametrize("field", ["context", "inner_bytes", "signature", "ots_key"])
def test_real_all_outer_fields_reject(env, field):
    p, readers, public, master, sender, receiver, cipher = env
    if field == "ots_key": value = generate_lamport_key(rng=rng(b"different-ots")).public_key
    else:
        raw = getattr(cipher, field)
        value = raw[:-1] + bytes([raw[-1] ^ 1])
    assert p.decrypt(public, receiver, b"Alice", replace(cipher, **{field: value}), rng=rng(b"outer-dec")) is BOTTOM


def _recipient_payload(p, public, receiver, cipher):
    baseline = BaselineIBME(p.hibe_backend, p.ibs_backend)
    inner = baseline.load_ciphertext(cipher.inner_bytes)
    child = p.hibe_backend.derive(receiver.level1_key, b"Alice", rng=rng(b"recipient-child"))
    payload = p.hibe_backend.decrypt(child, inner.hibe_ct, rng=rng(b"recipient-dec"))
    assert isinstance(payload, bytes)
    return baseline, payload


def test_recipient_reencrypts_same_plaintext_and_resigns_but_binding_rejects(env):
    p, readers, public, master, sender, receiver, cipher = env
    baseline, payload = _recipient_payload(p, public, receiver, cipher)
    # The attacker receives only public data and Bob's receiving key. They can
    # publicly re-encrypt the old signed payload and create their own valid OTS.
    changed_inner = Ciphertext(p.hibe_backend.encrypt(public.hpk, b"Bob", b"Alice", payload,
                                                     rng=rng(b"recipient-reencrypt")))
    sig_raw, envelope = parse_payload(payload)
    assert baseline.decrypt(public, receiver, b"Alice", changed_inner, rng=rng(b"recipient-control")) == envelope
    changed = authenticate_inner(public, changed_inner.to_bytes(), generate_lamport_key(rng=rng(b"recipient-new-ots")))
    assert changed.ots_key.verify(changed.signed_body(), changed.signature)
    assert p.decrypt(public, receiver, b"Alice", changed, rng=rng(b"recipient-reject")) is BOTTOM


def test_recipient_rebinds_new_ots_or_changes_message_with_valid_signature_type(env):
    p, readers, public, master, sender, receiver, cipher = env
    _, payload = _recipient_payload(p, public, receiver, cipher)
    sig_raw, old_envelope = parse_payload(payload)
    old_sig = p.ibs_backend.load_signature(public.ipk, sig_raw)
    assert isinstance(old_sig, LuoModuleSignature)
    key = generate_lamport_key(rng=rng(b"recipient-change-content"))
    _, old_message = parse_bound_message(old_envelope)
    envelope = encode_bound_message(key.public_key.commitment(), old_message + b" forged")
    assert not p.ibs_backend.verify(public.ipk, b"Alice", encode_message(b"Bob", envelope), old_sig)
    changed_inner = Ciphertext(p.hibe_backend.encrypt(public.hpk, b"Bob", b"Alice",
                         encode_signature(old_sig) + encode_bytes(envelope), rng=rng(b"recipient-new-payload")))
    changed = authenticate_inner(public, changed_inner.to_bytes(), key)
    assert changed.ots_key.verify(changed.signed_body(), changed.signature)
    assert p.decrypt(public, receiver, b"Alice", changed, rng=rng(b"recipient-message-dec")) is BOTTOM


def test_public_new_format_forgery_and_unissued_sender_are_rejected(env):
    p, readers, public, master, sender, receiver, cipher = env
    attacker = generate_lamport_key(rng=rng(b"public-attacker-ots"))
    envelope = encode_bound_message(attacker.public_key.commitment(), b"public spoof")
    signed = encode_message(b"Bob", envelope)
    params = public.ipk.params
    guesses = []
    for index in range(16):
        c = challenge(params, b"IBME:HYBRID:ATTACK-GUESS:v1", index.to_bytes(2, "big"))
        sig = LuoModuleSignature(params, public.ipk.context, ((0,) * params.degree,) * params.l,
                                c, ((0,) * params.degree,) * params.k, ((0,) * params.degree,) * params.k)
        loaded = p.ibs_backend.load_signature(public.ipk, sig.to_bytes())
        assert loaded.to_bytes() == sig.to_bytes()  # Genuine new wire, no type gate.
        assert not p.ibs_backend.verify(public.ipk, b"Unissued", signed, loaded)
        guesses.append(loaded)
    payload = encode_signature(guesses[0]) + encode_bytes(envelope)
    inner = Ciphertext(p.hibe_backend.encrypt(public.hpk, b"Bob", b"Unissued", payload, rng=rng(b"public-spoof")))
    forged = authenticate_inner(public, inner.to_bytes(), attacker)
    assert forged.ots_key.verify(forged.signed_body(), forged.signature)
    assert p.decrypt(public, receiver, b"Unissued", forged, rng=rng(b"public-spoof-dec")) is BOTTOM
    assert b"Unissued" not in master.imsk.cached_identities


def test_signed_payload_signature_tamper_reaches_verify_and_rejects(env):
    p, readers, public, master, sender, receiver, cipher = env
    _, payload = _recipient_payload(p, public, receiver, cipher)
    raw, envelope = parse_payload(payload)
    signature = p.ibs_backend.load_signature(public.ipk, raw)
    c = tuple(-x for x in signature.c)  # Still exactly kappa nonzero +/-1.
    changed = replace(signature, c=c)
    assert p.ibs_backend.load_signature(public.ipk, changed.to_bytes()).to_bytes() == changed.to_bytes()
    assert not p.ibs_backend.verify(public.ipk, b"Alice", encode_message(b"Bob", envelope), changed)


@pytest.mark.parametrize("mutation", ["truncate", "append", "duplicate", "version"])
def test_real_outer_encoding_rejects(env, mutation):
    p, readers, public, master, sender, receiver, cipher = env
    raw = cipher.to_bytes()
    modified = {"truncate": raw[:-1], "append": raw + b"\0", "duplicate": raw + raw,
                "version": b"?" + raw[1:]}[mutation]
    with pytest.raises(SerializationError): p.load_ciphertext(modified)
    assert p.decrypt(public, receiver, b"Alice", modified) is BOTTOM


def test_application_limit_checks_before_randomness(env):
    _, readers, public, master, sender, receiver, cipher = env
    class NoEntropy:
        def read(self, count): raise AssertionError("must not reach randomness")
    p, _ = make_research_runtime(ibs_rng=NoEntropy(), ots_rng=NoEntropy())
    assert MAX_APPLICATION_BYTES == 3924
    with pytest.raises(InvalidParameterError):
        p.encrypt(public, sender, b"Bob", b"x" * 3925, rng=NoEntropy())


def test_worst_receiver_length_reaches_exact_ibs_input_boundary(env):
    p, readers, public, master, sender, receiver, cipher = env
    identity, message = b"R" * 64, b"x" * MAX_APPLICATION_BYTES
    dk = p.rkgen(master, identity, rng=rng(b"max-receiver"))
    assert len(encode_message(identity, encode_bound_message(b"x" * 64, message))) == 4096
    ct = p.encrypt(public, sender, identity, message, rng=rng(b"max-receiver-enc"))
    assert p.decrypt(public, dk, b"Alice", ct, rng=rng(b"max-receiver-dec")) == message


def test_profile_decoders_reject_changed_parameter_or_resource_profiles(env):
    from ibme.ibs.luo_module import LuoModulePublicKey
    from ibme.protocol.hybrid_hibe import HybridPublicKey
    p, readers, public, master, sender, receiver, cipher = env
    changed_module = LuoModulePublicKey(replace(public.ipk.params, max_sign_attempts=512), public.ipk.A, public.ipk.t)
    with pytest.raises(SerializationError): readers["ipk"].from_bytes(changed_module.to_bytes())
    changed_hibe = HybridPublicKey(replace(public.hpk.limits, max_payload_bytes=60000), public.hpk.inner)
    with pytest.raises(SerializationError): readers["hpk"].from_bytes(changed_hibe.to_bytes())


def _fresh_cli(arguments, cwd):
    source = Path(__file__).resolve().parents[1] / "src"
    return subprocess.run([sys.executable, "-B", "-m", "ibme.cli", *arguments], cwd=cwd,
                           env={**os.environ, "PYTHONPATH": str(source), "PYTHONDONTWRITEBYTECODE": "1"},
                           capture_output=True, text=True, timeout=60)


@pytest.fixture(scope="module")
def cli_env(tmp_path_factory):
    root = tmp_path_factory.mktemp("luo-hybrid-cli")
    state = root / "state"
    base = ["--state", str(state)]
    for arguments in (["setup", "--params", PROFILE_NAME, *base], ["issue-sender-key", "Alice", *base],
                      ["issue-receiver-key", "Bob", *base]):
        result = _fresh_cli(arguments, root)
        assert result.returncode == 0, result.stderr
    return root, state, base


def test_cli_fresh_process_roundtrip_and_fixed_issued_key(cli_env):
    from ibme.cli import _sender_key_path
    root, state, base = cli_env
    sender_path = _sender_key_path(state, b"Alice")
    before = sender_path.read_bytes()  # Test private state stays in pytest temp.
    result = _fresh_cli(["issue-sender-key", "Alice", *base], root)
    assert result.returncode == 0, result.stderr
    assert sender_path.read_bytes() == before
    p, readers = make_research_runtime()
    master = MasterSecret.from_bytes((state / "msk.bin").read_bytes(), readers["hmsk"], readers["imsk"])
    assert master.imsk.cached_identities == (b"Alice",)
    message, cipher, output = (root / name for name in ("message.bin", "cipher.bin", "result.bin"))
    message.write_bytes(b"x" * 3924)
    args = [*base, "--sender", "Alice", "--receiver", "Bob"]
    result = _fresh_cli(["encrypt", *args, "--in", str(message), "--out", str(cipher)], root)
    assert result.returncode == 0, result.stderr
    result = _fresh_cli(["decrypt", *args, "--in", str(cipher), "--out", str(output)], root)
    assert result.returncode == 0, result.stderr
    assert output.read_bytes() == message.read_bytes()
    assert _fresh_cli(["decrypt", *base, "--sender", "Other", "--receiver", "Bob", "--in", str(cipher)], root).returncode == 1


def test_cli_disallows_flags_overwrite_and_oversized_messages(cli_env):
    root, state, base = cli_env
    before = (state / "msk.bin").read_bytes()
    assert _fresh_cli(["setup", "--params", PROFILE_NAME, *base], root).returncode == 2
    assert (state / "msk.bin").read_bytes() == before
    message, output = root / "oversized.bin", root / "must-not-exist.bin"
    message.write_bytes(b"x" * 3925)
    args = [*base, "--sender", "Alice", "--receiver", "Bob", "--in", str(message), "--out", str(output)]
    assert _fresh_cli(["encrypt", *args], root).returncode == 2
    assert _fresh_cli(["encrypt", *args, "--legacy-baseline"], root).returncode == 2
    assert _fresh_cli(["encrypt", *args, "--mock"], root).returncode == 2
    assert not output.exists()


def test_research_metadata_duplicate_or_profile_tamper_rejected(cli_env, tmp_path):
    from ibme.cli import _load_state_meta
    root, state, base = cli_env
    original = (state / "state.json").read_text(encoding="utf-8")
    meta = json.loads(original)
    assert meta["max_application_bytes"] == 3924 and meta["security_claim"] == "none"
    assert meta["backend_admitted"] is False
    for key, value in (("security_claim", "128-bit"), ("identity_bytes", 32), ("params_preset", "education"),
                       ("backend", "abb10+sis"), ("version", True), ("persistent_identity_cache", False)):
        (tmp_path / "state.json").write_text(json.dumps({**meta, key: value}), encoding="utf-8")
        with pytest.raises(ValueError): _load_state_meta(tmp_path)
    (tmp_path / "state.json").write_text(original[:-2] + ',"version":1}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"): _load_state_meta(tmp_path)
