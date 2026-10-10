"""Actual compact research combination, adversarial payloads and CLI persistence."""

from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

pytest.importorskip("cryptography")

from ibme.cli import _load_state_meta, _make_runtime, _sender_key_path
from ibme.core.encoding import encode_bytes, encode_message
from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.core.lamport_ots import generate_lamport_key
from ibme.core.randomness import DeterministicRandom
from ibme.ibs.luo_module import LuoModuleSignature, challenge
from ibme.ibs.luo_module_codec import LuoModuleCompactSignature
from ibme.protocol.baseline import BaselineIBME, BOTTOM, Ciphertext, MasterSecret, encode_signature, parse_payload
from ibme.protocol.byteauth import authenticate_inner, encode_bound_message
from ibme.protocol.luo_hybrid import (
    make_research_runtime, RESEARCH_HIBE_PARAMS, RESEARCH_IBS_PARAMS, MAX_APPLICATION_BYTES, PROFILE_NAME,
)


def rng(label): return DeterministicRandom(b"compact-ibme-contract:" + label)


@pytest.fixture(scope="module")
def env():
    p, readers = make_research_runtime(signature_format="compact", ibs_rng=rng(b"ibs"), ots_rng=rng(b"ots"))
    public, master = p.setup(RESEARCH_HIBE_PARAMS, ibs_params=RESEARCH_IBS_PARAMS, rng=rng(b"setup"))
    sender = p.skgen(master, b"Alice")
    receiver = p.rkgen(master, b"Bob", rng=rng(b"rk"))
    cipher = p.encrypt(public, sender, b"Bob", b"", rng=rng(b"encrypt"))
    return p, readers, public, master, sender, receiver, cipher


def payload(env):
    p, _, public, _, _, receiver, cipher = env
    baseline = BaselineIBME(p.hibe_backend, p.ibs_backend)
    inner = baseline.load_ciphertext(cipher.inner_bytes)
    child = p.hibe_backend.derive(receiver.level1_key, b"Alice", rng=rng(b"child"))
    raw = p.hibe_backend.decrypt(child, inner.hibe_ct, rng=rng(b"payload"))
    assert isinstance(raw, bytes)
    return baseline, parse_payload(raw)


@pytest.mark.parametrize("message", [b"", b"\x00\xff", b"x" * MAX_APPLICATION_BYTES], ids=["empty", "binary", "max-application"])
def test_compact_real_roundtrip(env, message):
    p, _, public, _, sender, receiver, _ = env
    cipher = p.encrypt(public, sender, b"Bob", message, rng=rng(b"messages"))
    assert p.decrypt(public, receiver, b"Alice", cipher.to_bytes(), rng=rng(b"message-dec")) == message
    assert p.security_claim == "none" and not p.backend_admitted


@pytest.mark.parametrize("wrong_receiver,wrong_sender", [(False, True), (True, False), (True, True)])
def test_compact_three_mismatches(env, wrong_receiver, wrong_sender):
    p, _, public, master, _, receiver, cipher = env
    if wrong_receiver: receiver = p.rkgen(master, b"Carol", rng=rng(b"other-rk"))
    assert p.decrypt(public, receiver, b"Other" if wrong_sender else b"Alice", cipher, rng=rng(b"mismatch")) is BOTTOM


def test_real_signature_transport_size_and_wrong_profile_rejection(env):
    p, _, public, _, _, receiver, cipher = env
    _, (raw, envelope) = payload(env)
    compact = p.ibs_backend.load_signature(public.ipk, raw)
    assert isinstance(compact, LuoModuleCompactSignature)
    assert len(raw) == 16063 and len(compact.signature.to_bytes()) == 29455
    assert len(cipher.to_bytes()) == 2566864
    assert p.ibs_backend.verify(public.ipk, b"Alice", encode_message(b"Bob", envelope), compact)
    reference, _ = make_research_runtime()
    assert reference.decrypt(public, receiver, b"Alice", cipher, rng=rng(b"no-fallback")) is BOTTOM
    with pytest.raises(SerializationError): p.ibs_backend.load_signature(public.ipk, compact.signature.to_bytes())


def test_compact_recipient_changes_envelope_and_resigns_outer_ots(env):
    p, _, public, _, _, receiver, _ = env
    _, (raw, old_envelope) = payload(env)
    signature = p.ibs_backend.load_signature(public.ipk, raw)
    attacker = generate_lamport_key(rng=rng(b"recipient-attacker-ots"))
    envelope = encode_bound_message(attacker.public_key.commitment(), b"recipient forged content")
    assert not p.ibs_backend.verify(public.ipk, b"Alice", encode_message(b"Bob", envelope), signature)
    inner = Ciphertext(p.hibe_backend.encrypt(public.hpk, b"Bob", b"Alice",
                    encode_signature(signature) + encode_bytes(envelope), rng=rng(b"recipient-reencrypt")))
    forged = authenticate_inner(public, inner.to_bytes(), attacker)
    assert forged.ots_key.verify(forged.signed_body(), forged.signature)
    assert p.decrypt(public, receiver, b"Alice", forged, rng=rng(b"recipient-forgery-dec")) is BOTTOM


def test_canonical_compact_public_forgery_reaches_equation_and_full_protocol(env):
    p, _, public, master, _, receiver, _ = env
    attacker = generate_lamport_key(rng=rng(b"public-forgery-ots"))
    envelope = encode_bound_message(attacker.public_key.commitment(), b"public spoof")
    params = public.ipk.params
    c = challenge(params, b"IBME:COMPACT:PUBLIC-GUESS:v1", b"fixed public guess")
    sig = LuoModuleCompactSignature(LuoModuleSignature(params, public.ipk.context,
              ((0,) * params.degree,) * params.l, c, ((0,) * params.degree,) * params.k,
              ((0,) * params.degree,) * params.k))
    loaded = p.ibs_backend.load_signature(public.ipk, sig.to_bytes())
    assert isinstance(loaded, LuoModuleCompactSignature) and loaded.to_bytes() == sig.to_bytes()
    assert not p.ibs_backend.verify(public.ipk, b"Unissued", encode_message(b"Bob", envelope), loaded)
    inner = Ciphertext(p.hibe_backend.encrypt(public.hpk, b"Bob", b"Unissued",
                    encode_signature(loaded) + encode_bytes(envelope), rng=rng(b"public-forgery-encrypt")))
    forged = authenticate_inner(public, inner.to_bytes(), attacker)
    assert forged.ots_key.verify(forged.signed_body(), forged.signature)
    assert p.decrypt(public, receiver, b"Unissued", forged, rng=rng(b"public-forgery-dec")) is BOTTOM
    assert b"Unissued" not in master.imsk.cached_identities


def test_compact_valid_type_tamper_rejected(env):
    p, _, public, _, _, _, _ = env
    _, (raw, envelope) = payload(env)
    sig = p.ibs_backend.load_signature(public.ipk, raw)
    changed = LuoModuleCompactSignature(replace(sig.signature, c=tuple(-x for x in sig.signature.c)))
    loaded = p.ibs_backend.load_signature(public.ipk, changed.to_bytes())
    assert not p.ibs_backend.verify(public.ipk, b"Alice", encode_message(b"Bob", envelope), loaded)


def test_runtime_rejects_unknown_or_inapplicable_formats_before_entropy():
    for value in ("unknown", None, True):
        with pytest.raises(InvalidParameterError): make_research_runtime(signature_format=value)
    for mock, preset in ((False, "education"), (True, "education"), (True, PROFILE_NAME)):
        with pytest.raises(ValueError): _make_runtime(mock, preset=preset, signature_format="compact")


def cli(args, root):
    source = Path(__file__).resolve().parents[1] / "src"
    return subprocess.run([sys.executable, "-B", "-m", "ibme.cli", *args], cwd=root,
                           env={**os.environ, "PYTHONPATH": str(source), "PYTHONDONTWRITEBYTECODE": "1"},
                           capture_output=True, text=True, timeout=60)


@pytest.fixture(scope="module")
def cli_env(tmp_path_factory):
    root = tmp_path_factory.mktemp("compact-cli")
    state = root / "state"
    base = ["--state", str(state)]
    for args in (["setup", "--params", PROFILE_NAME, "--signature-format", "compact", *base],
                 ["issue-sender-key", "Alice", *base], ["issue-receiver-key", "Bob", *base]):
        result = cli(args, root)
        assert result.returncode == 0, result.stderr
    return root, state, base


def test_compact_cli_fresh_process_roundtrip_and_cache(cli_env):
    root, state, base = cli_env
    assert _load_state_meta(state)["signature_format"] == "compact"
    sender_path = _sender_key_path(state, b"Alice")
    before = sender_path.read_bytes()
    result = cli(["issue-sender-key", "Alice", *base], root)
    assert result.returncode == 0, result.stderr
    assert sender_path.read_bytes() == before
    _, readers = make_research_runtime(signature_format="compact")
    master = MasterSecret.from_bytes((state / "msk.bin").read_bytes(), readers["hmsk"], readers["imsk"])
    assert master.imsk.cached_identities == (b"Alice",)
    message, cipher, output = (root / name for name in ("message.bin", "cipher.bin", "output.bin"))
    message.write_bytes(b"x" * 3924)
    common = [*base, "--sender", "Alice", "--receiver", "Bob"]
    result = cli(["encrypt", *common, "--in", str(message), "--out", str(cipher)], root)
    assert result.returncode == 0, result.stderr
    assert cipher.stat().st_size == 2570788
    result = cli(["decrypt", *common, "--in", str(cipher), "--out", str(output)], root)
    assert result.returncode == 0, result.stderr
    assert output.read_bytes() == message.read_bytes()


@pytest.mark.parametrize("value", ["unknown", "COMPACT", None, True, 1, [], {}])
def test_state_rejects_invalid_format(cli_env, tmp_path, value):
    _, state, _ = cli_env
    meta = _load_state_meta(state)
    (tmp_path / "state.json").write_text(json.dumps({**meta, "signature_format": value}), encoding="utf-8")
    with pytest.raises(ValueError, match="signature_format"): _load_state_meta(tmp_path)


def test_old_v1_state_without_selector_uses_only_reference(cli_env, tmp_path):
    _, state, _ = cli_env
    meta = _load_state_meta(state)
    meta.pop("signature_format")
    (tmp_path / "state.json").write_text(json.dumps(meta), encoding="utf-8")
    loaded = _load_state_meta(tmp_path)
    proto, _ = _make_runtime(False, preset=loaded["params_preset"], signature_format=loaded.get("signature_format", "reference"))
    assert type(proto.ibs_backend).__name__ == "LuoModuleIBSBackend"


def test_cli_denies_compact_education_before_writing_state(tmp_path):
    state = tmp_path / "invalid"
    result = cli(["setup", "--params", "education", "--signature-format", "compact", "--state", str(state)], tmp_path)
    assert result.returncode == 2 and not state.exists()
