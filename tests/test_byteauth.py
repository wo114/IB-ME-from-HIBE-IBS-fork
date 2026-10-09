"""Full-byte authentication, one-use keys, framing and recipient re-signing."""

from dataclasses import replace

import pytest

from ibme.core.errors import IBMEError, InvalidParameterError, RandomnessError, SerializationError
from ibme.core.lamport_ots import LamportPublicKey, PUBLIC_BYTES, SIGNATURE_BYTES, generate_lamport_key
from ibme.core.randomness import DeterministicRandom
from ibme.hibe.mock import MockHIBE
from ibme.ibs.mock import MockIBSBackend
from ibme.protocol.baseline import BASELINE_MOCK_PARAMS, BOTTOM, BaselineIBME
from ibme.protocol.byteauth import ByteAuthenticatedIBME, ByteAuthCiphertext, authenticate_inner


def rng(label):
    return DeterministicRandom(b"byteauth-tests:" + label)


@pytest.mark.parametrize("message", [b"", b"\x00\xff", b"a" * 256, "组会".encode()])
def test_ots_valid_signature_and_message_binding(message):
    key = generate_lamport_key(rng=rng(b"ots" + message))
    public = LamportPublicKey.from_bytes(key.public_key.to_bytes())
    signature = key.sign(message)
    assert len(public.images) == PUBLIC_BYTES and len(signature) == SIGNATURE_BYTES
    assert public.verify(message, signature)
    assert not public.verify(message + b"!", signature)
    assert not public.verify(message, signature[:-1])
    assert not public.verify(message, signature[:-1] + bytes([signature[-1] ^ 1]))
    assert not public.verify(message, signature + b"\x00")
    with pytest.raises(InvalidParameterError, match="consumed"):
        key.sign(message)
    assert key.used and "redacted" in repr(key)


@pytest.mark.parametrize("data", [b"", b"wrong", b"\x00" * 64])
def test_ots_malformed_public_key(data):
    with pytest.raises(IBMEError):
        LamportPublicKey.from_bytes(data)


def test_fresh_keys_and_invalid_entropy():
    source = rng(b"fresh")
    assert generate_lamport_key(rng=source).public_key != generate_lamport_key(rng=source).public_key
    with pytest.raises(RandomnessError):
        generate_lamport_key(rng=object())
    class Short:
        def read(self, count): return b"\x00"
    with pytest.raises(RandomnessError):
        generate_lamport_key(rng=Short())


@pytest.fixture(scope="module")
def env():
    protocol = ByteAuthenticatedIBME(MockHIBE(), MockIBSBackend(), ots_rng=rng(b"protocol-ots"))
    public, master = protocol.setup(BASELINE_MOCK_PARAMS, rng=rng(b"setup"))
    sender = protocol.skgen(master, b"Alice")
    receiver = protocol.rkgen(master, b"Bob", rng=rng(b"rk"))
    cipher = protocol.encrypt(public, sender, b"Bob", b"message", rng=rng(b"enc"))
    return protocol, public, master, sender, receiver, cipher


def test_honest_roundtrip_and_fresh_ots(env):
    protocol, public, master, sender, receiver, cipher = env
    assert protocol.decrypt(public, receiver, b"Alice", cipher.to_bytes(), rng=rng(b"dec")) == b"message"
    assert protocol.load_ciphertext(cipher.to_bytes()).to_bytes() == cipher.to_bytes()
    other = protocol.encrypt(public, sender, b"Bob", b"message", rng=rng(b"enc"))
    assert other.ots_key != cipher.ots_key


@pytest.mark.parametrize("wrong_receiver,wrong_sender", [(False, True), (True, False), (True, True)])
def test_all_mismatches(env, wrong_receiver, wrong_sender):
    protocol, public, master, sender, receiver, cipher = env
    if wrong_receiver:
        receiver = protocol.rkgen(master, b"Carol", rng=rng(b"wrong-rk"))
    assert protocol.decrypt(public, receiver, b"Carol" if wrong_sender else b"Alice", cipher) is BOTTOM


@pytest.mark.parametrize("field", ["context", "inner_bytes", "signature", "ots_key"])
def test_every_public_field_is_authenticated(env, field):
    protocol, public, master, sender, receiver, cipher = env
    if field == "ots_key":
        value = generate_lamport_key(rng=rng(b"other-key")).public_key
    else:
        data = getattr(cipher, field)
        value = data[:-1] + bytes([data[-1] ^ 1])
    changed = replace(cipher, **{field: value})
    assert protocol.decrypt(public, receiver, b"Alice", changed) is BOTTOM


def test_recipient_cannot_replace_ots_key_and_resign_existing_inner_ciphertext(env):
    protocol, public, master, sender, receiver, cipher = env
    # A valid new OTS is insufficient: the IBS-authenticated plaintext binds
    # the original key commitment. The recipient knows that plaintext.
    new_key = generate_lamport_key(rng=rng(b"recipient-ots"))
    changed = authenticate_inner(public, cipher.inner_bytes, new_key)
    assert changed.ots_key.verify(changed.signed_body(), changed.signature)
    assert protocol.decrypt(public, receiver, b"Alice", changed) is BOTTOM


@pytest.mark.parametrize("mutation", ["truncate", "append", "duplicate", "version", "oversized-length"])
def test_strict_framing(env, mutation):
    protocol, public, master, sender, receiver, cipher = env
    raw = cipher.to_bytes()
    if mutation == "truncate": raw = raw[:-1]
    elif mutation == "append": raw += b"\x00"
    elif mutation == "duplicate": raw += raw
    elif mutation == "version": raw = b"?" + raw[1:]
    else:
        from ibme.protocol.byteauth import MAGIC_BYTEAUTH
        pos = len(MAGIC_BYTEAUTH)
        raw = raw[:pos] + b"\xff" * 4 + raw[pos + 4:]
    with pytest.raises(IBMEError):
        protocol.load_ciphertext(raw)
    assert protocol.decrypt(public, receiver, b"Alice", raw) is BOTTOM


def test_no_implicit_legacy_downgrade(env):
    protocol, public, master, sender, receiver, cipher = env
    baseline = BaselineIBME(protocol.hibe_backend, protocol.ibs_backend)
    old = baseline.encrypt(public, sender, b"Bob", b"legacy", rng=rng(b"old"))
    assert baseline.decrypt(public, receiver, b"Alice", old) == b"legacy"
    with pytest.raises(SerializationError):
        protocol.load_ciphertext(old.to_bytes())
    assert protocol.decrypt(public, receiver, b"Alice", old.to_bytes()) is BOTTOM


def test_default_cli_protocol_and_explicit_legacy_flag(tmp_path):
    from ibme.cli import _make_runtime, main
    assert isinstance(_make_runtime(True)[0], ByteAuthenticatedIBME)
    assert type(_make_runtime(True, legacy_baseline=True)[0]) is BaselineIBME
    state = tmp_path / "state"
    assert main(["setup", "--state", str(state), "--mock"]) == 0
    assert main(["issue-sender-key", "Alice", "--state", str(state), "--mock"]) == 0
    assert main(["issue-receiver-key", "Bob", "--state", str(state), "--mock"]) == 0
    message, cipher, out = (tmp_path / name for name in ("message", "cipher", "out"))
    message.write_bytes(b"legacy")
    args = ["--state", str(state), "--mock", "--sender", "Alice", "--receiver", "Bob"]
    assert main(["encrypt", *args, "--in", str(message), "--out", str(cipher), "--legacy-baseline"]) == 0
    assert main(["decrypt", *args, "--in", str(cipher), "--out", str(out)]) == 1
    assert not out.exists()
    assert main(["decrypt", *args, "--in", str(cipher), "--out", str(out), "--legacy-baseline"]) == 0
    assert out.read_bytes() == b"legacy"
