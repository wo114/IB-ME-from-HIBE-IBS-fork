"""Versioned byte authentication around the unchanged Wang baseline.

The IBS signs an envelope binding the ephemeral OTS key. A fresh OTS then
signs the complete ciphertext frame. Recipient-side re-signing with a new OTS
key fails the encrypted binding unless the IBS or commitment is broken.
This does not repair an insecure IBS or assert CCA/QROM security.
"""

from dataclasses import dataclass, replace
from hmac import compare_digest

from ibme.core.encoding import decode_bytes, encode_bytes
from ibme.core.errors import IBMEError, RandomnessError, SerializationError
from ibme.core.hashing import shake256
from ibme.core.lamport_ots import LamportPublicKey, SIGNATURE_BYTES, generate_lamport_key
from ibme.core.randomness import SecureRandom
from ibme.core.types import validate_bytes, validate_identity
from ibme.protocol.baseline import BASELINE_DEBUG_PARAMS, BaselineIBME, BOTTOM, PublicKey, ReceiverKey, SenderKey

MAGIC_BYTEAUTH = b"IBME:BYTEAUTH-CT:v1"
MAGIC_ENVELOPE = b"IBME:BOUND-MSG:v1"
DOMAIN_CONTEXT = b"IBME:BYTEAUTH-CONTEXT:v1"
COMMITMENT_BYTES = 64
MAX_INNER_BYTES = 64 * 2**20
MAX_WIRE_BYTES = MAX_INNER_BYTES + 100 * 2**10
ENVELOPE_OVERHEAD = len(MAGIC_ENVELOPE) + 8 + COMMITMENT_BYTES
BYTEAUTH_DEBUG_PARAMS = replace(BASELINE_DEBUG_PARAMS, name="byteauth-hibe-abb10-debug",
                               max_message_bytes=BASELINE_DEBUG_PARAMS.max_message_bytes + ENVELOPE_OVERHEAD)


def public_context(public: PublicKey) -> bytes:
    if not isinstance(public, PublicKey):
        raise TypeError("byte authentication expects an IBME PublicKey")
    return shake256(DOMAIN_CONTEXT, encode_bytes(public.to_bytes()), COMMITMENT_BYTES)


def encode_bound_message(commitment: bytes, message: bytes) -> bytes:
    commit = validate_bytes(commitment, name="OTS commitment")
    if len(commit) != COMMITMENT_BYTES:
        raise SerializationError("invalid OTS commitment length")
    return MAGIC_ENVELOPE + encode_bytes(commit) + encode_bytes(message)


def parse_bound_message(data: bytes) -> tuple[bytes, bytes]:
    raw = validate_bytes(data, name="bound message")
    if not raw.startswith(MAGIC_ENVELOPE):
        raise SerializationError("missing bound-message version")
    commit, pos = decode_bytes(raw, len(MAGIC_ENVELOPE))
    message, pos = decode_bytes(raw, pos)
    if pos != len(raw) or len(commit) != COMMITMENT_BYTES:
        raise SerializationError("invalid bound-message framing")
    return commit, message


@dataclass(frozen=True, repr=False)
class ByteAuthCiphertext:
    context: bytes
    ots_key: LamportPublicKey
    inner_bytes: bytes
    signature: bytes

    def __post_init__(self):
        for name in ("context", "inner_bytes", "signature"):
            object.__setattr__(self, name, validate_bytes(getattr(self, name), name=name))
        if len(self.context) != COMMITMENT_BYTES or not isinstance(self.ots_key, LamportPublicKey):
            raise SerializationError("invalid byte-authentication context or key")
        if not self.inner_bytes or len(self.inner_bytes) > MAX_INNER_BYTES or len(self.signature) != SIGNATURE_BYTES:
            raise SerializationError("invalid byte-authentication ciphertext/signature length")

    def signed_body(self):
        return (MAGIC_BYTEAUTH + encode_bytes(self.context) + encode_bytes(self.ots_key.to_bytes())
                + encode_bytes(self.inner_bytes))

    def to_bytes(self):
        return self.signed_body() + encode_bytes(self.signature)

    @classmethod
    def from_bytes(cls, data):
        raw = validate_bytes(data, name="byte-authentication ciphertext")
        if len(raw) > MAX_WIRE_BYTES or not raw.startswith(MAGIC_BYTEAUTH):
            raise SerializationError("unsupported or oversized ciphertext; legacy baseline needs explicit opt-in")
        try:
            context, pos = decode_bytes(raw, len(MAGIC_BYTEAUTH))
            key, pos = decode_bytes(raw, pos)
            inner, pos = decode_bytes(raw, pos)
            signature, pos = decode_bytes(raw, pos)
            if pos != len(raw):
                raise SerializationError("appended/duplicate ciphertext fields")
            return cls(context, LamportPublicKey.from_bytes(key), inner, signature)
        except IBMEError as exc:
            raise SerializationError(str(exc)) from exc

    def __repr__(self):
        return f"ByteAuthCiphertext(inner={len(self.inner_bytes)}B, signature={len(self.signature)}B)"


def authenticate_inner(public: PublicKey, inner_bytes: bytes, ots_secret) -> ByteAuthCiphertext:
    """Public framing helper; it does not create or modify an IBS signature."""
    key = ots_secret.public_key
    unsigned = ByteAuthCiphertext(public_context(public), key, inner_bytes, b"\0" * SIGNATURE_BYTES)
    return ByteAuthCiphertext(unsigned.context, key, unsigned.inner_bytes, ots_secret.sign(unsigned.signed_body()))


class ByteAuthenticatedIBME(BaselineIBME):
    def __init__(self, hibe_backend, ibs_backend, *, ots_rng=None):
        super().__init__(hibe_backend, ibs_backend)
        self._ots_rng = SecureRandom() if ots_rng is None else ots_rng
        if not callable(getattr(self._ots_rng, "read", None)):
            raise RandomnessError("OTS rng must implement read(n)")

    def encrypt(self, public, ek, receiver_id, message, *, rng=None):
        if not isinstance(public, PublicKey) or not isinstance(ek, SenderKey):
            raise TypeError("encrypt expects IBME public and sender keys")
        receiver = validate_identity(receiver_id, name="receiver_id")
        msg = validate_bytes(message, name="message")
        ots_secret = generate_lamport_key(rng=self._ots_rng)
        envelope = encode_bound_message(ots_secret.public_key.commitment(), msg)
        inner = super().encrypt(public, ek, receiver, envelope, rng=rng)
        return authenticate_inner(public, inner.to_bytes(), ots_secret)

    def load_ciphertext(self, data):
        return ByteAuthCiphertext.from_bytes(data)

    def decrypt(self, public, dk, sender_id, ciphertext, *, rng=None):
        if not isinstance(public, PublicKey) or not isinstance(dk, ReceiverKey):
            raise TypeError("decrypt expects IBME public and receiver keys")
        sender = validate_identity(sender_id, name="sender_id")
        try:
            ct = ciphertext if isinstance(ciphertext, ByteAuthCiphertext) else self.load_ciphertext(ciphertext)
            if not compare_digest(ct.context, public_context(public)) or not ct.ots_key.verify(ct.signed_body(), ct.signature):
                return BOTTOM
            inner = super().load_ciphertext(ct.inner_bytes)
            envelope = super().decrypt(public, dk, sender, inner, rng=rng)
            if envelope is BOTTOM:
                return BOTTOM
            commitment, message = parse_bound_message(envelope)
            if not compare_digest(commitment, ct.ots_key.commitment()):
                return BOTTOM
            return message
        except IBMEError:
            return BOTTOM
