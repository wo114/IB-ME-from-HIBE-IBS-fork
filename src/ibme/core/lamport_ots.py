"""Single-use Lamport-style hash signature for ciphertext byte authentication.

Assumes preimage/second-preimage resistance and message-hash collision
resistance of the separated SHAKE domains. No NIST/QROM grade is claimed.
The public key is deliberately uncompressed; this is the correctness baseline.
"""

from dataclasses import dataclass, field
from hmac import compare_digest

from ibme.core.encoding import encode_bytes
from ibme.core.errors import InvalidParameterError, RandomnessError, SerializationError
from ibme.core.hashing import shake256
from ibme.core.randomness import SecureRandom
from ibme.core.types import validate_bytes

BITS = 512
ELEMENT_BYTES = 64
PUBLIC_BYTES = 2 * BITS * ELEMENT_BYTES
SIGNATURE_BYTES = BITS * ELEMENT_BYTES
MAGIC_PUBLIC = b"IBME:LAMPORT-PK:v1"
DOMAIN_ELEMENT = b"IBME:OTS-ELEMENT:v1"
DOMAIN_MESSAGE = b"IBME:OTS-MESSAGE:v1"
DOMAIN_COMMITMENT = b"IBME:OTS-COMMIT:v1"


def _image(index, bit, token):
    return shake256(DOMAIN_ELEMENT, index.to_bytes(4, "big") + bytes([bit]) + encode_bytes(token), ELEMENT_BYTES)


@dataclass(frozen=True, repr=False)
class LamportPublicKey:
    images: bytes

    def __post_init__(self):
        data = validate_bytes(self.images, name="OTS public images")
        if len(data) != PUBLIC_BYTES:
            raise SerializationError("invalid OTS public-key length")
        object.__setattr__(self, "images", data)

    def to_bytes(self):
        return MAGIC_PUBLIC + self.images

    @classmethod
    def from_bytes(cls, data):
        raw = validate_bytes(data, name="OTS public key")
        if len(raw) != len(MAGIC_PUBLIC) + PUBLIC_BYTES or not raw.startswith(MAGIC_PUBLIC):
            raise SerializationError("invalid OTS public-key version or length")
        return cls(raw[len(MAGIC_PUBLIC):])

    def commitment(self):
        return shake256(DOMAIN_COMMITMENT, encode_bytes(self.to_bytes()), ELEMENT_BYTES)

    def _digest(self, message):
        return shake256(DOMAIN_MESSAGE, self.commitment() + encode_bytes(message), BITS // 8)

    def verify(self, message, signature):
        if not isinstance(message, (bytes, bytearray, memoryview)) or not isinstance(signature, (bytes, bytearray, memoryview)):
            return False
        sig = bytes(signature)
        if len(sig) != SIGNATURE_BYTES:
            return False
        digest = self._digest(bytes(message))
        for i in range(BITS):
            bit = (digest[i // 8] >> (7 - i % 8)) & 1
            token = sig[i * ELEMENT_BYTES:(i + 1) * ELEMENT_BYTES]
            start = (2 * i + bit) * ELEMENT_BYTES
            if not compare_digest(_image(i, bit, token), self.images[start:start + ELEMENT_BYTES]):
                return False
        return True

    def __repr__(self):
        return f"LamportPublicKey({PUBLIC_BYTES}B)"


@dataclass(repr=False)
class LamportSigningKey:
    public_key: LamportPublicKey
    _tokens: bytes = field(repr=False)
    used: bool = field(default=False, init=False)

    def sign(self, message):
        msg = validate_bytes(message, name="OTS message")
        if self.used:
            raise InvalidParameterError("OTS key has already been consumed")
        self.used = True
        digest = self.public_key._digest(msg)
        signature = b"".join(
            self._tokens[(2 * i + ((digest[i // 8] >> (7 - i % 8)) & 1)) * ELEMENT_BYTES:
                         (2 * i + ((digest[i // 8] >> (7 - i % 8)) & 1) + 1) * ELEMENT_BYTES]
            for i in range(BITS)
        )
        self._tokens = b""  # Releases the reference; Python does not guarantee erasure.
        return signature

    def __repr__(self):
        return f"LamportSigningKey(used={self.used}, secret=<redacted>)"


def generate_lamport_key(*, rng=None):
    source = SecureRandom() if rng is None else rng
    if not callable(getattr(source, "read", None)):
        raise RandomnessError("OTS rng must implement read(n)")
    tokens = source.read(PUBLIC_BYTES)
    if not isinstance(tokens, bytes) or len(tokens) != PUBLIC_BYTES:
        raise RandomnessError("OTS rng returned a wrong type or length")
    images = b"".join(_image(i, bit, tokens[(2 * i + bit) * ELEMENT_BYTES:(2 * i + bit + 1) * ELEMENT_BYTES])
                      for i in range(BITS) for bit in (0, 1))
    return LamportSigningKey(LamportPublicKey(images), tokens)
