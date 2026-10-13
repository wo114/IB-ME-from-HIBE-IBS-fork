"""IBS five-method research adapter; stateless issuer, persistent issued user key.

key_extract is PW KeyExt and may issue another key for the same identity. The
caller owns issuance/cache policy; sign and restored sign preserve that key's r.
No formal fixed-service security theorem or default registry admission claimed.
"""
from ibme.core.errors import EncodingError, SerializationError
from ibme.core.randomness import SecureRandom
from ibme.core.types import validate_identity, validate_bytes

from .hashing import inner_identity, inner_message, identity_matrix, message_vector
from .objects import PublicKey, MasterSecret, SigningKey, Signature
from .params import Params


class CheckedRandom:
    def __init__(self, source): self.source = source
    def read(self, size):
        data = self.source.read(size)
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise ValueError("random source returned invalid byte count/type; no fallback")
        try:
            length = data.nbytes if isinstance(data, memoryview) else len(data)
            if length != size: raise ValueError("random source returned wrong byte count")
            raw = bytes(data)
        except (ValueError, TypeError) as exc:
            raise ValueError("invalid random byte view; no fallback") from exc
        if len(raw) != size: raise ValueError("random byte length changed during conversion")
        return raw


def checked_identity(params, value):
    value = validate_identity(value)
    if len(value) > params.identity_max_bytes: raise EncodingError("identity capacity exceeded")
    return value


def checked_message(params, value):
    value = validate_bytes(value, name="message")
    if len(value) > params.message_max_bytes: raise EncodingError("message capacity exceeded")
    return value


def signature_shape(pk, signature):
    p = pk.params
    return (isinstance(signature, Signature) and signature.context == pk.context
            and len(signature.identity_salt) == p.salt_bytes and len(signature.message_salt) == p.salt_bytes
            and len(signature.z) == p.dimension and any(signature.z)
            and sum(z*z for z in signature.z) <= p.signature_bound_squared)


class Backend:
    security_claim = "none"
    backend_admitted = False

    def __init__(self, *, rng=None):
        self.rng = CheckedRandom(SecureRandom() if rng is None else rng)

    def setup(self, params):
        if not isinstance(params, Params): raise TypeError("WangPW Params required")
        from . import engine
        a, trapdoor = engine.generate(params, self.rng)
        pk = PublicKey(params, a)
        return pk, MasterSecret(pk, trapdoor)

    def key_extract(self, msk, identity):
        if not isinstance(msk, MasterSecret): raise TypeError("WangPW master secret required")
        pk, p = msk.public_key, msk.public_key.params
        identity = checked_identity(p, identity)
        from . import engine
        salt = self.rng.read(p.salt_bytes)
        x = inner_identity(p, identity, salt)
        return SigningKey(pk, identity, salt, engine.delegate(msk, identity_matrix(pk, x), self.rng))

    def sign(self, sk, message):
        if not isinstance(sk, SigningKey): raise TypeError("WangPW signing key required")
        pk, p = sk.public_key, sk.public_key.params
        message = checked_message(p, message)
        from . import engine
        from experiments.research.gaussian_reference import SamplingAbort
        salt = self.rng.read(p.salt_bytes)
        x = inner_identity(p, sk.identity, sk.identity_salt)
        y = inner_message(p, message, salt)
        z = engine.sample_signature(sk, message_vector(pk, x, y), self.rng)
        signature = Signature(pk.context, sk.identity_salt, salt, z)
        if not self.verify(pk, sk.identity, message, signature):
            raise SamplingAbort("zero, excessive norm or invalid signature; no reroll")
        return signature

    def verify(self, pk, identity, message, signature):
        try:
            if not isinstance(pk, PublicKey) or not signature_shape(pk, signature): return False
            identity, message = checked_identity(pk.params, identity), checked_message(pk.params, message)
            x = inner_identity(pk.params, identity, signature.identity_salt)
            y = inner_message(pk.params, message, signature.message_salt)
            b, target = identity_matrix(pk, x), message_vector(pk, x, y)
            f = tuple(a+bb for a, bb in zip(pk.a, b))
            return all(sum(a*z for a, z in zip(row, signature.z)) % pk.params.q == v
                       for row, v in zip(f, target))
        except (EncodingError, SerializationError, ValueError, TypeError, AttributeError, OverflowError):
            return False

    def load_signature(self, pk, data):
        if not isinstance(pk, PublicKey): raise TypeError("WangPW public key required")
        signature = Signature.from_bytes(data)
        if not signature_shape(pk, signature): raise SerializationError("signature context/dimension/norm mismatch")
        return signature
