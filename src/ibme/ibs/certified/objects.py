"""Certification objects and entropy-free private-state reconstruction."""
from dataclasses import dataclass, field
import threading

from ibme.core.errors import EncodingError, SerializationError
from ibme.core.hashing import hash_identity, shake256
from ibme.core.types import validate_identity
from ibme.ibs.api import IBSPublicKey, IBSMasterSecret, IBSSigningKey, IBSSignature
from .codec import Cursor, blob, decode, encode, framed
from .ordinary import ordinary, PROFILES
from .falcon import PROFILES as FALCON_PROFILES, canonical_public
from .params import CertifiedIBSParams

PK_MAGIC = b"IBME/CERTIBS/PK/1\0"
MSK_MAGIC = b"IBME/CERTIBS/MSK/1\0"
SK_MAGIC = b"IBME/CERTIBS/SK/1\0"
SIG_MAGIC = b"IBME/CERTIBS/SIG/1\0"


def exact(value, size):
    if type(value) is not bytes or len(value) != size:
        raise SerializationError("certified IBS field type/size mismatch")


def certificate_message(public, identity, user_public):
    return framed(b"IBME/CERTIBS/CERTIFICATE/1", public.context, identity, user_public)


def application_message(public, identity, user_public, certificate, message):
    return framed(b"IBME/CERTIBS/MESSAGE/1", public.context, identity, user_public, certificate, message)


@dataclass(frozen=True, eq=False)
class CertifiedPublicKey(IBSPublicKey):
    params: CertifiedIBSParams
    authority_public: bytes

    def __post_init__(self):
        if type(self.params) is not CertifiedIBSParams:
            raise SerializationError("certified IBS public parameters type")
        exact(self.authority_public, PROFILES[self.params.base_algorithm].public_key_bytes)
        if self.params.base_algorithm in FALCON_PROFILES and not canonical_public(self.params.base_algorithm,self.authority_public):
            raise SerializationError("noncanonical Falcon authority public key")

    @property
    def context(self):
        return shake256(b"IBME/CERTIBS/PUBLIC-CONTEXT/1", blob(self.to_bytes()), 32)

    def to_bytes(self):
        return encode(PK_MAGIC, self.params.to_bytes(), self.authority_public)

    @classmethod
    def from_bytes(cls, data):
        params, public = decode(data, PK_MAGIC, 2, limit=16384)
        return cls(CertifiedIBSParams.from_bytes(params), public)


@dataclass(frozen=True, eq=False)
class CertifiedSigningKey(IBSSigningKey):
    public_key: CertifiedPublicKey
    bound_identity: bytes
    user_public: bytes
    certificate: bytes
    user_secret: bytes = field(repr=False)

    def __post_init__(self):
        if type(self.public_key) is not CertifiedPublicKey:
            raise SerializationError("certified IBS signing key public context")
        try:
            validate_identity(self.bound_identity, max_bytes=self.params.identity_bytes)
        except EncodingError as exc:
            raise SerializationError("certified IBS signing identity") from exc
        if type(self.bound_identity) is not bytes:
            raise SerializationError("certified IBS stored identity must be immutable bytes")
        profile = PROFILES[self.params.base_algorithm]
        exact(self.user_public, profile.public_key_bytes)
        exact(self.user_secret, profile.secret_key_bytes)
        exact(self.certificate, profile.signature_bytes)
        engine = ordinary(self.params)
        if engine.public_from_secret(self.user_secret) != self.user_public:
            raise SerializationError("certified IBS user private/public mismatch")
        if not engine.verify(self.public_key.authority_public,
                             certificate_message(self.public_key, self.identity, self.user_public), self.certificate):
            raise SerializationError("certified IBS invalid identity certificate")

    @property
    def params(self):
        return self.public_key.params

    @property
    def identity(self):
        return self.bound_identity

    @property
    def identity_digest(self):
        return hash_identity(self.identity, 32)

    def to_bytes(self):
        return encode(SK_MAGIC, self.public_key.to_bytes(), self.identity, self.user_public,
                      self.certificate, self.user_secret)

    @classmethod
    def from_bytes(cls, data):
        public, identity, user_public, certificate, secret = decode(data, SK_MAGIC, 5, limit=32768)
        return cls(CertifiedPublicKey.from_bytes(public), identity, user_public, certificate, secret)


@dataclass(frozen=True, eq=False)
class CertifiedSignature(IBSSignature):
    algorithm: str
    context: bytes
    user_public: bytes
    certificate: bytes
    message_signature: bytes

    def __post_init__(self):
        if type(self.algorithm) is not str or self.algorithm not in PROFILES:
            raise SerializationError("certified IBS signature algorithm")
        profile = PROFILES[self.algorithm]
        exact(self.context, 32)
        exact(self.user_public, profile.public_key_bytes)
        if self.algorithm in FALCON_PROFILES and not canonical_public(self.algorithm,self.user_public):
            raise SerializationError("noncanonical Falcon user public key")
        exact(self.certificate, profile.signature_bytes)
        exact(self.message_signature, profile.signature_bytes)

    def to_bytes(self):
        return encode(SIG_MAGIC, self.algorithm.encode("ascii"), self.context, self.user_public,
                      self.certificate, self.message_signature)

    @classmethod
    def from_bytes(cls, data):
        algorithm, context, public, certificate, message = decode(data, SIG_MAGIC, 5, limit=32768)
        try:
            name = algorithm.decode("ascii")
        except UnicodeError as exc:
            raise SerializationError("certified IBS signature algorithm encoding")
        return cls(name, context, public, certificate, message)


class CertifiedMasterSecret(IBSMasterSecret):
    """A fixed-issuance service. Its lock/cache are private to this module."""
    __hash__ = None

    def __init__(self, public_key, authority_secret, *, persist_callback=None):
        if type(public_key) is not CertifiedPublicKey:
            raise SerializationError("certified IBS master public context")
        exact(authority_secret, PROFILES[public_key.params.base_algorithm].secret_key_bytes)
        if persist_callback is not None and not callable(persist_callback):
            raise TypeError("persist_callback must be callable")
        if ordinary(public_key.params).public_from_secret(authority_secret) != public_key.authority_public:
            raise SerializationError("certified IBS authority private/public mismatch")
        self.public_key = public_key
        self._authority_secret = authority_secret
        self._cache = {}
        self._lock = threading.RLock()
        self.persist_callback = persist_callback

    @property
    def params(self):
        return self.public_key.params

    def __repr__(self):
        return "CertifiedMasterSecret(<private fixed-issuance state>)"

    def to_bytes(self):
        with self._lock:
            entries = len(self._cache).to_bytes(4, "big")
            for identity, key in sorted(self._cache.items()):
                entries += blob(identity) + blob(b"" if key is None else key.to_bytes())
            return encode(MSK_MAGIC, self.public_key.to_bytes(), self._authority_secret, entries)

    @classmethod
    def from_bytes(cls, data):
        public, secret, entries = decode(data, MSK_MAGIC, 3)
        result = cls(CertifiedPublicKey.from_bytes(public), secret)
        cursor = Cursor(entries)
        count = cursor.number()
        if count > result.params.max_identities:
            raise SerializationError("certified IBS issuance count exceeds capacity")
        previous = b""
        for _ in range(count):
            identity, encoded_key = cursor.field(), cursor.field()
            if not previous < identity or not 1 <= len(identity) <= result.params.identity_bytes:
                raise SerializationError("duplicate/unordered/invalid certified IBS cached identity")
            previous = identity
            key = CertifiedSigningKey.from_bytes(encoded_key) if encoded_key else None
            if key is not None and (key.public_key != result.public_key or key.identity != identity):
                raise SerializationError("certified IBS cached key context/identity mismatch")
            result._cache[identity] = key
        cursor.end()
        return result
