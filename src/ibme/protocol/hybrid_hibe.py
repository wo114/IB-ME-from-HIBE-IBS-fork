"""HYBRID-HIBE/1: opaque HIBE seed encryption + HKDF/AES-256-GCM payload.

Only the frozen HIBE interface and explicit component decoders are used.
No identity or identity digest is published in this wrapper's ciphertext.
This research adapter does not add a CCA, QROM or parameter security claim.
"""

from dataclasses import dataclass, field
from hmac import compare_digest
from typing import ClassVar

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ibme.core.encoding import decode_bytes, encode_bytes
from ibme.core.errors import IBMEError, InvalidParameterError, RandomnessError, SerializationError
from ibme.core.hashing import shake256
from ibme.core.randomness import SecureRandom
from ibme.core.types import validate_bytes, validate_identity

MAGIC = b"IBME:HYBRID-HIBE:v1"
SUITE = b"HIBE-IDPAD/SEED32/HKDF-SHA256/AES256GCM/v1"
DOMAIN_PUBLIC = b"IBME:HYBRID-HIBE:PUBLIC:v1"
DOMAIN_KDF = b"IBME:HYBRID-HIBE:DEM-KEY:v1"
DOMAIN_ID_PAD = b"IBME:HYBRID-ID:v1"
SEED_BYTES, NONCE_BYTES, TAG_BYTES, CONTEXT_BYTES = 32, 12, 16, 64
HARD_CAPSULE_BYTES = 4 * 2**20
HARD_PAYLOAD_BYTES = 16 * 2**20
# Target-scale lattice HIBE keys (e.g. Lai n=2048) exceed the old
# 16 MiB component / 32 MiB wire caps.  Capsules remain 4 MiB.
HARD_COMPONENT_BYTES = 64 * 2**20
HARD_WIRE_BYTES = 64 * 2**20 + 1024


def _frame(kind, fields):
    raw = MAGIC + encode_bytes(SUITE) + encode_bytes(kind) + b"".join(encode_bytes(x) for x in fields)
    if len(raw) > HARD_WIRE_BYTES:
        raise SerializationError("hybrid object exceeds wire budget")
    return raw


def _unframe(data, kind, count):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise SerializationError("hybrid object must be bytes")
    size = data.nbytes if isinstance(data, memoryview) else len(data)
    if size > HARD_WIRE_BYTES:
        raise SerializationError("hybrid object exceeds wire budget")
    raw = bytes(data)
    if not raw.startswith(MAGIC):
        raise SerializationError("invalid hybrid magic/size")
    try:
        suite, pos = decode_bytes(raw, len(MAGIC))
        actual, pos = decode_bytes(raw, pos)
        if suite != SUITE or actual != kind:
            raise SerializationError("invalid hybrid suite/object kind")
        fields = []
        for _ in range(count):
            value, pos = decode_bytes(raw, pos)
            fields.append(value)
        if pos != len(raw):
            raise SerializationError("appended/duplicate hybrid fields")
        return fields
    except IBMEError as exc:
        raise SerializationError(str(exc)) from exc


def _component_bytes(value):
    if not callable(getattr(value, "to_bytes", None)):
        raise TypeError("expected a serializable HIBE component")
    raw = value.to_bytes()
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= HARD_COMPONENT_BYTES:
        raise SerializationError("invalid hybrid component type/size")
    return raw


def _canonical_load(decoder, raw):
    if not 1 <= len(raw) <= HARD_COMPONENT_BYTES:
        raise SerializationError("hybrid component exceeds budget")
    value = decoder.from_bytes(raw)
    if _component_bytes(value) != raw:
        raise SerializationError("noncanonical inner HIBE component")
    return value


@dataclass(frozen=True)
class HybridLimits:
    backend_id: bytes = b"abb10-debug-v2"
    identity_max_bytes: int = 64
    max_payload_bytes: int = 65536
    max_capsule_bytes: int = HARD_CAPSULE_BYTES

    def __post_init__(self):
        try:
            identifier = validate_bytes(self.backend_id, name="hybrid backend identifier")
        except IBMEError as exc:
            raise InvalidParameterError(str(exc)) from exc
        if not 1 <= len(identifier) <= 32 or any(x not in b"abcdefghijklmnopqrstuvwxyz0123456789-_" for x in identifier):
            raise InvalidParameterError("invalid explicit hybrid backend identifier")
        object.__setattr__(self, "backend_id", identifier)
        for name, maximum in (("identity_max_bytes", 256), ("max_payload_bytes", HARD_PAYLOAD_BYTES),
                              ("max_capsule_bytes", HARD_CAPSULE_BYTES)):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
                raise InvalidParameterError("hybrid resource limit out of range/type")

    def to_bytes(self):
        return encode_bytes(self.backend_id) + b"".join(x.to_bytes(4, "big") for x in
                    (self.identity_max_bytes, self.max_payload_bytes, self.max_capsule_bytes))

    @classmethod
    def from_bytes(cls, data):
        try:
            identifier, pos = decode_bytes(data)
            if len(data) - pos != 12:
                raise SerializationError("invalid hybrid limit length")
            values = [int.from_bytes(data[i:i + 4], "big") for i in range(pos, len(data), 4)]
            return cls(identifier, *values)
        except IBMEError as exc:
            raise SerializationError(str(exc)) from exc


@dataclass(frozen=True)
class HybridHIBEParams:
    inner_params: object
    limits: HybridLimits = field(default_factory=HybridLimits)
    security_claim: ClassVar[str] = "none"
    backend_admitted: ClassVar[bool] = False

    def __post_init__(self):
        if not isinstance(self.limits, HybridLimits):
            raise TypeError("expected HybridLimits")
        # These are explicit public configuration fields, never key internals.
        if (getattr(self.inner_params, "max_message_bytes", 0) < SEED_BYTES
                or getattr(self.inner_params, "identity_bytes", None) != encoded_identity_bytes(self.limits.identity_max_bytes)):
            raise InvalidParameterError("inner configuration must support 32 B seeds and fixed-width encoded identities")

    @property
    def identity_bytes(self): return self.limits.identity_max_bytes

    @property
    def max_message_bytes(self): return self.limits.max_payload_bytes

    @property
    def name(self): return "hybrid-hibe-research-v1"


@dataclass(frozen=True, eq=False, repr=False)
class HybridPublicKey:
    limits: HybridLimits
    inner: object
    context: bytes = field(init=False, repr=False)

    def __post_init__(self):
        if not isinstance(self.limits, HybridLimits):
            raise TypeError("expected HybridLimits")
        _component_bytes(self.inner)
        object.__setattr__(self, "context", shake256(DOMAIN_PUBLIC, self.to_bytes(), CONTEXT_BYTES))

    def to_bytes(self): return _frame(b"PUBLIC", (self.limits.to_bytes(), _component_bytes(self.inner)))

    @classmethod
    def from_bytes(cls, data, inner_type):
        limits, public = _unframe(data, b"PUBLIC", 2)
        return cls(HybridLimits.from_bytes(limits), _canonical_load(inner_type, public))

    def __repr__(self): return "HybridPublicKey(security_claim='none')"


@dataclass(frozen=True, eq=False, repr=False)
class _HybridSecret:
    public_key: HybridPublicKey
    inner: object
    identities: tuple = ()
    KIND: ClassVar[bytes]
    IDENTITY_FIELDS: ClassVar[int] = 0
    __hash__ = None

    def __post_init__(self):
        if not isinstance(self.public_key, HybridPublicKey):
            raise TypeError("expected hybrid public key")
        _component_bytes(self.inner)
        if not isinstance(self.identities, (tuple, list)) or len(self.identities) != self.IDENTITY_FIELDS:
            raise SerializationError("hybrid key identity field count mismatch")
        object.__setattr__(self, "identities", tuple(validate_identity(value,
                            max_bytes=self.public_key.limits.identity_max_bytes) for value in self.identities))

    def to_bytes(self): return _frame(self.KIND, (self.public_key.to_bytes(), _component_bytes(self.inner), *self.identities))

    @classmethod
    def from_bytes(cls, data, public_type, inner_type):
        public, inner, *identities = _unframe(data, cls.KIND, 2 + cls.IDENTITY_FIELDS)
        try:
            return cls(HybridPublicKey.from_bytes(public, public_type), _canonical_load(inner_type, inner), tuple(identities))
        except IBMEError as exc:
            raise SerializationError(str(exc)) from exc

    def __repr__(self): return f"{type(self).__name__}(secrets=<redacted>)"


@dataclass(frozen=True, eq=False, repr=False)
class HybridMasterSecret(_HybridSecret):
    KIND: ClassVar[bytes] = b"MASTER"


@dataclass(frozen=True, eq=False, repr=False)
class HybridLevel1SecretKey(_HybridSecret):
    KIND: ClassVar[bytes] = b"LEVEL1"
    IDENTITY_FIELDS: ClassVar[int] = 1

    def __post_init__(self):
        super().__post_init__()
        if not compare_digest(self.inner.identity, encoded_identity(self.identity, self.public_key.limits, b"P")):
            raise SerializationError("hybrid parent identity binding mismatch")

    @property
    def identity(self):
        return self.identities[0]


@dataclass(frozen=True, eq=False, repr=False)
class HybridLevel2SecretKey(_HybridSecret):
    KIND: ClassVar[bytes] = b"LEVEL2"
    IDENTITY_FIELDS: ClassVar[int] = 2

    def __post_init__(self):
        super().__post_init__()
        if (not compare_digest(self.inner.parent_identity, encoded_identity(self.parent_identity, self.public_key.limits, b"P"))
                or not compare_digest(self.inner.child_identity, encoded_identity(self.child_identity, self.public_key.limits, b"C"))):
            raise SerializationError("hybrid parent/child identity binding mismatch")

    @property
    def parent_identity(self):
        return self.identities[0]

    @property
    def child_identity(self):
        return self.identities[1]


def encoded_identity_bytes(maximum): return len(DOMAIN_ID_PAD) + 1 + 4 + maximum


def encoded_identity(identity, limits, role):
    if role not in (b"P", b"C"):
        raise InvalidParameterError("invalid hybrid identity role")
    raw = validate_identity(identity, max_bytes=limits.identity_max_bytes)
    return DOMAIN_ID_PAD + role + encode_bytes(raw) + b"\0" * (limits.identity_max_bytes - len(raw))


def derive_dem_key(seed, context):
    seed = validate_bytes(seed, name="hybrid seed")
    context = validate_bytes(context, name="hybrid public context")
    if len(seed) != SEED_BYTES or len(context) != CONTEXT_BYTES:
        raise InvalidParameterError("invalid hybrid seed/context length")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=context,
                info=encode_bytes(DOMAIN_KDF) + encode_bytes(SUITE)).derive(seed)


def authenticated_header(context, capsule, nonce, payload_bytes):
    return _frame(b"AAD", (context, capsule, nonce, payload_bytes.to_bytes(4, "big")))


@dataclass(frozen=True, eq=False, repr=False)
class HybridCiphertext:
    context: bytes
    capsule: bytes
    nonce: bytes
    body: bytes

    def __post_init__(self):
        maxima = dict(context=CONTEXT_BYTES, nonce=NONCE_BYTES, capsule=HARD_CAPSULE_BYTES,
                      body=HARD_PAYLOAD_BYTES + TAG_BYTES)
        for name in ("context", "capsule", "nonce", "body"):
            value = getattr(self, name)
            if isinstance(value, (bytes, bytearray, memoryview)):
                size = value.nbytes if isinstance(value, memoryview) else len(value)
                if size > maxima[name]:
                    raise SerializationError("hybrid ciphertext exceeds field budget")
            object.__setattr__(self, name, validate_bytes(value, name=f"hybrid {name}"))
        if (len(self.context) != CONTEXT_BYTES or len(self.nonce) != NONCE_BYTES
                or not 1 <= len(self.capsule) <= HARD_CAPSULE_BYTES
                or not TAG_BYTES <= len(self.body) <= HARD_PAYLOAD_BYTES + TAG_BYTES):
            raise SerializationError("hybrid ciphertext length out of range")

    def aad(self): return authenticated_header(self.context, self.capsule, self.nonce, len(self.body) - TAG_BYTES)

    def to_bytes(self): return _frame(b"CIPHERTEXT", (self.context, self.capsule, self.nonce, self.body))

    @classmethod
    def from_bytes(cls, data):
        fields = _unframe(data, b"CIPHERTEXT", 4)
        try:
            return cls(*fields)
        except IBMEError as exc:
            raise SerializationError(str(exc)) from exc

    def __repr__(self): return f"HybridCiphertext(capsule={len(self.capsule)}B, payload={len(self.body) - TAG_BYTES}B)"


@dataclass(frozen=True)
class _BoundDecoder:
    from_bytes: object


class HybridHIBE:
    security_claim = "none"
    backend_admitted = False

    def __init__(self, inner_backend, *, backend_id, public_key_type, master_type, level1_type, level2_type,
                 key_binding_validator=None):
        self.inner_backend = inner_backend
        self.backend_id = HybridLimits(backend_id=backend_id).backend_id
        self.public_key_type, self.master_type = public_key_type, master_type
        self.level1_type, self.level2_type = level1_type, level2_type
        validator = getattr(inner_backend, "validate_key_binding", None) if key_binding_validator is None else key_binding_validator
        if not callable(validator):
            raise InvalidParameterError("hybrid HIBE requires an explicit primitive key-binding validator")
        self._key_binding_validator = validator

    def component_decoders(self):
        return dict(hpk=_BoundDecoder(self.load_public_key), hmsk=_BoundDecoder(self.load_master_secret),
                    sk1=_BoundDecoder(self.load_level1_key), sk2=_BoundDecoder(self.load_level2_key))

    def _check_public(self, public):
        if not isinstance(public, HybridPublicKey) or not isinstance(public.inner, self.public_key_type):
            raise TypeError("expected the selected hybrid public key")
        if public.limits.backend_id != self.backend_id:
            raise InvalidParameterError("hybrid backend identifier mismatch")

    def _check_secret(self, secret, wrapper_type, inner_type):
        if not isinstance(secret, wrapper_type) or not isinstance(secret.inner, inner_type):
            raise TypeError("expected the selected hybrid secret type")
        self._check_public(secret.public_key)
        try:
            accepted = self._key_binding_validator(secret.public_key.inner, secret.inner)
        except Exception as exc:
            raise InvalidParameterError("inner HIBE key/public binding validation failed") from exc
        if accepted is not True:
            raise InvalidParameterError("inner HIBE secret is not bound to its advertised public key")

    def load_public_key(self, data):
        value = HybridPublicKey.from_bytes(data, self.public_key_type)
        try:
            self._check_public(value)
        except IBMEError as exc:
            raise SerializationError(str(exc)) from exc
        return value

    def _load_secret(self, data, wrapper_type, inner_type):
        value = wrapper_type.from_bytes(data, self.public_key_type, inner_type)
        try:
            self._check_secret(value, wrapper_type, inner_type)
        except IBMEError as exc:
            raise SerializationError(str(exc)) from exc
        return value

    def load_master_secret(self, data): return self._load_secret(data, HybridMasterSecret, self.master_type)

    def load_level1_key(self, data): return self._load_secret(data, HybridLevel1SecretKey, self.level1_type)

    def load_level2_key(self, data): return self._load_secret(data, HybridLevel2SecretKey, self.level2_type)

    def setup(self, params, *, rng=None):
        if not isinstance(params, HybridHIBEParams):
            raise TypeError("hybrid setup requires explicit HybridHIBEParams")
        if params.limits.backend_id != self.backend_id:
            raise InvalidParameterError("hybrid setup backend mismatch")
        public, master = self.inner_backend.setup(params.inner_params, rng=rng)
        wrapped = HybridPublicKey(params.limits, public)
        self._check_public(wrapped)
        result = HybridMasterSecret(wrapped, master)
        self._check_secret(result, HybridMasterSecret, self.master_type)
        return wrapped, result

    def extract(self, msk, parent_id, *, rng=None):
        self._check_secret(msk, HybridMasterSecret, self.master_type)
        identity = validate_identity(parent_id, max_bytes=msk.public_key.limits.identity_max_bytes)
        inner = self.inner_backend.extract(msk.inner, encoded_identity(identity, msk.public_key.limits, b"P"), rng=rng)
        result = HybridLevel1SecretKey(msk.public_key, inner, (identity,))
        self._check_secret(result, HybridLevel1SecretKey, self.level1_type)
        return result

    def derive(self, sk_parent, child_id, *, rng=None):
        self._check_secret(sk_parent, HybridLevel1SecretKey, self.level1_type)
        identity = validate_identity(child_id, max_bytes=sk_parent.public_key.limits.identity_max_bytes)
        inner = self.inner_backend.derive(sk_parent.inner, encoded_identity(identity, sk_parent.public_key.limits, b"C"), rng=rng)
        result = HybridLevel2SecretKey(sk_parent.public_key, inner, (sk_parent.identity, identity))
        self._check_secret(result, HybridLevel2SecretKey, self.level2_type)
        return result

    def encrypt(self, pk, parent_id, child_id, payload, *, rng=None):
        self._check_public(pk)
        parent = validate_identity(parent_id, max_bytes=pk.limits.identity_max_bytes)
        child = validate_identity(child_id, max_bytes=pk.limits.identity_max_bytes)
        message = validate_bytes(payload, name="hybrid payload")
        if len(message) > pk.limits.max_payload_bytes:
            raise InvalidParameterError("hybrid payload exceeds configured budget")
        source = SecureRandom() if rng is None else rng
        if not callable(getattr(source, "read", None)):
            raise RandomnessError("hybrid rng must provide read(n)")
        try:
            seed, nonce = source.read(SEED_BYTES), source.read(NONCE_BYTES)
        except Exception as exc:
            raise RandomnessError("hybrid entropy source failed") from exc
        if not isinstance(seed, bytes) or not isinstance(nonce, bytes) or len(seed) != SEED_BYTES or len(nonce) != NONCE_BYTES:
            raise RandomnessError("hybrid rng returned a wrong type/length")
        capsule = self.inner_backend.encrypt(pk.inner, encoded_identity(parent, pk.limits, b"P"),
                       encoded_identity(child, pk.limits, b"C"), seed, rng=source).to_bytes()
        if not 1 <= len(capsule) <= pk.limits.max_capsule_bytes:
            raise SerializationError("inner HIBE capsule exceeds configured budget")
        body = AESGCM(derive_dem_key(seed, pk.context)).encrypt(nonce, message,
                        authenticated_header(pk.context, capsule, nonce, len(message)))
        return HybridCiphertext(pk.context, capsule, nonce, body)

    def load_ciphertext(self, data):
        value = HybridCiphertext.from_bytes(data)
        inner = self.inner_backend.load_ciphertext(value.capsule)
        if inner.to_bytes() != value.capsule:
            raise SerializationError("noncanonical inner HIBE capsule")
        return value

    def decrypt(self, sk_child, ct, *, rng=None):
        self._check_secret(sk_child, HybridLevel2SecretKey, self.level2_type)
        if not isinstance(ct, HybridCiphertext):
            raise TypeError("expected HybridCiphertext")
        public = sk_child.public_key
        try:
            ct = HybridCiphertext.from_bytes(ct.to_bytes())
            if (not compare_digest(ct.context, public.context) or len(ct.capsule) > public.limits.max_capsule_bytes
                    or len(ct.body) - TAG_BYTES > public.limits.max_payload_bytes):
                return None
            inner = self.inner_backend.load_ciphertext(ct.capsule)
            if inner.to_bytes() != ct.capsule:
                return None
            seed = self.inner_backend.decrypt(sk_child.inner, inner, rng=rng)
            if not isinstance(seed, bytes) or len(seed) != SEED_BYTES:
                return None
            return AESGCM(derive_dem_key(seed, public.context)).decrypt(ct.nonce, ct.body, ct.aad())
        except (IBMEError, InvalidTag, ValueError, OverflowError):
            return None
