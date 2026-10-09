"""Luo ICICS 2024 §4 Algorithms 13--16: module IBS research backend.

Explicit uniform A, bounded uniform masks, fixed identity keys and exact NTT.
This MODULE-REF/1 is uncompressed, variable-time and not security-admitted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
import math
import struct
from typing import ClassVar

from ibme.core.encoding import decode_bytes, encode_bytes
from ibme.core.errors import EncodingError, IBMEError, InvalidParameterError, RandomnessError, SerializationError
from ibme.core.hashing import hash_identity, shake256
from ibme.core.randomness import SecureRandom
from ibme.core.types import validate_bytes, validate_identity
from .api import IBSPublicKey, IBSMasterSecret, IBSSigningKey, IBSSignature
from .luo_module_math import NegacyclicRing, Rounding, sparse_product

VERSION = b"IBME/LUO2024/MODULE-REF/1"
MAGIC = b"L24M1"
MAX_WIRE_BYTES = 16 * 2**20
HASH_BYTES = 16384
DOMAIN_PUBLIC = b"IBME:LUO2024:MODULE:PUBLIC:v1"
DOMAIN_H1 = b"IBME:LUO2024:MODULE:H1:v1"
DOMAIN_H2 = b"IBME:LUO2024:MODULE:H2:v1"
FIELDS = ("degree", "k", "l", "q", "root", "eta", "kappa", "gamma1", "gamma2", "gamma3",
          "dropped_bits", "identity_max_bytes", "message_max_bytes", "max_extract_attempts",
          "max_sign_attempts", "max_uniform_attempts", "max_cached_identities")


class LuoModuleSamplingAbort(IBMEError):
    """Public sampling/cache budget exhausted; no partial object is returned."""


@lru_cache(maxsize=128)
def _approved_prime(q):
    # The selected large prime has a Sage check in the M2-B1 artifact. Unknown
    # large moduli require a separately reviewed parameter entry, not a guess.
    if q == 274877844481:
        return True
    if not 3 <= q <= 65536 or q % 2 == 0:
        return False
    return all(q % divisor for divisor in range(3, math.isqrt(q) + 1, 2))


@dataclass(frozen=True)
class LuoModuleParams:
    degree: int = 256
    k: int = 11
    l: int = 10
    q: int = 274877844481
    root: int = 153250464611
    eta: int = 1
    kappa: int = 64
    gamma1: int = 125440
    gamma2: int = 31470387200
    gamma3: int = 15270991360
    dropped_bits: int = 28
    identity_max_bytes: int = 64
    message_max_bytes: int = 4096
    max_extract_attempts: int = 1024
    max_sign_attempts: int = 1024
    max_uniform_attempts: int = 128
    max_cached_identities: int = 64
    security_claim: ClassVar[str] = "none"
    backend_admitted: ClassVar[bool] = False

    def __post_init__(self):
        if any(isinstance(getattr(self, name), bool) or not isinstance(getattr(self, name), int)
               or not 1 <= getattr(self, name) < 2**64 for name in FIELDS):
            raise InvalidParameterError("module parameters must be positive uint64 integers")
        if (not _approved_prime(self.q) or not 1 <= self.k <= 16 or not 1 <= self.l <= 16
                or not 2 <= self.degree <= 256 or self.degree & (self.degree - 1)
                or not 1 <= self.dropped_bits <= 62):
            raise InvalidParameterError("unapproved modulus or module dimensions")
        if self.kappa > self.degree or self.gamma1 <= self.beta1 or self.gamma2 <= self.beta2:
            raise InvalidParameterError("invalid challenge or mask bounds")
        if self.gamma2 * 2 >= self.q or self.beta2 >= self.gamma3 or self.kappa * 2**(self.dropped_bits - 1) >= self.gamma3:
            raise InvalidParameterError("module rejection/Hint bounds do not hold")
        limits = dict(identity_max_bytes=256, message_max_bytes=65536, max_extract_attempts=4096,
                      max_sign_attempts=4096, max_uniform_attempts=256, max_cached_identities=64)
        if any(getattr(self, name) > high for name, high in limits.items()):
            raise InvalidParameterError("module research resource limit exceeded")
        try:
            self.ring()
            self.rounding()
        except ValueError as exc:
            raise InvalidParameterError(str(exc)) from exc

    @property
    def beta1(self): return self.kappa * self.eta

    @property
    def beta2(self): return self.kappa * self.gamma1

    def ring(self): return NegacyclicRing(self.degree, self.q, self.root)

    def rounding(self): return Rounding(self.q, 2 * self.gamma3, self.dropped_bits)

    @property
    def max_w1(self): return self.rounding().power2round(self.q - 1)

    def to_bytes(self): return struct.pack(">" + "Q" * len(FIELDS), *(getattr(self, name) for name in FIELDS))

    @classmethod
    def from_bytes(cls, raw):
        if not isinstance(raw, (bytes, bytearray, memoryview)) or len(raw) != 8 * len(FIELDS):
            raise SerializationError("invalid module parameter length")
        try:
            return cls(**dict(zip(FIELDS, struct.unpack(">" + "Q" * len(FIELDS), raw))))
        except InvalidParameterError as exc:
            raise SerializationError(str(exc)) from exc


def _frame(kind, fields):
    raw = MAGIC + encode_bytes(VERSION) + encode_bytes(kind) + b"".join(encode_bytes(x) for x in fields)
    if len(raw) > MAX_WIRE_BYTES:
        raise SerializationError("module wire budget exceeded")
    return raw


def _unframe(data, kind, count):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise SerializationError("module encoding must be bytes")
    raw = validate_bytes(data, name="module encoding")
    if len(raw) > MAX_WIRE_BYTES or not raw.startswith(MAGIC):
        raise SerializationError("invalid module magic/size")
    try:
        version, pos = decode_bytes(raw, len(MAGIC))
        actual, pos = decode_bytes(raw, pos)
        if version != VERSION or actual != kind:
            raise SerializationError("invalid module version/object kind")
        result = []
        for _ in range(count):
            item, pos = decode_bytes(raw, pos)
            result.append(item)
        if pos != len(raw):
            raise SerializationError("appended/duplicate module fields")
        return result
    except IBMEError as exc:
        raise SerializationError(str(exc)) from exc


def _vector(vector, count, p, low, high):
    if not isinstance(vector, (tuple, list)) or len(vector) != count:
        raise SerializationError("module vector dimension mismatch")
    result = []
    for poly in vector:
        if not isinstance(poly, (tuple, list)) or len(poly) != p.degree:
            raise SerializationError("module polynomial dimension mismatch")
        if any(isinstance(x, bool) or not isinstance(x, int) or not low <= x <= high for x in poly):
            raise SerializationError("module coefficient out of range/type")
        result.append(tuple(poly))
    return tuple(result)


def _pack(vector, width=8, signed=False):
    return b"".join(x.to_bytes(width, "big", signed=signed) for poly in vector for x in poly)


def _unpack(raw, count, p, width=8, signed=False):
    if len(raw) != count * p.degree * width:
        raise SerializationError("module coefficient body length mismatch")
    values = [int.from_bytes(raw[pos:pos + width], "big", signed=signed) for pos in range(0, len(raw), width)]
    return tuple(tuple(values[j * p.degree:(j + 1) * p.degree]) for j in range(count))


def _add(a, b, q=None):
    return tuple(tuple((x + y) if q is None else (x + y) % q for x, y in zip(u, v)) for u, v in zip(a, b))


def _sparse_vector(vector, challenge, q=None):
    output = tuple(sparse_product(poly, challenge) for poly in vector)
    return output if q is None else tuple(tuple(x % q for x in poly) for poly in output)


def _norm(vector): return max(abs(x) for poly in vector for x in poly)


def _map(vector, function): return tuple(tuple(function(x) for x in poly) for poly in vector)


def _read(source, count):
    try:
        data = source.read(count)
    except LuoModuleSamplingAbort:
        raise
    except Exception as exc:
        raise RandomnessError("module entropy source failed") from exc
    if not isinstance(data, bytes) or len(data) != count:
        raise RandomnessError("module random source returned a wrong type/length")
    return data


def _below(bound, source, attempts):
    width = max(1, ((bound - 1).bit_length() + 7) // 8)
    ceiling = 2**(8 * width)
    limit = ceiling - ceiling % bound
    for _ in range(attempts):
        value = int.from_bytes(_read(source, width), "big")
        if value < limit:
            return value % bound
    raise LuoModuleSamplingAbort("uniform integer rejection budget exhausted")


class _HashStream:
    def __init__(self, raw): self.raw, self.pos = raw, 0

    def read(self, count):
        if self.pos + count > len(self.raw):
            raise LuoModuleSamplingAbort("challenge XOF byte budget exhausted")
        value = self.raw[self.pos:self.pos + count]
        self.pos += count
        return value


def challenge(p, domain, encoded):
    stream = _HashStream(shake256(domain, encoded, HASH_BYTES))
    positions = list(range(p.degree))
    result = [0] * p.degree
    for j in range(p.kappa):
        pick = j + _below(p.degree - j, stream, p.max_uniform_attempts)
        positions[j], positions[pick] = positions[pick], positions[j]
        result[positions[j]] = 1 if _below(2, stream, p.max_uniform_attempts) else -1
    return tuple(result)


def identity_challenge(public, w1, identity):
    return challenge(public.params, DOMAIN_H1,
                     encode_bytes(public.context) + encode_bytes(_pack(w1)) + encode_bytes(identity))


def message_challenge(public, high, identity, message):
    return challenge(public.params, DOMAIN_H2, encode_bytes(public.context) + encode_bytes(identity)
                     + encode_bytes(_pack(high)) + encode_bytes(message))


@dataclass(frozen=True, eq=False, repr=False)
class LuoModulePublicKey(IBSPublicKey):
    params: LuoModuleParams
    A: tuple
    t: tuple
    context: bytes = field(init=False, repr=False)
    _ring: NegacyclicRing = field(init=False, repr=False)
    _prepared: tuple = field(init=False, repr=False)

    def __post_init__(self):
        if not isinstance(self.params, LuoModuleParams):
            raise TypeError("expected LuoModuleParams")
        p = self.params
        if not isinstance(self.A, (tuple, list)) or len(self.A) != p.k:
            raise SerializationError("module public matrix rows mismatch")
        object.__setattr__(self, "A", tuple(_vector(row, p.l, p, 0, p.q - 1) for row in self.A))
        object.__setattr__(self, "t", _vector(self.t, p.k, p, 0, p.q - 1))
        object.__setattr__(self, "context", shake256(DOMAIN_PUBLIC, self.to_bytes(), 64))
        ring = p.ring()
        object.__setattr__(self, "_ring", ring)
        object.__setattr__(self, "_prepared", ring.prepare_matrix(self.A))

    def matvec(self, vector): return self._ring.matvec(self._prepared, vector)

    def to_bytes(self): return _frame(b"PUBLIC", (self.params.to_bytes(), _pack(tuple(poly for row in self.A for poly in row)), _pack(self.t)))

    @classmethod
    def from_bytes(cls, data):
        params, matrix, t = _unframe(data, b"PUBLIC", 3)
        p = LuoModuleParams.from_bytes(params)
        flat = _unpack(matrix, p.k * p.l, p)
        return cls(p, tuple(tuple(flat[i * p.l:(i + 1) * p.l]) for i in range(p.k)), _unpack(t, p.k, p))

    def __repr__(self): return "LuoModulePublicKey(security_claim='none')"


@dataclass(frozen=True, eq=False, repr=False)
class LuoModuleSigningKey(IBSSigningKey):
    public_key: LuoModulePublicKey
    _identity: bytes
    z1: tuple
    z2: tuple
    w: tuple

    def __post_init__(self):
        if not isinstance(self.public_key, LuoModulePublicKey):
            raise TypeError("expected module public key")
        p = self.public_key.params
        object.__setattr__(self, "_identity", validate_identity(self._identity, max_bytes=p.identity_max_bytes))
        bound = p.gamma1 - p.beta1
        object.__setattr__(self, "z1", _vector(self.z1, p.l, p, -bound, bound))
        object.__setattr__(self, "z2", _vector(self.z2, p.k, p, -bound, bound))
        object.__setattr__(self, "w", _vector(self.w, p.k, p, 0, p.q - 1))
        cid = identity_challenge(self.public_key, _map(self.w, p.rounding().power2round), self.identity)
        if _add(self.public_key.matvec(self.z1), self.z2, p.q) != _add(self.w, _sparse_vector(self.public_key.t, cid, p.q), p.q):
            raise SerializationError("module signing-key equation failed")

    @property
    def identity(self): return self._identity

    @property
    def identity_digest(self): return hash_identity(self.identity, 32)

    def _local_bytes(self): return _frame(b"IDENTITY-STATE", (self.identity, _pack(self.z1, signed=True), _pack(self.z2, signed=True), _pack(self.w)))

    def to_bytes(self): return _frame(b"SIGNING-KEY", (self.public_key.to_bytes(), self._local_bytes()))

    @classmethod
    def _from_local(cls, public, data):
        identity, z1, z2, w = _unframe(data, b"IDENTITY-STATE", 4)
        p = public.params
        try:
            return cls(public, identity, _unpack(z1, p.l, p, signed=True), _unpack(z2, p.k, p, signed=True), _unpack(w, p.k, p))
        except IBMEError as exc:
            raise SerializationError(str(exc)) from exc

    @classmethod
    def from_bytes(cls, data):
        public, local = _unframe(data, b"SIGNING-KEY", 2)
        return cls._from_local(LuoModulePublicKey.from_bytes(public), local)

    def __repr__(self): return f"LuoModuleSigningKey(identity_bytes={len(self.identity)}, secrets=<redacted>)"


@dataclass(frozen=True, eq=False, repr=False)
class LuoModuleMasterSecret(IBSMasterSecret):
    public_key: LuoModulePublicKey
    s1: tuple
    s2: tuple
    _cache: dict = field(default_factory=dict, repr=False)
    __hash__ = None

    def __post_init__(self):
        if not isinstance(self.public_key, LuoModulePublicKey):
            raise TypeError("expected module public key")
        p = self.public_key.params
        object.__setattr__(self, "s1", _vector(self.s1, p.l, p, -p.eta, p.eta))
        object.__setattr__(self, "s2", _vector(self.s2, p.k, p, -p.eta, p.eta))
        if _add(self.public_key.matvec(self.s1), self.s2, p.q) != self.public_key.t:
            raise SerializationError("module master equation failed")
        if not isinstance(self._cache, dict) or len(self._cache) > p.max_cached_identities or any(not isinstance(key, LuoModuleSigningKey)
                or identity != key.identity or key.public_key.context != self.public_key.context for identity, key in self._cache.items()):
            raise SerializationError("invalid module identity cache")

    @property
    def cached_identities(self): return tuple(sorted(self._cache))

    def to_bytes(self):
        cache = len(self._cache).to_bytes(4, "big") + b"".join(encode_bytes(self._cache[id]._local_bytes()) for id in self.cached_identities)
        return _frame(b"MASTER", (self.public_key.to_bytes(), _pack(self.s1, signed=True), _pack(self.s2, signed=True), cache))

    @classmethod
    def from_bytes(cls, data):
        public, s1, s2, cache = _unframe(data, b"MASTER", 4)
        pk = LuoModulePublicKey.from_bytes(public)
        if len(cache) < 4:
            raise SerializationError("truncated module cache count")
        count = int.from_bytes(cache[:4], "big")
        if count > pk.params.max_cached_identities:
            raise SerializationError("module cache count limit")
        keys, pos, previous = {}, 4, None
        try:
            for _ in range(count):
                raw, pos = decode_bytes(cache, pos)
                key = LuoModuleSigningKey._from_local(pk, raw)
                if previous is not None and key.identity <= previous:
                    raise SerializationError("duplicate or noncanonical module cache order")
                keys[key.identity] = key
                previous = key.identity
            if pos != len(cache):
                raise SerializationError("appended module cache fields")
        except IBMEError as exc:
            raise SerializationError(str(exc)) from exc
        return cls(pk, _unpack(s1, pk.params.l, pk.params, signed=True), _unpack(s2, pk.params.k, pk.params, signed=True), keys)

    def __repr__(self): return f"LuoModuleMasterSecret(cached={len(self._cache)}, secrets=<redacted>)"


@dataclass(frozen=True, eq=False, repr=False)
class LuoModuleSignature(IBSSignature):
    params: LuoModuleParams
    context: bytes
    z: tuple
    c: tuple
    w1: tuple
    h: tuple

    def __post_init__(self):
        if not isinstance(self.params, LuoModuleParams):
            raise TypeError("expected module parameters")
        p = self.params
        context = validate_bytes(self.context, name="module context")
        if len(context) != 64:
            raise SerializationError("invalid module context length")
        object.__setattr__(self, "context", context)
        bound = p.gamma2 - p.beta2 - 1
        object.__setattr__(self, "z", _vector(self.z, p.l, p, -bound, bound))
        c = _vector((self.c,), 1, p, -1, 1)[0]
        if sum(abs(x) for x in c) != p.kappa:
            raise SerializationError("module challenge weight mismatch")
        object.__setattr__(self, "c", c)
        object.__setattr__(self, "w1", _vector(self.w1, p.k, p, 0, p.max_w1))
        object.__setattr__(self, "h", _vector(self.h, p.k, p, 0, 1))

    def to_bytes(self):
        width = max(1, (self.params.max_w1.bit_length() + 7) // 8)
        return _frame(b"SIGNATURE", (self.params.to_bytes(), self.context, _pack(self.z, signed=True),
                    _pack((self.c,), 1, True), _pack(self.w1, width), _pack(self.h, 1)))

    @classmethod
    def from_bytes(cls, data, public):
        if not isinstance(public, LuoModulePublicKey):
            raise TypeError("expected module public key")
        params, context, z, c, w1, h = _unframe(data, b"SIGNATURE", 6)
        p = LuoModuleParams.from_bytes(params)
        if p != public.params or context != public.context:
            raise SerializationError("cross-public-key module signature")
        width = max(1, (p.max_w1.bit_length() + 7) // 8)
        return cls(p, context, _unpack(z, p.l, p, signed=True), _unpack(c, 1, p, 1, True)[0],
                   _unpack(w1, p.k, p, width), _unpack(h, p.k, p, 1))

    def __repr__(self): return "LuoModuleSignature(security_claim='none')"


class LuoModuleIBSBackend:
    security_claim = "none"
    backend_admitted = False
    research_only = True

    def __init__(self, *, rng=None):
        self._rng = SecureRandom() if rng is None else rng
        if not callable(getattr(self._rng, "read", None)):
            raise RandomnessError("module rng must implement read(n)")
        self.last_extract_attempts = self.last_sign_attempts = 0

    def _draw(self, p, count, bound):
        return tuple(tuple(_below(2 * bound + 1, self._rng, p.max_uniform_attempts) - bound
                           for _ in range(p.degree)) for _ in range(count))

    def setup(self, params):
        if not isinstance(params, LuoModuleParams):
            raise TypeError("setup requires explicit LuoModuleParams")
        p = params
        matrix = tuple(tuple(tuple(_below(p.q, self._rng, p.max_uniform_attempts) for _ in range(p.degree))
                             for _ in range(p.l)) for _ in range(p.k))
        s1, s2 = self._draw(p, p.l, p.eta), self._draw(p, p.k, p.eta)
        ring = p.ring()
        t = _add(ring.matvec(ring.prepare_matrix(matrix), s1), s2, p.q)
        public = LuoModulePublicKey(p, matrix, t)
        return public, LuoModuleMasterSecret(public, s1, s2)

    def key_extract(self, msk, identity):
        if not isinstance(msk, LuoModuleMasterSecret):
            raise TypeError("expected module master state")
        pk, p = msk.public_key, msk.public_key.params
        ident = validate_identity(identity, max_bytes=p.identity_max_bytes)
        if ident in msk._cache:
            self.last_extract_attempts = 0
            return msk._cache[ident]
        if len(msk._cache) >= p.max_cached_identities:
            raise LuoModuleSamplingAbort("module identity-cache budget exhausted")
        rounding = p.rounding()
        for attempt in range(1, p.max_extract_attempts + 1):
            self.last_extract_attempts = attempt
            y1, y2 = self._draw(p, p.l, p.gamma1), self._draw(p, p.k, p.gamma1)
            w = _add(pk.matvec(y1), y2, p.q)
            cid = identity_challenge(pk, _map(w, rounding.power2round), ident)
            z1, z2 = _add(_sparse_vector(msk.s1, cid), y1), _add(_sparse_vector(msk.s2, cid), y2)
            if max(_norm(z1), _norm(z2)) <= p.gamma1 - p.beta1:
                key = LuoModuleSigningKey(pk, ident, z1, z2, w)
                msk._cache[ident] = key
                return key
        raise LuoModuleSamplingAbort("module Extract budget exhausted")

    def sign(self, sk, message):
        if not isinstance(sk, LuoModuleSigningKey):
            raise TypeError("expected module signing key")
        pk, p = sk.public_key, sk.public_key.params
        msg = validate_bytes(message, name="message")
        if len(msg) > p.message_max_bytes:
            raise EncodingError("module message length limit")
        rounding = p.rounding()
        w1 = _map(sk.w, rounding.power2round)
        w0 = tuple(tuple(w - high * 2**p.dropped_bits for w, high in zip(poly, highs)) for poly, highs in zip(sk.w, w1))
        for attempt in range(1, p.max_sign_attempts + 1):
            self.last_sign_attempts = attempt
            y = self._draw(p, p.l, p.gamma2)
            w = pk.matvec(y)
            c = message_challenge(pk, _map(w, rounding.high_bits), sk.identity, msg)
            z = _add(_sparse_vector(sk.z1, c), y)
            sid2c, w0c = _sparse_vector(sk.z2, c), _sparse_vector(w0, c)
            r = tuple(tuple((a - b) % p.q for a, b in zip(u, v)) for u, v in zip(w, sid2c))
            # Algorithm 15 line 9 prints z_id; §4.2 and Algorithm 16 check z.
            if _norm(z) >= p.gamma2 - p.beta2 or _norm(_map(r, rounding.low_bits)) >= p.gamma3 - p.beta2 or _norm(w0c) >= p.gamma3:
                continue
            h = tuple(tuple(rounding.make_hint(-shift, (value + shift) % p.q) for value, shift in zip(poly, shifts))
                      for poly, shifts in zip(r, w0c))
            signature = LuoModuleSignature(p, pk.context, z, c, w1, h)
            if not self.verify(pk, sk.identity, msg, signature):
                raise IBMEError("module honest-signature equation failed")
            return signature
        raise LuoModuleSamplingAbort("module Sign budget exhausted")

    def verify(self, pk, identity, message, signature):
        if not isinstance(pk, LuoModulePublicKey) or not isinstance(signature, LuoModuleSignature):
            return False
        try:
            p = pk.params
            ident = validate_identity(identity, max_bytes=p.identity_max_bytes)
            msg = validate_bytes(message, name="message")
            if len(msg) > p.message_max_bytes or signature.params != p or signature.context != pk.context:
                return False
            # Validate a local copy; public verification never normalizes or
            # mutates the caller's signature object in place.
            signature = LuoModuleSignature(signature.params, signature.context, signature.z,
                                           signature.c, signature.w1, signature.h)
            cid = identity_challenge(pk, signature.w1, ident)
            tcid = _sparse_vector(pk.t, cid, p.q)
            combined = tuple(tuple((high * 2**p.dropped_bits + value) % p.q for high, value in zip(u, v))
                             for u, v in zip(signature.w1, tcid))
            response = _sparse_vector(combined, signature.c, p.q)
            az = pk.matvec(signature.z)
            candidate = tuple(tuple((a - b) % p.q for a, b in zip(u, v)) for u, v in zip(az, response))
            rounding = p.rounding()
            high = tuple(tuple(rounding.use_hint(h, value) for h, value in zip(hints, poly))
                         for hints, poly in zip(signature.h, candidate))
            return signature.c == message_challenge(pk, high, ident, msg)
        except (IBMEError, TypeError, ValueError, OverflowError):
            return False

    def load_signature(self, pk, data): return LuoModuleSignature.from_bytes(data, pk)
