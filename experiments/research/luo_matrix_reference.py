"""Luo et al. ICICS 2024, Section 3: isolated matrix IBS reference.

Implements Algorithms 1--4 with bounded uniform integer masks, rejection,
public verification and one persistent (Z,W) per identity. This is research
code with hand-selected small parameters, variable-time operations and
SHAKE-based hash instantiation. security_claim: none; not an IBSBackend.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
import hashlib
import math
from pathlib import Path
import struct
import sys
from typing import ClassVar

# Standalone research entry points work from a checkout without an editable
# package installation, as do the existing repository attack references.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from ibme.core.encoding import decode_bytes, encode_bytes
from ibme.core.errors import IBMEError
from ibme.core.randomness import SecureRandom
from ibme.lattice.modmat import ModMatrix, ModVector


VERSION = b"IBME/LUO2024/MATRIX-REF/1"
MAGIC = b"L24R1"
MAX_WIRE_BYTES = 8 * 1024 * 1024
MAX_IDENTITIES = 128
PARAM_FIELDS = (
    "n", "m", "k", "q", "eta", "kappa", "gamma1", "gamma2",
    "identity_max_bytes", "message_max_bytes", "max_extract_attempts",
    "max_sign_attempts", "max_uniform_attempts", "max_cached_identities",
)


class SamplingAbort(RuntimeError):
    """A public sampling/resource budget was exhausted; no object is issued."""


def _integer(value, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in [{low}, {high}]")
    return value


@lru_cache(maxsize=128)
def _prime32(q: int) -> bool:
    if q < 2 or (q != 2 and q % 2 == 0):
        return False
    return all(q % d for d in range(3, math.isqrt(q) + 1, 2))


@dataclass(frozen=True)
class MatrixParams:
    n: int = 4
    m: int = 8
    k: int = 4
    q: int = 65537
    eta: int = 1
    kappa: int = 2
    gamma1: int = 128
    gamma2: int = 2048
    identity_max_bytes: int = 16
    message_max_bytes: int = 32
    max_extract_attempts: int = 4096
    max_sign_attempts: int = 4096
    max_uniform_attempts: int = 64
    max_cached_identities: int = MAX_IDENTITIES
    security_claim: ClassVar[str] = "none"
    backend_admitted: ClassVar[bool] = False

    def __post_init__(self):
        limits = dict(n=(1, 16), m=(2, 128), k=(1, 32), q=(3, 2**32 - 1),
                      eta=(1, 2**30), kappa=(1, 32), gamma1=(1, 2**31 - 1),
                      gamma2=(1, 2**31 - 1), identity_max_bytes=(1, 256),
                      message_max_bytes=(1, 65536), max_extract_attempts=(1, 4096),
                      max_sign_attempts=(1, 4096), max_uniform_attempts=(1, 256),
                      max_cached_identities=(1, MAX_IDENTITIES))
        for name in PARAM_FIELDS:
            _integer(getattr(self, name), name, *limits[name])
        if self.m <= self.n or self.kappa > self.k or not _prime32(self.q):
            raise ValueError("require m>n, kappa<=k and an odd prime q")
        if self.gamma1 <= self.beta1 or self.gamma2 <= self.beta2:
            raise ValueError("mask ranges must exceed their secret-shift bounds")

    @property
    def beta1(self):
        return self.kappa * self.eta

    @property
    def beta2(self):
        return self.kappa * self.gamma1

    def to_bytes(self) -> bytes:
        return b"".join(struct.pack(">I", getattr(self, x)) for x in PARAM_FIELDS)

    @classmethod
    def from_bytes(cls, raw: bytes):
        if not isinstance(raw, bytes) or len(raw) != 4 * len(PARAM_FIELDS):
            raise ValueError("invalid parameter encoding")
        return cls(**dict(zip(PARAM_FIELDS, struct.unpack(">" + "I" * len(PARAM_FIELDS), raw))))


def _bytes(value, name: str, maximum: int, *, nonempty=False) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes")
    result = bytes(value)
    if len(result) > maximum or (nonempty and not result):
        raise ValueError(f"invalid {name} length")
    return result


def _frame(kind: bytes, fields) -> bytes:
    raw = MAGIC + encode_bytes(VERSION) + encode_bytes(kind)
    raw += b"".join(encode_bytes(x) for x in fields)
    if len(raw) > MAX_WIRE_BYTES:
        raise ValueError("reference encoding exceeds its size limit")
    return raw


def _unframe(raw, kind: bytes, count: int) -> list[bytes]:
    data = _bytes(raw, "encoding", MAX_WIRE_BYTES)
    if not data.startswith(MAGIC):
        raise ValueError("wrong reference magic")
    version, offset = decode_bytes(data, len(MAGIC))
    actual_kind, offset = decode_bytes(data, offset)
    if version != VERSION or actual_kind != kind:
        raise ValueError("wrong version or object kind")
    values = []
    for _ in range(count):
        value, offset = decode_bytes(data, offset)
        values.append(value)
    if offset != len(data):
        raise ValueError("appended or duplicate fields")
    return values


def _pack_integers(values) -> bytes:
    copied = tuple(values)
    if not 1 <= len(copied) <= 4096:
        raise ValueError("integer vector exceeds reference dimensions")
    for x in copied:
        _integer(x, "signed coefficient", -(2**63), 2**63 - 1)
    return struct.pack(">I", len(copied)) + b"".join(struct.pack(">q", x) for x in copied)


def _unpack_integers(raw: bytes, count: int, bound: int) -> tuple[int, ...]:
    if len(raw) != 4 + 8 * count or int.from_bytes(raw[:4], "big") != count:
        raise ValueError("wrong integer dimensions")
    values = tuple(x[0] for x in struct.iter_unpack(">q", raw[4:]))
    if any(abs(x) > bound for x in values):
        raise ValueError("integer coefficient outside object bound")
    return values


def _pack_integer_matrix(rows) -> bytes:
    matrix = tuple(tuple(row) for row in rows)
    if not matrix or not matrix[0] or any(len(x) != len(matrix[0]) for x in matrix):
        raise ValueError("integer matrix is not rectangular")
    return struct.pack(">II", len(matrix), len(matrix[0])) + _pack_integers(
        x for row in matrix for x in row)


def _unpack_integer_matrix(raw: bytes, rows: int, cols: int, bound: int):
    if len(raw) < 8 or struct.unpack(">II", raw[:8]) != (rows, cols):
        raise ValueError("wrong integer matrix shape")
    values = _unpack_integers(raw[8:], rows * cols, bound)
    return tuple(values[i * cols:(i + 1) * cols] for i in range(rows))


def _mod_matrix(raw: bytes, rows: int, cols: int, q: int) -> ModMatrix:
    if len(raw) < 12 or struct.unpack(">III", raw[:12]) != (rows, cols, q):
        raise ValueError("wrong modular matrix shape or modulus")
    return ModMatrix.from_bytes(raw)


def _check_mod_matrix(value, rows: int, cols: int, q: int):
    if not isinstance(value, ModMatrix) or (value.rows, value.cols, value.q) != (rows, cols, q):
        raise ValueError("wrong modular matrix shape or modulus")


def _integer_matrix(value, rows: int, cols: int, bound: int):
    copied = tuple(tuple(row) for row in value)
    if len(copied) != rows or any(len(row) != cols for row in copied):
        raise ValueError("wrong integer matrix shape")
    for row in copied:
        for x in row:
            _integer(x, "secret coefficient", -bound, bound)
    return copied


@dataclass(frozen=True)
class PublicKey:
    params: MatrixParams
    A: ModMatrix
    T: ModMatrix

    def __post_init__(self):
        if not isinstance(self.params, MatrixParams):
            raise TypeError("expected MatrixParams")
        p = self.params
        _check_mod_matrix(self.A, p.n, p.m, p.q)
        _check_mod_matrix(self.T, p.n, p.k, p.q)

    def to_bytes(self):
        self.__post_init__()
        return _frame(b"PUBLIC", [self.params.to_bytes(), self.A.to_bytes(), self.T.to_bytes()])

    @property
    def context(self):
        return hashlib.shake_256(encode_bytes(b"LUO-PUBLIC-CONTEXT") + self.to_bytes()).digest(32)

    @classmethod
    def from_bytes(cls, raw):
        parameters, a, t = _unframe(raw, b"PUBLIC", 3)
        p = MatrixParams.from_bytes(parameters)
        return cls(p, _mod_matrix(a, p.n, p.m, p.q), _mod_matrix(t, p.n, p.k, p.q))


@dataclass(frozen=True, repr=False)
class SigningKey:
    public: PublicKey
    identity: bytes
    Z: tuple[tuple[int, ...], ...]
    W: ModMatrix

    def __post_init__(self):
        if not isinstance(self.public, PublicKey):
            raise TypeError("expected PublicKey")
        p = self.public.params
        object.__setattr__(self, "identity", _bytes(
            self.identity, "identity", p.identity_max_bytes, nonempty=True))
        object.__setattr__(self, "Z", _integer_matrix(self.Z, p.m, p.k, p.gamma1 - p.beta1))
        _check_mod_matrix(self.W, p.n, p.k, p.q)

    def __repr__(self):
        return f"SigningKey(identity_bytes={len(self.identity)}, security_claim='none')"

    def to_bytes(self):
        _validate_key(self)
        return _frame(b"USER-PRIVATE", [self.public.to_bytes(), self.identity,
                                       _pack_integer_matrix(self.Z), self.W.to_bytes()])

    @classmethod
    def from_bytes(cls, raw):
        public, identity, z, w = _unframe(raw, b"USER-PRIVATE", 4)
        pk = PublicKey.from_bytes(public)
        p = pk.params
        key = cls(pk, identity, _unpack_integer_matrix(z, p.m, p.k, p.gamma1 - p.beta1),
                  _mod_matrix(w, p.n, p.k, p.q))
        _validate_key(key)
        return key


@dataclass(frozen=True)
class Signature:
    context: bytes
    z: tuple[int, ...]
    c: tuple[int, ...]
    W: ModMatrix

    def __post_init__(self):
        object.__setattr__(self, "z", tuple(self.z))
        object.__setattr__(self, "c", tuple(self.c))

    def to_bytes(self):
        context = _bytes(self.context, "context", 32)
        if len(context) != 32 or not isinstance(self.W, ModMatrix):
            raise ValueError("invalid signature context or matrix")
        return _frame(b"SIGNATURE", [context, _pack_integers(self.z),
                                     _pack_integers(self.c), self.W.to_bytes()])

    @classmethod
    def from_bytes(cls, public: PublicKey, raw):
        context, z, c, w = _unframe(raw, b"SIGNATURE", 4)
        p = public.params
        sig = cls(context, _unpack_integers(z, p.m, p.gamma2 - p.beta2 - 1),
                  _unpack_integers(c, p.k, 1), _mod_matrix(w, p.n, p.k, p.q))
        _validate_signature(public, sig)
        return sig


@dataclass(repr=False)
class MasterState:
    public: PublicKey
    S: tuple[tuple[int, ...], ...]
    _cache: dict[bytes, SigningKey] = field(default_factory=dict, repr=False)

    def __post_init__(self):
        if not isinstance(self.public, PublicKey):
            raise TypeError("expected PublicKey")
        p = self.public.params
        self.S = _integer_matrix(self.S, p.m, p.k, p.eta)
        if self.public.A @ ModMatrix(self.S, p.q) != self.public.T:
            raise ValueError("master public equation does not hold")

    def __repr__(self):
        return f"MasterState(cached_identities={len(self._cache)}, security_claim='none')"

    @property
    def cached_identities(self):
        return tuple(sorted(self._cache))

    def to_bytes(self):
        self.__post_init__()
        p = self.public.params
        if len(self._cache) > p.max_cached_identities:
            raise ValueError("too many cached identities")
        body = struct.pack(">I", len(self._cache))
        for identity in sorted(self._cache):
            key = self._cache[identity]
            if identity != key.identity or key.public.context != self.public.context:
                raise ValueError("cached key context or identity mismatch")
            body += encode_bytes(key.to_bytes())
        return _frame(b"MASTER-PRIVATE", [self.public.to_bytes(),
                                         _pack_integer_matrix(self.S), body])

    @classmethod
    def from_bytes(cls, raw):
        public, secret, cache = _unframe(raw, b"MASTER-PRIVATE", 3)
        pk = PublicKey.from_bytes(public)
        p = pk.params
        master = cls(pk, _unpack_integer_matrix(secret, p.m, p.k, p.eta))
        if len(cache) < 4:
            raise ValueError("truncated identity count")
        count = int.from_bytes(cache[:4], "big")
        if count > p.max_cached_identities:
            raise ValueError("too many cached identities")
        offset, previous = 4, None
        for _ in range(count):
            encoded, offset = decode_bytes(cache, offset)
            key = SigningKey.from_bytes(encoded)
            if key.public.to_bytes() != pk.to_bytes() or (previous is not None and key.identity <= previous):
                raise ValueError("cross-context, duplicate or unordered cached identity")
            master._cache[key.identity] = key
            previous = key.identity
        if offset != len(cache):
            raise ValueError("appended cached entries")
        return master


class _HashReader:
    def __init__(self, domain: bytes, fields):
        material = encode_bytes(domain) + encode_bytes(VERSION)
        material += b"".join(encode_bytes(x) for x in fields)
        self._state = hashlib.shake_256(material)
        self._offset = 0

    def read(self, count):
        if self._offset + count > 65536:
            raise SamplingAbort("hash expansion budget exhausted")
        end = self._offset + count
        result = self._state.digest(end)[self._offset:end]
        self._offset = end
        return result


def uniform_below(rng, bound: int, *, attempts: int = 64) -> int:
    """Unbiased bit-mask/rejection draw; modulo reduction is not used."""
    _integer(bound, "bound", 1, 2**33)
    _integer(attempts, "attempts", 1, 256)
    if bound == 1:
        return 0
    bits = (bound - 1).bit_length()
    count, mask = (bits + 7) // 8, (1 << bits) - 1
    for _ in range(attempts):
        raw = rng.read(count)
        if not isinstance(raw, bytes) or len(raw) != count:
            raise TypeError("random source must return exactly the requested bytes")
        value = int.from_bytes(raw, "big") & mask
        if value < bound:
            return value
    raise SamplingAbort("uniform draw budget exhausted")


def _uniform_mask(rng, bound: int, count: int, attempts: int):
    return tuple(uniform_below(rng, 2 * bound + 1, attempts=attempts) - bound for _ in range(count))


def _sparse_challenge(reader, length: int, weight: int, attempts: int):
    positions = list(range(length))
    result = [0] * length
    for _ in range(weight):
        index = uniform_below(reader, len(positions), attempts=attempts)
        position = positions.pop(index)
        result[position] = 2 * uniform_below(reader, 2, attempts=attempts) - 1
    return tuple(result)


def hash_h1(public: PublicKey, identity: bytes, W: ModMatrix):
    """Matrix-valued H1 with independent fixed-weight signed columns."""
    p = public.params
    identity = _bytes(identity, "identity", p.identity_max_bytes, nonempty=True)
    _check_mod_matrix(W, p.n, p.k, p.q)
    fields = [public.context, identity, W.to_bytes()]
    columns = [_sparse_challenge(_HashReader(b"LUO-H1-COLUMN", fields + [struct.pack(">I", j)]),
                                 p.k, p.kappa, p.max_uniform_attempts) for j in range(p.k)]
    return tuple(tuple(columns[j][i] for j in range(p.k)) for i in range(p.k))


def hash_h2(public: PublicKey, identity: bytes, commitment: ModVector, message: bytes):
    p = public.params
    identity = _bytes(identity, "identity", p.identity_max_bytes, nonempty=True)
    message = _bytes(message, "message", p.message_max_bytes)
    if not isinstance(commitment, ModVector) or commitment.q != p.q or commitment.length != p.n:
        raise ValueError("wrong commitment dimensions or modulus")
    reader = _HashReader(b"LUO-H2-MESSAGE", [public.context, identity, commitment.to_bytes(), message])
    return _sparse_challenge(reader, p.k, p.kappa, p.max_uniform_attempts)


def _int_product(a, b):
    """Integer product without reducing/lifting secret coefficients mod q."""
    columns = tuple(zip(*b))
    return tuple(tuple(sum(x * y for x, y in zip(row, col)) for col in columns) for row in a)


def _validate_key(key: SigningKey):
    key.__post_init__()
    p, pk = key.public.params, key.public
    challenge = hash_h1(pk, key.identity, key.W)
    if pk.A @ ModMatrix(key.Z, p.q) != key.W + pk.T @ ModMatrix(challenge, p.q):
        raise ValueError("user key equation does not hold")


def _validate_signature(public: PublicKey, signature: Signature):
    p = public.params
    if not isinstance(signature, Signature) or signature.context != public.context:
        raise ValueError("wrong signature context")
    if len(signature.z) != p.m or len(signature.c) != p.k:
        raise ValueError("wrong signature dimensions")
    for x in signature.z:
        _integer(x, "signature coefficient", -(p.gamma2 - p.beta2 - 1), p.gamma2 - p.beta2 - 1)
    for x in signature.c:
        _integer(x, "challenge coefficient", -1, 1)
    if sum(abs(x) for x in signature.c) != p.kappa:
        raise ValueError("wrong challenge weight")
    _check_mod_matrix(signature.W, p.n, p.k, p.q)


def setup(params: MatrixParams = MatrixParams(), *, rng=None):
    """Algorithm 1: exact uniform public matrix and bounded secret entries."""
    if not isinstance(params, MatrixParams):
        raise TypeError("expected MatrixParams")
    random = SecureRandom() if rng is None else rng
    A = ModMatrix([[uniform_below(random, params.q, attempts=params.max_uniform_attempts)
                    for _ in range(params.m)] for _ in range(params.n)], params.q)
    S = tuple(_uniform_mask(random, params.eta, params.k, params.max_uniform_attempts)
              for _ in range(params.m))
    public = PublicKey(params, A, A @ ModMatrix(S, params.q))
    return public, MasterState(public, S)


def key_extract(master: MasterState, identity: bytes, *, rng=None):
    """Algorithm 2 plus the R1 persistent identity-cache interpretation."""
    if not isinstance(master, MasterState):
        raise TypeError("expected MasterState")
    p, pk = master.public.params, master.public
    identity = _bytes(identity, "identity", p.identity_max_bytes, nonempty=True)
    if identity in master._cache:
        return master._cache[identity]
    if len(master._cache) >= p.max_cached_identities:
        raise SamplingAbort("identity cache budget exhausted")
    random = SecureRandom() if rng is None else rng
    for _ in range(p.max_extract_attempts):
        Y = tuple(_uniform_mask(random, p.gamma1, p.k, p.max_uniform_attempts) for _ in range(p.m))
        W = pk.A @ ModMatrix(Y, p.q)
        SC = _int_product(master.S, hash_h1(pk, identity, W))
        Z = tuple(tuple(x + y for x, y in zip(row_x, row_y)) for row_x, row_y in zip(SC, Y))
        if max(abs(x) for row in Z for x in row) <= p.gamma1 - p.beta1:
            key = SigningKey(pk, identity, Z, W)
            _validate_key(key)
            master._cache[identity] = key
            return key
    raise SamplingAbort("key extraction budget exhausted")


def sign(key: SigningKey, message: bytes, *, rng=None):
    """Algorithm 3: fresh masks for each message, strict norm rejection."""
    if not isinstance(key, SigningKey):
        raise TypeError("expected SigningKey")
    _validate_key(key)
    p, pk = key.public.params, key.public
    message = _bytes(message, "message", p.message_max_bytes)
    random = SecureRandom() if rng is None else rng
    for _ in range(p.max_sign_attempts):
        y = _uniform_mask(random, p.gamma2, p.m, p.max_uniform_attempts)
        c = hash_h2(pk, key.identity, pk.A @ ModVector(y, p.q), message)
        z = tuple(sum(a * b for a, b in zip(row, c)) + yi for row, yi in zip(key.Z, y))
        if max(abs(x) for x in z) < p.gamma2 - p.beta2:
            return Signature(pk.context, z, c, key.W)
    raise SamplingAbort("signing budget exhausted")


def verify(public: PublicKey, identity: bytes, message: bytes, signature: Signature) -> bool:
    """Algorithm 4; verification uses no master, key directory or user cache."""
    try:
        if not isinstance(public, PublicKey):
            return False
        public.__post_init__()
        p = public.params
        identity = _bytes(identity, "identity", p.identity_max_bytes, nonempty=True)
        message = _bytes(message, "message", p.message_max_bytes)
        _validate_signature(public, signature)
        public_user = signature.W + public.T @ ModMatrix(hash_h1(public, identity, signature.W), p.q)
        commitment = public.A @ ModVector(signature.z, p.q) - public_user @ ModVector(signature.c, p.q)
        return signature.c == hash_h2(public, identity, commitment, message)
    except (TypeError, ValueError, IBMEError, OverflowError, SamplingAbort):
        return False


def sign_for_identity(master: MasterState, identity: bytes, message: bytes, *, rng=None):
    """Research oracle: key and signature calls share the same persistent cache."""
    key = key_extract(master, identity, rng=rng)
    return sign(key, message, rng=rng)
