"""Five strict Lai objects: public key, master secret, two secret keys, ciphertext.

Ring elements are tuples of ``n`` canonical coefficients in ``[0, q)``.  The
objects are Sage-free so registry discovery and CLI state parsing work without
loading the arithmetic engine; actual operations import it lazily.
"""
from __future__ import annotations

from dataclasses import dataclass

from ibme.core.errors import InvalidParameterError, SerializationError
from . import codec
from .params import LaiParams


def _check_ring(value, params: LaiParams, name: str) -> tuple:
    if type(value) is not tuple or len(value) != params.n:
        raise InvalidParameterError(f"{name} must have {params.n} coefficients")
    if any(type(c) is not int or not 0 <= c < params.q for c in value):
        raise InvalidParameterError(f"{name} coefficient out of range")
    return value


def _check_vector(value, params: LaiParams, length: int, name: str) -> tuple:
    if type(value) is not tuple or len(value) != length:
        raise InvalidParameterError(f"{name} must have {length} ring elements")
    for element in value:
        _check_ring(element, params, name)
    return value


def _check_matrix(value, params: LaiParams, rows: int, columns: int, name: str) -> tuple:
    if type(value) is not tuple or len(value) != rows:
        raise InvalidParameterError(f"{name} must have {rows} rows")
    for row in value:
        if type(row) is not tuple or len(row) != columns:
            raise InvalidParameterError(f"{name} must be {rows}x{columns}")
        for element in row:
            _check_ring(element, params, name)
    return value


def _check_identity(value: bytes, params: LaiParams, name: str) -> bytes:
    if type(value) is not bytes or not 1 <= len(value) <= params.identity_bytes:
        raise InvalidParameterError(
            f"{name} must be non-empty bytes of at most {params.identity_bytes}")
    return value


def _write_public(params: LaiParams, a, u) -> bytes:
    body = bytearray(codec.params_bytes(params))
    body.extend(codec.vector_bytes(a, params))
    body.extend(len(u).to_bytes(2, "big"))
    for vector in u:
        body.extend(codec.vector_bytes(vector, params))
    return bytes(body)


def _read_public(data: bytes, offset: int):
    params, offset = codec.read_params(data, offset)
    a, offset = codec.read_vector(data, offset, params, expected=params.l + params.k)
    if offset + 2 > len(data):
        raise SerializationError("truncated Lai public u count")
    count = int.from_bytes(data[offset:offset + 2], "big")
    offset += 2
    if count != 3:
        raise SerializationError("Lai public key must carry three u vectors")
    u = []
    for _ in range(count):
        vector, offset = codec.read_vector(data, offset, params, expected=params.k)
        u.append(vector)
    return params, a, tuple(u), offset


@dataclass(frozen=True)
class LaiPublicKey:
    params: LaiParams
    a: tuple
    u: tuple

    def __post_init__(self) -> None:
        if type(self.params) is not LaiParams:
            raise InvalidParameterError("LaiPublicKey requires LaiParams")
        _check_vector(self.a, self.params, self.params.l + self.params.k, "a")
        if type(self.u) is not tuple or len(self.u) != 3:
            raise InvalidParameterError("LaiPublicKey requires three u vectors")
        for vector in self.u:
            _check_vector(vector, self.params, self.params.k, "u")

    def to_bytes(self) -> bytes:
        return codec.pack(codec.MAGIC_PK, _write_public(self.params, self.a, self.u))

    @classmethod
    def from_bytes(cls, data: bytes) -> "LaiPublicKey":
        body = codec.unpack(data, codec.MAGIC_PK, "LaiPublicKey")
        params, a, u, offset = _read_public(body, 0)
        if offset != len(body):
            raise SerializationError("LaiPublicKey: trailing bytes")
        return cls(params, a, u)


@dataclass(frozen=True, repr=False)
class LaiMasterSecret:
    public_key: LaiPublicKey
    trapdoor: tuple

    def __post_init__(self) -> None:
        if type(self.public_key) is not LaiPublicKey:
            raise InvalidParameterError("LaiMasterSecret requires a public key")
        p = self.public_key.params
        _check_matrix(self.trapdoor, p, p.l, p.k, "master trapdoor")

    @property
    def params(self) -> LaiParams:
        return self.public_key.params

    def __repr__(self) -> str:
        return "LaiMasterSecret(<redacted>)"

    def to_bytes(self) -> bytes:
        pk = self.public_key
        body = _write_public(pk.params, pk.a, pk.u)
        body += codec.matrix_bytes(self.trapdoor, pk.params)
        return codec.pack(codec.MAGIC_MSK, body)

    @classmethod
    def from_bytes(cls, data: bytes) -> "LaiMasterSecret":
        body = codec.unpack(data, codec.MAGIC_MSK, "LaiMasterSecret")
        params, a, u, offset = _read_public(body, 0)
        trapdoor, offset = codec.read_matrix(
            body, offset, params, expected=(params.l, params.k))
        if offset != len(body):
            raise SerializationError("LaiMasterSecret: trailing bytes")
        return cls(LaiPublicKey(params, a, u), trapdoor)


@dataclass(frozen=True, repr=False)
class LaiLevel1SecretKey:
    public_key: LaiPublicKey
    identity: bytes
    tag: tuple
    base: tuple
    a_id: tuple
    trapdoor: tuple

    def __post_init__(self) -> None:
        if type(self.public_key) is not LaiPublicKey:
            raise InvalidParameterError("LaiLevel1SecretKey requires a public key")
        p = self.public_key.params
        _check_identity(self.identity, p, "identity")
        _check_ring(self.tag, p, "tag")
        _check_vector(self.base, p, p.l + p.k, "base")
        _check_vector(self.a_id, p, p.k, "a_id")
        _check_matrix(self.trapdoor, p, p.l + p.k, p.k, "level-1 trapdoor")

    @property
    def params(self) -> LaiParams:
        return self.public_key.params

    def __repr__(self) -> str:
        return f"LaiLevel1SecretKey(identity={self.identity!r}, <redacted>)"

    def to_bytes(self) -> bytes:
        pk = self.public_key
        body = _write_public(pk.params, pk.a, pk.u)
        body += codec.identity_bytes(self.identity)
        body += codec.ring_bytes(self.tag, pk.params)
        body += codec.vector_bytes(self.base, pk.params)
        body += codec.vector_bytes(self.a_id, pk.params)
        body += codec.matrix_bytes(self.trapdoor, pk.params)
        return codec.pack(codec.MAGIC_SK1, body)

    @classmethod
    def from_bytes(cls, data: bytes) -> "LaiLevel1SecretKey":
        body = codec.unpack(data, codec.MAGIC_SK1, "LaiLevel1SecretKey")
        params, a, u, offset = _read_public(body, 0)
        identity, offset = codec.read_identity(body, offset)
        tag, offset = codec.read_ring(body, offset, params)
        base, offset = codec.read_vector(body, offset, params,
                                         expected=params.l + params.k)
        a_id, offset = codec.read_vector(body, offset, params, expected=params.k)
        trapdoor, offset = codec.read_matrix(
            body, offset, params, expected=(params.l + params.k, params.k))
        if offset != len(body):
            raise SerializationError("LaiLevel1SecretKey: trailing bytes")
        return cls(LaiPublicKey(params, a, u), identity, tag, base, a_id, trapdoor)


@dataclass(frozen=True, repr=False)
class LaiLevel2SecretKey:
    public_key: LaiPublicKey
    parent_identity: bytes
    child_identity: bytes
    tag: tuple
    base: tuple
    a_id: tuple
    trapdoor: tuple

    def __post_init__(self) -> None:
        if type(self.public_key) is not LaiPublicKey:
            raise InvalidParameterError("LaiLevel2SecretKey requires a public key")
        p = self.public_key.params
        _check_identity(self.parent_identity, p, "parent_identity")
        _check_identity(self.child_identity, p, "child_identity")
        _check_ring(self.tag, p, "tag")
        _check_vector(self.base, p, p.l + 2 * p.k, "base")
        _check_vector(self.a_id, p, p.k, "a_id")
        _check_matrix(self.trapdoor, p, p.l + 2 * p.k, p.k, "level-2 trapdoor")

    @property
    def params(self) -> LaiParams:
        return self.public_key.params

    def __repr__(self) -> str:
        return (f"LaiLevel2SecretKey(parent={self.parent_identity!r}, "
                f"child={self.child_identity!r}, <redacted>)")

    def to_bytes(self) -> bytes:
        pk = self.public_key
        body = _write_public(pk.params, pk.a, pk.u)
        body += codec.identity_bytes(self.parent_identity)
        body += codec.identity_bytes(self.child_identity)
        body += codec.ring_bytes(self.tag, pk.params)
        body += codec.vector_bytes(self.base, pk.params)
        body += codec.vector_bytes(self.a_id, pk.params)
        body += codec.matrix_bytes(self.trapdoor, pk.params)
        return codec.pack(codec.MAGIC_SK2, body)

    @classmethod
    def from_bytes(cls, data: bytes) -> "LaiLevel2SecretKey":
        body = codec.unpack(data, codec.MAGIC_SK2, "LaiLevel2SecretKey")
        params, a, u, offset = _read_public(body, 0)
        parent, offset = codec.read_identity(body, offset)
        child, offset = codec.read_identity(body, offset)
        tag, offset = codec.read_ring(body, offset, params)
        base, offset = codec.read_vector(body, offset, params,
                                         expected=params.l + 2 * params.k)
        a_id, offset = codec.read_vector(body, offset, params, expected=params.k)
        trapdoor, offset = codec.read_matrix(
            body, offset, params, expected=(params.l + 2 * params.k, params.k))
        if offset != len(body):
            raise SerializationError("LaiLevel2SecretKey: trailing bytes")
        return cls(LaiPublicKey(params, a, u), parent, child, tag, base, a_id,
                   trapdoor)


@dataclass(frozen=True)
class LaiCiphertext:
    params: LaiParams
    level: int
    hprime: tuple
    u: tuple
    v: tuple

    def __post_init__(self) -> None:
        if type(self.params) is not LaiParams:
            raise InvalidParameterError("LaiCiphertext requires LaiParams")
        if self.level not in (1, 2):
            raise InvalidParameterError("Lai ciphertext level must be 1 or 2")
        _check_ring(self.hprime, self.params, "hprime")
        _check_vector(self.u, self.params,
                      self.params.l + self.level * self.params.k, "u")
        _check_vector(self.v, self.params, self.params.k, "v")

    def to_bytes(self) -> bytes:
        body = bytearray(codec.params_bytes(self.params))
        body.append(self.level)
        body.extend(codec.ring_bytes(self.hprime, self.params))
        body.extend(codec.vector_bytes(self.u, self.params))
        body.extend(codec.vector_bytes(self.v, self.params))
        return codec.pack(codec.MAGIC_CT, bytes(body))

    @classmethod
    def from_bytes(cls, data: bytes) -> "LaiCiphertext":
        body = codec.unpack(data, codec.MAGIC_CT, "LaiCiphertext")
        params, offset = codec.read_params(body, 0)
        if offset >= len(body):
            raise SerializationError("truncated Lai ciphertext level")
        level = body[offset]
        offset += 1
        if level not in (1, 2):
            raise SerializationError("invalid Lai ciphertext level")
        hprime, offset = codec.read_ring(body, offset, params)
        u, offset = codec.read_vector(body, offset, params,
                                      expected=params.l + level * params.k)
        v, offset = codec.read_vector(body, offset, params, expected=params.k)
        if offset != len(body):
            raise SerializationError("LaiCiphertext: trailing bytes")
        return cls(params, level, hprime, u, v)
