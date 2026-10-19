"""Strict, Sage-free binary codec for Lai objects."""
from __future__ import annotations

import struct

from ibme.core.errors import InvalidParameterError, SerializationError
from .params import LaiParams

MAGIC_PK = b"LAI1PK"
MAGIC_MSK = b"LAI1MS"
MAGIC_SK1 = b"LAI1K1"
MAGIC_SK2 = b"LAI1K2"
MAGIC_CT = b"LAI1CT"


def _uint(value: int, bits: int, name: str) -> bytes:
    if type(value) is not int or not 0 <= value < 2 ** bits:
        raise SerializationError(f"{name} does not fit uint{bits}")
    return value.to_bytes(bits // 8, "big")


def _read_uint(data: bytes, offset: int, bits: int, name: str) -> tuple[int, int]:
    size = bits // 8
    if offset + size > len(data):
        raise SerializationError(f"truncated {name}")
    return int.from_bytes(data[offset:offset + size], "big"), offset + size


def pack(magic: bytes, body: bytes) -> bytes:
    return magic + _uint(len(body), 32, "body length") + body


def unpack(data: bytes, magic: bytes, name: str) -> bytes:
    if type(data) is not bytes:
        raise SerializationError(f"{name} requires bytes")
    if len(data) < len(magic) + 4 or data[:len(magic)] != magic:
        raise SerializationError(f"{name}: bad magic")
    length, offset = _read_uint(data, len(magic), 32, "body length")
    if len(data) != offset + length:
        raise SerializationError(f"{name}: body length mismatch")
    return data[offset:]


def params_bytes(params: LaiParams) -> bytes:
    if type(params) is not LaiParams:
        raise SerializationError("Lai params object required")
    sigma = round(params.sigma * 1_000_000)
    sigma_r = round(params.sigma_r * 1_000_000)
    if sigma <= 0 or sigma_r <= 0:
        raise SerializationError("Lai sigma must be positive")
    mode = 0 if params.message_mode == "seed32" else 1
    return b"".join((
        _uint(params.q, 64, "q"), _uint(params.n, 16, "n"),
        _uint(params.k, 16, "k"), _uint(params.l, 16, "l"),
        _uint(params.p, 16, "p"), _uint(sigma, 32, "sigma"),
        _uint(sigma_r, 32, "sigma_r"),
        _uint(params.identity_bytes, 16, "identity_bytes"),
        _uint(params.max_message_bytes, 16, "max_message_bytes"),
        bytes([mode]),
    ))


def read_params(data: bytes, offset: int = 0) -> tuple[LaiParams, int]:
    q, offset = _read_uint(data, offset, 64, "q")
    n, offset = _read_uint(data, offset, 16, "n")
    k, offset = _read_uint(data, offset, 16, "k")
    l, offset = _read_uint(data, offset, 16, "l")
    p, offset = _read_uint(data, offset, 16, "p")
    sigma, offset = _read_uint(data, offset, 32, "sigma")
    sigma_r, offset = _read_uint(data, offset, 32, "sigma_r")
    identity_bytes, offset = _read_uint(data, offset, 16, "identity_bytes")
    max_message, offset = _read_uint(data, offset, 16, "max_message_bytes")
    if offset >= len(data):
        raise SerializationError("truncated message mode")
    mode = data[offset]
    offset += 1
    if mode not in (0, 1):
        raise SerializationError("invalid Lai message mode")
    try:
        params = LaiParams(q=q, n=n, k=k, l=l, p=p,
                           sigma=sigma / 1_000_000,
                           sigma_r=sigma_r / 1_000_000,
                           identity_bytes=identity_bytes,
                           max_message_bytes=max_message,
                           message_mode="seed32" if mode == 0 else "framed32")
    except InvalidParameterError as exc:
        raise SerializationError(f"invalid Lai parameter snapshot: {exc}") from exc
    return params, offset


def ring_bytes(value, params: LaiParams) -> bytes:
    if type(value) is not tuple or len(value) != params.n:
        raise SerializationError("Lai ring element has the wrong length")
    width = params.coefficient_bytes
    out = bytearray()
    for coefficient in value:
        if type(coefficient) is not int or not 0 <= coefficient < params.q:
            raise SerializationError("Lai ring coefficient out of range")
        out.extend(coefficient.to_bytes(width, "big"))
    return bytes(out)


def read_ring(data: bytes, offset: int, params: LaiParams) -> tuple[tuple[int, ...], int]:
    width = params.coefficient_bytes
    need = width * params.n
    if offset + need > len(data):
        raise SerializationError("truncated Lai ring element")
    values = tuple(
        int.from_bytes(data[offset + width * i:offset + width * (i + 1)], "big")
        for i in range(params.n)
    )
    if any(value >= params.q for value in values):
        raise SerializationError("Lai ring coefficient out of range")
    return values, offset + need


def vector_bytes(values, params: LaiParams) -> bytes:
    if type(values) is not tuple:
        raise SerializationError("Lai vector must be a tuple")
    return _uint(len(values), 16, "vector length") + b"".join(
        ring_bytes(value, params) for value in values)


def read_vector(data: bytes, offset: int, params: LaiParams,
                expected: int | None = None) -> tuple[tuple[tuple[int, ...], ...], int]:
    count, offset = _read_uint(data, offset, 16, "vector length")
    if expected is not None and count != expected:
        raise SerializationError(f"Lai vector must have {expected} entries")
    values = []
    for _ in range(count):
        value, offset = read_ring(data, offset, params)
        values.append(value)
    return tuple(values), offset


def matrix_bytes(rows, params: LaiParams) -> bytes:
    if type(rows) is not tuple or not rows or type(rows[0]) is not tuple:
        raise SerializationError("Lai matrix must be a non-empty tuple of rows")
    width = len(rows[0])
    if any(type(row) is not tuple or len(row) != width for row in rows):
        raise SerializationError("Lai matrix rows have inconsistent widths")
    return (_uint(len(rows), 16, "matrix rows")
            + _uint(width, 16, "matrix columns")
            + b"".join(ring_bytes(value, params) for row in rows for value in row))


def read_matrix(data: bytes, offset: int, params: LaiParams,
                expected: tuple[int, int] | None = None):
    rows, offset = _read_uint(data, offset, 16, "matrix rows")
    columns, offset = _read_uint(data, offset, 16, "matrix columns")
    if expected is not None and (rows, columns) != expected:
        raise SerializationError(
            f"Lai matrix must be {expected[0]}x{expected[1]}")
    if rows < 1 or columns < 1:
        raise SerializationError("Lai matrix must be non-empty")
    values = []
    for _ in range(rows):
        row = []
        for _ in range(columns):
            value, offset = read_ring(data, offset, params)
            row.append(value)
        values.append(tuple(row))
    return tuple(values), offset


def identity_bytes(value: bytes) -> bytes:
    if type(value) is not bytes or not value:
        raise SerializationError("Lai identity must be non-empty bytes")
    if len(value) > 65535:
        raise SerializationError("Lai identity is too long")
    return _uint(len(value), 16, "identity length") + value


def read_identity(data: bytes, offset: int) -> tuple[bytes, int]:
    length, offset = _read_uint(data, offset, 16, "identity length")
    if length == 0 or offset + length > len(data):
        raise SerializationError("invalid Lai identity length")
    return bytes(data[offset:offset + length]), offset + length
