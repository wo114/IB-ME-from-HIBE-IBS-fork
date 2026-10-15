"""Strict binary wire helpers for the Sageloli research objects.

The codec deliberately contains no sampling or protocol logic.  Every field
is length prefixed, object kinds and versions are explicit, and top-level
decoders reject truncation, unknown/repeated fields and trailing bytes.
The format is a research wire format; it does not authenticate state or
upgrade the security status of either Sageloli profile.
"""

from __future__ import annotations

from ibme.core.errors import SerializationError

MAGIC = b"IBME:SAGELOLI-IBS:v1"
MAX_WIRE_BYTES = 16 * 2**20
MAX_FIELDS = 32
MAX_FIELD_BYTES = MAX_WIRE_BYTES
MAX_DIMENSION = 4096
_U32 = 4
_U64 = 8
_U128 = 16
_I64_MIN = -(1 << 63)
_I64_MAX = (1 << 63) - 1


def _bytes(value, what="bytes"):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise SerializationError(f"{what} must be bytes-like")
    return bytes(value)


def u32(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 2**32:
        raise SerializationError("uint32 value out of range")
    return value.to_bytes(_U32, "big")


def u64(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 2**64:
        raise SerializationError("uint64 value out of range")
    return value.to_bytes(_U64, "big")


def u128(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 2**128:
        raise SerializationError("uint128 value out of range")
    return value.to_bytes(_U128, "big")


def read_u32(raw: bytes, offset: int = 0) -> tuple[int, int]:
    raw = _bytes(raw, "buffer")
    if type(offset) is not int or offset < 0 or offset > len(raw) or len(raw) - offset < _U32:
        raise SerializationError("truncated uint32")
    return int.from_bytes(raw[offset:offset + _U32], "big"), offset + _U32


def read_u64(raw: bytes, offset: int = 0) -> tuple[int, int]:
    raw = _bytes(raw, "buffer")
    if type(offset) is not int or offset < 0 or offset > len(raw) or len(raw) - offset < _U64:
        raise SerializationError("truncated uint64")
    return int.from_bytes(raw[offset:offset + _U64], "big"), offset + _U64


def blob(value) -> bytes:
    value = _bytes(value)
    if len(value) > 2**32 - 1:
        raise SerializationError("length-prefixed field exceeds uint32")
    return u32(len(value)) + value


def read_blob(raw: bytes, offset: int = 0, *, what="field") -> tuple[bytes, int]:
    raw = _bytes(raw, "buffer")
    length, offset = read_u32(raw, offset)
    if length > len(raw) - offset:
        raise SerializationError(f"truncated {what}")
    return raw[offset:offset + length], offset + length


def encode(kind: bytes | str, *fields: bytes) -> bytes:
    """Encode one object as ``MAGIC || kind || LP(fields...)``."""
    if isinstance(kind, str):
        kind = kind.encode("ascii")
    kind = _bytes(kind, "object kind")
    if not kind or len(fields) > MAX_FIELDS:
        raise SerializationError("invalid object kind/field count")
    result = bytearray(MAGIC + blob(kind) + u32(len(fields)))
    for field in fields:
        result.extend(blob(field))
    if len(result) > MAX_WIRE_BYTES:
        raise SerializationError("Sageloli wire budget exceeded")
    return bytes(result)


def decode(raw, kind: bytes | str, count: int) -> tuple[bytes, ...]:
    """Strictly decode one object and require the exact expected field count."""
    raw = _bytes(raw, "object")
    if len(raw) > MAX_WIRE_BYTES:
        raise SerializationError("Sageloli wire budget exceeded")
    if isinstance(kind, str):
        kind = kind.encode("ascii")
    kind = _bytes(kind, "object kind")
    if type(count) is not int or not 0 <= count <= MAX_FIELDS:
        raise SerializationError("invalid field count")
    if not raw.startswith(MAGIC):
        raise SerializationError("Sageloli object/version mismatch")
    pos = len(MAGIC)
    actual, pos = read_blob(raw, pos, what="object kind")
    if actual != kind:
        raise SerializationError("Sageloli object kind mismatch")
    actual_count, pos = read_u32(raw, pos)
    if actual_count != count:
        raise SerializationError("Sageloli field count mismatch")
    values = []
    for index in range(count):
        value, pos = read_blob(raw, pos, what=f"field {index}")
        if len(value) > MAX_FIELD_BYTES:
            raise SerializationError("Sageloli field exceeds wire budget")
        values.append(value)
    if pos != len(raw):
        raise SerializationError("trailing or duplicated Sageloli fields")
    return tuple(values)


def pack_ints(values, *, signed=True) -> bytes:
    """Pack a finite integer sequence using fixed-width canonical int64s."""
    if not isinstance(values, (tuple, list)) or len(values) > MAX_DIMENSION**2:
        raise SerializationError("integer sequence exceeds dimension budget")
    output = bytearray(u32(len(values)))
    for value in values:
        if type(value) is not int:
            raise SerializationError("integer coefficient must be an int")
        if signed:
            if not _I64_MIN <= value <= _I64_MAX:
                raise SerializationError("signed coefficient outside int64")
            output.extend(value.to_bytes(8, "big", signed=True))
        else:
            if not 0 <= value <= _I64_MAX:
                raise SerializationError("unsigned coefficient outside int64")
            output.extend(value.to_bytes(8, "big"))
    return bytes(output)


def unpack_ints(raw, *, expected=None, signed=True) -> tuple[int, ...]:
    raw = _bytes(raw, "integer sequence")
    count, pos = read_u32(raw)
    if count > MAX_DIMENSION**2 or (expected is not None and count != expected):
        raise SerializationError("integer sequence length mismatch")
    if len(raw) - pos != count * 8:
        raise SerializationError("integer sequence byte length mismatch")
    return tuple(int.from_bytes(raw[pos + 8*i:pos + 8*i + 8], "big", signed=signed)
                 for i in range(count))


def pack_matrix(rows, *, expected=None, signed=True) -> bytes:
    if not isinstance(rows, (tuple, list)) or not rows:
        raise SerializationError("matrix must be non-empty")
    if any(not isinstance(row, (tuple, list)) for row in rows):
        raise SerializationError("matrix rows must be sequences")
    row_count, col_count = len(rows), len(rows[0])
    if not 1 <= row_count <= MAX_DIMENSION or not 1 <= col_count <= MAX_DIMENSION:
        raise SerializationError("matrix dimensions exceed budget")
    if any(len(row) != col_count for row in rows):
        raise SerializationError("matrix must be rectangular")
    if expected is not None and (row_count, col_count) != tuple(expected):
        raise SerializationError("matrix dimensions do not match parameters")
    flat = [value for row in rows for value in row]
    return u32(row_count) + u32(col_count) + pack_ints(flat, signed=signed)


def unpack_matrix(raw, *, expected=None, signed=True) -> tuple[tuple[int, ...], ...]:
    raw = _bytes(raw, "matrix")
    rows, pos = read_u32(raw)
    cols, pos = read_u32(raw, pos)
    if not 1 <= rows <= MAX_DIMENSION or not 1 <= cols <= MAX_DIMENSION:
        raise SerializationError("matrix dimensions exceed budget")
    flat = unpack_ints(raw[pos:], expected=rows * cols, signed=signed)
    if pos + len(raw[pos:]) != len(raw):
        raise SerializationError("matrix trailing bytes")
    return tuple(tuple(flat[i * cols:(i + 1) * cols]) for i in range(rows))


def pack_params(values) -> bytes:
    if not isinstance(values, (tuple, list)) or not values or len(values) > MAX_FIELDS:
        raise SerializationError("invalid parameter tuple")
    # Widths in the paper are recorded as squares (the RSIS debug profile uses
    # 2**66), so parameter scalars use a fixed unsigned 128-bit slot.
    return u32(len(values)) + b"".join(u128(value) for value in values)


def unpack_params(raw, *, expected=None) -> tuple[int, ...]:
    raw = _bytes(raw, "parameters")
    count, pos = read_u32(raw)
    if count > MAX_FIELDS or (expected is not None and count != expected):
        raise SerializationError("parameter field count mismatch")
    if len(raw) - pos != count * _U128:
        raise SerializationError("parameter byte length mismatch")
    return tuple(int.from_bytes(raw[pos + i*_U128:pos + (i+1)*_U128], "big") for i in range(count))


__all__ = [
    "MAGIC", "MAX_WIRE_BYTES", "encode", "decode", "blob", "read_blob",
    "pack_ints", "unpack_ints", "pack_matrix", "unpack_matrix",
    "pack_params", "unpack_params", "u32", "u64", "u128", "read_u32", "read_u64",
]
