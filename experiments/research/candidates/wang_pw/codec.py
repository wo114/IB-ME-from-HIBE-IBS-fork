"""Canonical bounded research wire; secret objects are plaintext trusted storage."""
import json

from ibme.core.errors import SerializationError

PREFIX = b"IBME-WANG-PW-v1:"
MAX_WIRE_BYTES = 2**20
MAX_COEFFICIENT = 2**63-1


def canonical(record):
    return json.dumps(record, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def encode(kind, record):
    result = PREFIX+kind.encode("ascii")+b"\x00"+canonical(record)
    if len(result) > MAX_WIRE_BYTES:
        raise ValueError("research object wire exceeds 1 MiB")
    return result


def decode(kind, data, fields):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise SerializationError("bounded bytes-like object required")
    try:
        size = data.nbytes if isinstance(data, memoryview) else len(data)
        if size > MAX_WIRE_BYTES:
            raise SerializationError("research object wire exceeds 1 MiB")
    except (ValueError, TypeError) as exc:
        raise SerializationError("invalid or released byte view") from exc
    raw, prefix = bytes(data), PREFIX+kind.encode("ascii")+b"\x00"
    if not raw.startswith(prefix):
        raise SerializationError("wrong object or algorithm version")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError("duplicate object field")
            result[key] = value
        return result
    try:
        record = json.loads(raw[len(prefix):], object_pairs_hook=unique)
        if not isinstance(record, dict) or set(record) != set(fields) or encode(kind, record) != raw:
            raise ValueError("noncanonical, unknown or missing fields")
        return record
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise SerializationError("invalid canonical research object") from exc


def matrix_rows(value, rows, cols, *, q=None):
    if not isinstance(value, (tuple, list)) or len(value) != rows:
        raise ValueError("matrix height mismatch")
    result = []
    for row in value:
        if not isinstance(row, (tuple, list)) or len(row) != cols:
            raise ValueError("matrix width mismatch")
        for x in row:
            if type(x) is not int or not (-MAX_COEFFICIENT <= x <= MAX_COEFFICIENT):
                raise ValueError("bounded signed integer coefficient required")
            if q is not None and not 0 <= x < q:
                raise ValueError("canonical mod-q coefficient required")
        result.append(tuple(row))
    return tuple(result)


def blob(value, length):
    if type(value) is not bytes or len(value) != length:
        raise ValueError("exact byte field length required")
    return value


def unhex(value):
    if type(value) is not str or len(value) > 2*MAX_WIRE_BYTES:
        raise ValueError("bounded hex string required")
    raw = bytes.fromhex(value)
    if raw.hex() != value: raise ValueError("noncanonical hex string")
    return raw
