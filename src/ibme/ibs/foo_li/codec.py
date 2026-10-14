"""Bounded canonical tagged objects. Secret encodings are plaintext."""
from dataclasses import asdict, fields
import json
import struct

from ibme.core.errors import SerializationError
from .params import FooLiParams

MAX_OBJECT = 16*1024*1024
PK_MAGIC = b"IBME:FOOLI:PK:1"
SK_MAGIC = b"IBME:FOOLI:SK:1"
MSK_MAGIC = b"IBME:FOOLI:MSK:1"
SIG_MAGIC = b"IBME:FOOLI:SIG:1"


def bounded_bytes(value, limit=MAX_OBJECT):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise SerializationError("Foo-Li object must be bytes-like")
    try:
        with memoryview(value) as view:
            if view.nbytes > limit:
                raise SerializationError("Foo-Li object exceeds resource limit")
            return view.tobytes()
    except ValueError as exc:
        raise SerializationError("invalid Foo-Li input buffer") from exc


def encode(magic, *values):
    raw = magic + b"".join(bytes([tag])+struct.pack(">I", len(v))+v
                           for tag, v in enumerate(values, 1))
    if len(raw) > MAX_OBJECT:
        raise SerializationError("Foo-Li object exceeds resource limit")
    return raw


def decode(data, magic, count, *, limit=MAX_OBJECT):
    data = bounded_bytes(data, limit)
    if not data.startswith(magic):
        raise SerializationError("Foo-Li magic/version mismatch")
    cursor, values = len(magic), []
    for tag in range(1, count+1):
        if cursor+5 > len(data) or data[cursor] != tag:
            raise SerializationError("Foo-Li missing, repeated or unordered tag")
        size = struct.unpack_from(">I", data, cursor+1)[0]
        cursor += 5
        if size > len(data)-cursor:
            raise SerializationError("truncated Foo-Li field")
        values.append(data[cursor:cursor+size])
        cursor += size
    if cursor != len(data):
        raise SerializationError("appended Foo-Li field")
    return values


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def parse_json(data):
    try:
        value = json.loads(data)
        if canonical(value) != data:
            raise ValueError("noncanonical JSON")
        return value
    except (ValueError, TypeError, RecursionError, UnicodeError) as exc:
        raise SerializationError("noncanonical Foo-Li JSON") from exc


def params_bytes(params): return canonical(asdict(params))


def parse_params(data):
    value = parse_json(bounded_bytes(data, 16384))
    if type(value) is not dict or set(value) != {f.name for f in fields(FooLiParams)}:
        raise SerializationError("Foo-Li requires a complete parameter snapshot")
    try:
        return FooLiParams(**value)
    except (ValueError, TypeError, ZeroDivisionError) as exc:
        raise SerializationError("invalid Foo-Li parameters") from exc


def pack_ints(values, *, signed):
    if any(type(x) is not int for x in values):
        raise SerializationError("Foo-Li coefficients must be exact Python integers")
    try:
        return b"".join(x.to_bytes(8 if signed else 4, "big", signed=signed) for x in values)
    except OverflowError as exc:
        raise SerializationError("Foo-Li coefficient out of wire range") from exc


def unpack_ints(data, count, *, signed):
    width = 8 if signed else 4
    if len(data) != count*width:
        raise SerializationError("Foo-Li coefficient count/width mismatch")
    return tuple(int.from_bytes(data[i:i+width], "big", signed=signed)
                 for i in range(0, len(data), width))
