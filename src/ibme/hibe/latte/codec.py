"""Bounded canonical records. Private records must never enter public receipts."""
import json
from ibme.core.errors import SerializationError,EncodingError,InvalidParameterError
from .params import N, Q, VERSION

MAX_WIRE = 16 * 2**20


def canonical(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def write(record):
    raw = canonical(record)
    if len(raw) > MAX_WIRE:
        raise SerializationError("LATTE whole snapshot exceeds byte limit")
    return raw


def read(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_WIRE:
        raise SerializationError("LATTE bounded snapshot bytes required")
    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result:
                raise ValueError("duplicate field")
            result[k] = v
        return result
    def integer(text):
        if len(text) > 22:
            raise ValueError("integer resource budget")
        return int(text)
    def reject(value):
        raise ValueError("floating point or nonfinite number")
    try:
        record = json.loads(raw.decode("ascii"), object_pairs_hook=unique,
            parse_int=integer, parse_float=reject, parse_constant=reject)
        if write(record) != raw:
            raise ValueError("noncanonical record")
        return record
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise SerializationError("invalid canonical LATTE snapshot") from None


def fields(value, kind, names):
    if (type(value) is not dict or set(value) != {"schema", *names} or
            value["schema"] != VERSION + "/" + kind):
        raise ValueError("LATTE object version or field set")


def poly(value, *, private=False):
    if type(value) not in (tuple, list) or len(value) != N:
        raise ValueError("LATTE polynomial dimension")
    bound = 2**50 if private else Q
    for v in value:
        if type(v) is not int or (not -bound < v < bound if private else not 0 <= v < Q):
            raise ValueError("LATTE polynomial integer/residue bounds")
    return tuple(value)


def polynomials(values, count, *, private=False):
    if type(values) not in (tuple, list) or len(values) != count:
        raise ValueError("LATTE polynomial collection dimension")
    return tuple(poly(v, private=private) for v in values)


def hexadecimal(value, size):
    if type(value) is not str or len(value) != 2*size:
        raise ValueError("LATTE fixed hex field")
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise ValueError("LATTE hex field") from None
    if raw.hex() != value:
        raise ValueError("LATTE noncanonical hex")
    return raw


def decode(raw, reader):
    try:
        return reader(read(raw))
    except SerializationError:
        raise
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError,EncodingError,InvalidParameterError):
        raise SerializationError("LATTE object validation failed") from None
