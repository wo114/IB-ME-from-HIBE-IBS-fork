"""Canonical length-prefixed, domain-separated encodings.

Implements IMPLEMENTATION_SPEC section 1 exactly::

    encode_bytes(x)        = uint32_be(len(x)) || x
    encode_identity(id)    = DOMAIN_ID   || encode_bytes(id)
    encode_pair(a, b)      = DOMAIN_PAIR || encode_bytes(a) || encode_bytes(b)
    encode_message(id, m)  = DOMAIN_MSG  || encode_bytes(id) || encode_bytes(m)

Bare concatenation without a length prefix is forbidden everywhere.

Two decoder families are provided:

* ``decode_*(buffer, offset=0)`` parse one field starting at ``offset`` and
  return ``(value, new_offset)`` so callers can walk composite buffers;
* ``parse_*(buffer)`` are top-level exact parsers: they additionally reject
  any trailing bytes ("trailing garbage"), which is what makes duplicated or
  appended fields unambiguous failures.

Every malformed input -- wrong type, truncated length field, length field
larger than the available data, length values overflowing uint32, empty
identity, wrong domain prefix, trailing garbage -- raises
:class:`~ibme.core.errors.EncodingError`.  The decoder never allocates based
on a length field before checking it against the remaining buffer size.
"""

from __future__ import annotations

from .errors import EncodingError
from .hashing import DOMAIN_ID, DOMAIN_MSG, DOMAIN_PAIR
from .types import validate_bytes, validate_identity

_UINT32_SIZE = 4
_MAX_UINT32 = 0xFFFFFFFF
_BYTES_LIKE = (bytes, bytearray, memoryview)


def _u32be(n: int) -> bytes:
    return n.to_bytes(_UINT32_SIZE, "big")


# --------------------------------------------------------------------------
# Encoding
# --------------------------------------------------------------------------

def encode_bytes(x: bytes) -> bytes:
    """Encode a byte string with a uint32 big-endian length prefix.

    ``x`` may be empty (messages can be empty); identities are rejected by
    the dedicated :func:`encode_identity`.  Inputs longer than ``2**32 - 1``
    bytes cannot be represented and raise ``EncodingError``.  The limit is
    checked on the raw input *before* normalisation so that the guard is
    well-defined for every bytes-like input.
    """
    if isinstance(x, (bytes, bytearray, memoryview)) and len(x) > _MAX_UINT32:
        raise EncodingError(
            f"field of {len(x)} bytes exceeds the uint32 length limit"
        )
    data = validate_bytes(x, name="x")
    return _u32be(len(data)) + data


def encode_identity(identity: bytes) -> bytes:
    """Domain-separated canonical encoding of a non-empty identity."""
    ident = validate_identity(identity)
    return DOMAIN_ID + encode_bytes(ident)


def encode_pair(a: bytes, b: bytes) -> bytes:
    """Domain-separated canonical encoding of an ordered identity pair.

    The pair is ordered: ``encode_pair(a, b) != encode_pair(b, a)`` for
    distinct identities.  Both components must be non-empty.
    """
    first = validate_identity(a, name="a")
    second = validate_identity(b, name="b")
    return DOMAIN_PAIR + encode_bytes(first) + encode_bytes(second)


def encode_message(identity: bytes, message: bytes) -> bytes:
    """Domain-separated canonical encoding of (receiver identity, message).

    ``identity`` must be non-empty; ``message`` may be empty.
    """
    ident = validate_identity(identity)
    msg = validate_bytes(message, name="message")
    return DOMAIN_MSG + encode_bytes(ident) + encode_bytes(msg)


# --------------------------------------------------------------------------
# Decoding helpers
# --------------------------------------------------------------------------

def _prepare(buffer: object, offset: int) -> tuple[bytes, int]:
    """Normalise ``buffer`` to ``bytes`` and validate ``offset``."""
    if not isinstance(buffer, _BYTES_LIKE):
        raise EncodingError(
            f"buffer must be bytes-like, got {type(buffer).__name__}"
        )
    data = bytes(buffer)
    if not isinstance(offset, int) or isinstance(offset, bool):
        raise EncodingError(f"offset must be an int, got {type(offset).__name__}")
    if offset < 0 or offset > len(data):
        raise EncodingError(
            f"offset {offset} out of range for buffer of {len(data)} bytes"
        )
    return data, offset


def _match_domain(data: bytes, offset: int, domain: bytes, what: str) -> int:
    """Consume ``domain`` at ``offset``; return the offset after the domain."""
    end = offset + len(domain)
    if end > len(data) or data[offset:end] != domain:
        raise EncodingError(
            f"malformed {what}: missing or mismatched domain prefix"
        )
    return end


def _require_non_empty(value: bytes, what: str) -> bytes:
    if not value:
        raise EncodingError(f"malformed {what}: identity field is empty")
    return value


def decode_bytes(buffer: bytes, offset: int = 0) -> tuple[bytes, int]:
    """Decode one ``uint32_be(len) || data`` field starting at ``offset``.

    Returns ``(value, new_offset)``.  Raises ``EncodingError`` when the
    length field is truncated or announces more bytes than the buffer holds.
    """
    data, offset = _prepare(buffer, offset)
    if len(data) - offset < _UINT32_SIZE:
        raise EncodingError("truncated uint32 length field")
    length = int.from_bytes(data[offset:offset + _UINT32_SIZE], "big")
    start = offset + _UINT32_SIZE
    end = start + length
    if end > len(data):
        raise EncodingError(
            f"length field announces {length} bytes but only "
            f"{len(data) - start} remain"
        )
    return data[start:end], end


def decode_identity(buffer: bytes, offset: int = 0) -> tuple[bytes, int]:
    """Decode ``DOMAIN_ID || encode_bytes(id)`` starting at ``offset``."""
    data, offset = _prepare(buffer, offset)
    pos = _match_domain(data, offset, DOMAIN_ID, "identity")
    ident, pos = decode_bytes(data, pos)
    _require_non_empty(ident, "identity")
    return ident, pos


def decode_pair(buffer: bytes, offset: int = 0) -> tuple[tuple[bytes, bytes], int]:
    """Decode ``DOMAIN_PAIR || field(a) || field(b)`` starting at ``offset``."""
    data, offset = _prepare(buffer, offset)
    pos = _match_domain(data, offset, DOMAIN_PAIR, "identity pair")
    first, pos = decode_bytes(data, pos)
    _require_non_empty(first, "identity pair (first component)")
    second, pos = decode_bytes(data, pos)
    _require_non_empty(second, "identity pair (second component)")
    return (first, second), pos


def decode_message(
    buffer: bytes, offset: int = 0
) -> tuple[tuple[bytes, bytes], int]:
    """Decode ``DOMAIN_MSG || field(id) || field(message)`` from ``offset``.

    The identity field must be non-empty; the message field may be empty.
    """
    data, offset = _prepare(buffer, offset)
    pos = _match_domain(data, offset, DOMAIN_MSG, "message")
    ident, pos = decode_bytes(data, pos)
    _require_non_empty(ident, "message (identity field)")
    message, pos = decode_bytes(data, pos)
    return (ident, message), pos


# --------------------------------------------------------------------------
# Top-level exact parsers (reject trailing garbage)
# --------------------------------------------------------------------------

def _check_exact_end(buffer: bytes, end: int, what: str) -> None:
    if end != len(buffer):
        raise EncodingError(
            f"malformed {what}: {len(buffer) - end} trailing byte(s) after "
            "the last field (appended or duplicated data is rejected)"
        )


def parse_bytes(buffer: bytes) -> bytes:
    """Exactly parse a single length-prefixed field; reject trailing bytes."""
    value, end = decode_bytes(buffer, 0)
    _check_exact_end(buffer, end, "length-prefixed field")
    return value


def parse_identity(buffer: bytes) -> bytes:
    """Exactly parse one canonical identity encoding."""
    ident, end = decode_identity(buffer, 0)
    _check_exact_end(buffer, end, "identity")
    return ident


def parse_pair(buffer: bytes) -> tuple[bytes, bytes]:
    """Exactly parse one canonical identity-pair encoding."""
    pair, end = decode_pair(buffer, 0)
    _check_exact_end(buffer, end, "identity pair")
    return pair


def parse_message(buffer: bytes) -> tuple[bytes, bytes]:
    """Exactly parse one canonical message encoding as ``(identity, message)``."""
    fields, end = decode_message(buffer, 0)
    _check_exact_end(buffer, end, "message")
    return fields
