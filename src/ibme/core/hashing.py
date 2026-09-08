"""Domain-separated SHAKE-256 hashing (frozen domain constants).

FROZEN INTERFACE: the six domain constants below must stay byte-for-byte
identical; they are part of the cross-module contract consumed by the HIBE,
IBS and protocol layers.

Public API
----------
``shake256(domain, data, out_len)``
    The primitive everyone builds on.  The digest input is *not* a bare
    concatenation (IMPLEMENTATION_SPEC section 1 forbids unprefixed
    concatenation); instead it is the length-prefixed, domain-separated
    encoding::

        u32be(len(domain)) || domain || data

    which makes different domains yield different digests even when one
    domain is a prefix of another.

``hash_identity`` / ``hash_pair`` / ``hash_message``
    Convenience wrappers that pick the domain and feed the same
    length-prefixed field encoding produced by ``ibme.core.encoding``::

        hash_identity(id, n)    == shake256(DOMAIN_ID,   encode_bytes(id), n)
        hash_pair(a, b, n)      == shake256(DOMAIN_PAIR, encode_bytes(a) || encode_bytes(b), n)
        hash_message(id, m, n)  == shake256(DOMAIN_MSG,  encode_bytes(id) || encode_bytes(m), n)

    (This module re-creates the field prefix locally instead of importing
    ``ibme.core.encoding`` to avoid an import cycle -- ``encoding`` imports
    the frozen domain constants from here.  The equality above is pinned by
    ``tests/test_encoding.py``.)

For the HIBE / IBS internal domains (``DOMAIN_HIBE_ID``, ``DOMAIN_IBS_H1``,
``DOMAIN_IBS_H2``) callers pass their own already-canonicalised ``data`` to
:func:`shake256`, because the field layout of those inputs is owned by the
respective modules.
"""

from __future__ import annotations

import hashlib

from .errors import InvalidParameterError
from .types import validate_bytes, validate_identity

# --- FROZEN domain constants (do not rename, revalue or remove) -------------

DOMAIN_ID = b"IBME:ID:v1"
DOMAIN_PAIR = b"IBME:PAIR:v1"
DOMAIN_MSG = b"IBME:MSG:v1"
DOMAIN_HIBE_ID = b"IBME:HIBE-ID:v1"
DOMAIN_IBS_H1 = b"IBME:IBS-H1:v1"
DOMAIN_IBS_H2 = b"IBME:IBS-H2:v1"

#: All frozen domains, in declaration order (useful for audits/tests).
ALL_DOMAINS: tuple[bytes, ...] = (
    DOMAIN_ID,
    DOMAIN_PAIR,
    DOMAIN_MSG,
    DOMAIN_HIBE_ID,
    DOMAIN_IBS_H1,
    DOMAIN_IBS_H2,
)

_BYTES_LIKE = (bytes, bytearray, memoryview)


def _u32be(n: int) -> bytes:
    """Big-endian uint32 length prefix (same encoding as encode_bytes)."""
    return n.to_bytes(4, "big")


def shake256(domain: bytes, data: bytes, out_len: int) -> bytes:
    """Return ``out_len`` bytes of SHAKE-256 over a domain-separated input.

    The squeezed input is ``u32be(len(domain)) || domain || data`` (see the
    module docstring).  ``domain`` must be a non-empty bytes-like object and
    ``out_len`` a positive ``int``; violations raise
    :class:`~ibme.core.errors.InvalidParameterError`.  ``data`` may be empty.
    """
    if not isinstance(domain, _BYTES_LIKE):
        raise InvalidParameterError(
            f"domain must be non-empty bytes, got {type(domain).__name__}"
        )
    if not bytes(domain):
        raise InvalidParameterError("domain must be non-empty bytes")
    if not isinstance(data, _BYTES_LIKE):
        raise InvalidParameterError(
            f"data must be bytes-like, got {type(data).__name__}"
        )
    if not isinstance(out_len, int) or isinstance(out_len, bool) or out_len <= 0:
        raise InvalidParameterError(
            f"out_len must be a positive int, got {out_len!r}"
        )
    hasher = hashlib.shake_256()
    hasher.update(_u32be(len(bytes(domain))) + bytes(domain))
    hasher.update(bytes(data))
    return hasher.digest(out_len)


def hash_identity(identity: bytes, out_len: int) -> bytes:
    """SHAKE-256 over ``DOMAIN_ID`` and the length-prefixed identity."""
    ident = validate_identity(identity)
    return shake256(DOMAIN_ID, _u32be(len(ident)) + ident, out_len)


def hash_pair(a: bytes, b: bytes, out_len: int) -> bytes:
    """SHAKE-256 over ``DOMAIN_PAIR`` and both length-prefixed identities."""
    first = validate_identity(a, name="a")
    second = validate_identity(b, name="b")
    data = _u32be(len(first)) + first + _u32be(len(second)) + second
    return shake256(DOMAIN_PAIR, data, out_len)


def hash_message(identity: bytes, message: bytes, out_len: int) -> bytes:
    """SHAKE-256 over ``DOMAIN_MSG``, the identity and the message.

    ``identity`` must be non-empty; ``message`` may be empty.  Both are
    length-prefixed exactly like ``encode_bytes``.
    """
    ident = validate_identity(identity)
    msg = validate_bytes(message, name="message")
    data = _u32be(len(ident)) + ident + _u32be(len(msg)) + msg
    return shake256(DOMAIN_MSG, data, out_len)
