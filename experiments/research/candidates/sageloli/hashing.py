"""Salted, domain-separated H1/H2 for the adaptive Sageloli schemes."""

from __future__ import annotations

from ibme.core.encoding import encode_bytes
from ibme.core.hashing import shake256
from ibme.core.types import validate_bytes, validate_identity


H1_SIS_DOMAIN = b"IBME-SAGEL0LI-SIS-H1-v1"
H2_SIS_DOMAIN = b"IBME-SAGEL0LI-SIS-H2-v1"
H1_RSIS_DOMAIN = b"IBME-SAGEL0LI-RSIS-H1-v1"
H2_RSIS_DOMAIN = b"IBME-SAGEL0LI-RSIS-H2-v1"


def _digest(domain, context, r, identity, message=b"", salt=b"", length=32):
    context = validate_bytes(context, name="public context")
    r = validate_bytes(r, name="identity salt")
    identity = validate_identity(identity)
    message = validate_bytes(message, name="message")
    salt = validate_bytes(salt, name="message salt")
    payload = encode_bytes(context) + encode_bytes(r) + encode_bytes(identity)
    if salt or message:
        payload += encode_bytes(salt) + encode_bytes(message)
    return shake256(domain, payload, length)


def sis_h1(context, r, identity, n, k, q):
    width = max(1, (int(q).bit_length() + 7) // 8)
    raw = _digest(H1_SIS_DOMAIN, context, r, identity, length=n * n * k * width)
    values = [int.from_bytes(raw[i:i + width], "big") % q for i in range(0, len(raw), width)]
    return tuple(tuple(values[i * n * k:(i + 1) * n * k]) for i in range(n))


def sis_h2(context, r, s, identity, message, n, q):
    width = max(1, (int(q).bit_length() + 7) // 8)
    raw = _digest(H2_SIS_DOMAIN, context, r, identity, message, s, length=n * width)
    return tuple(int.from_bytes(raw[i:i + width], "big") % q for i in range(0, len(raw), width))


def rsis_h1(context, r, identity, k, d, q):
    width = max(1, (int(q).bit_length() + 7) // 8)
    raw = _digest(H1_RSIS_DOMAIN, context, r, identity, length=k * d * width)
    values = [int.from_bytes(raw[i:i + width], "big") % q for i in range(0, len(raw), width)]
    return tuple(tuple(values[i * d:(i + 1) * d]) for i in range(k))


def rsis_h2(context, r, s, identity, message, d, q):
    width = max(1, (int(q).bit_length() + 7) // 8)
    raw = _digest(H2_RSIS_DOMAIN, context, r, identity, message, s, length=d * width)
    return tuple(int.from_bytes(raw[i:i + width], "big") % q for i in range(0, len(raw), width))


__all__ = ["sis_h1", "sis_h2", "rsis_h1", "rsis_h2"]
