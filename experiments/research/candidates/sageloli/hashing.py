"""Salted, domain-separated H1/H2 for the adaptive Sageloli schemes."""

from __future__ import annotations

from ibme.core.encoding import encode_bytes
from ibme.core.types import validate_bytes, validate_identity

from .uniform import DEFAULT_MAX_TRIALS_PER_VALUE, MAX_BYTES, MAX_VALUES, shake_uniform_mod_q


H1_SIS_DOMAIN = b"IBME-SAGEL0LI-SIS-H1-v2"
H2_SIS_DOMAIN = b"IBME-SAGEL0LI-SIS-H2-v2"
H1_RSIS_DOMAIN = b"IBME-SAGEL0LI-RSIS-H1-v2"
H2_RSIS_DOMAIN = b"IBME-SAGEL0LI-RSIS-H2-v2"
_NO_MESSAGE = object()


def _payload(context, r, identity, *, message=_NO_MESSAGE, salt=None):
    context = validate_bytes(context, name="public context")
    r = validate_bytes(r, name="identity salt")
    identity = validate_identity(identity)
    if any(len(value) > MAX_BYTES // 8 for value in (context, r, identity)):
        raise ValueError("hash field exceeds resource cap")
    payload = encode_bytes(context) + encode_bytes(r) + encode_bytes(identity)
    if message is not _NO_MESSAGE:
        message = validate_bytes(message, name="message")
        salt = validate_bytes(salt, name="message salt")
        if max(len(message), len(salt)) > MAX_BYTES // 8:
            raise ValueError("hash field exceeds resource cap")
        payload += encode_bytes(salt) + encode_bytes(message)
    return payload


def _dimensions(*values):
    count = 1
    for value in values:
        if (isinstance(value, bool) or not isinstance(value, int)
                or not 1 <= value <= MAX_VALUES):
            raise ValueError("invalid hash dimension")
        count *= value
        if count > MAX_VALUES:
            raise ValueError("hash output exceeds resource cap")
    return count


def sis_h1(context, r, identity, n, k, q, *,
           max_trials_per_value=DEFAULT_MAX_TRIALS_PER_VALUE, max_bytes=MAX_BYTES):
    count = _dimensions(n, n, k)
    values = shake_uniform_mod_q(H1_SIS_DOMAIN, _payload(context, r, identity), q, count,
                                max_trials_per_value=max_trials_per_value, max_bytes=max_bytes)
    return tuple(tuple(values[i * n * k:(i + 1) * n * k]) for i in range(n))


def sis_h2(context, r, s, identity, message, n, q, *,
           max_trials_per_value=DEFAULT_MAX_TRIALS_PER_VALUE, max_bytes=MAX_BYTES):
    count = _dimensions(n)
    return shake_uniform_mod_q(H2_SIS_DOMAIN, _payload(context, r, identity, message=message, salt=s),
                               q, count, max_trials_per_value=max_trials_per_value, max_bytes=max_bytes)


def rsis_h1(context, r, identity, k, d, q, *,
            max_trials_per_value=DEFAULT_MAX_TRIALS_PER_VALUE, max_bytes=MAX_BYTES):
    count = _dimensions(k, d)
    values = shake_uniform_mod_q(H1_RSIS_DOMAIN, _payload(context, r, identity), q, count,
                                max_trials_per_value=max_trials_per_value, max_bytes=max_bytes)
    return tuple(tuple(values[i * d:(i + 1) * d]) for i in range(k))


def rsis_h2(context, r, s, identity, message, d, q, *,
            max_trials_per_value=DEFAULT_MAX_TRIALS_PER_VALUE, max_bytes=MAX_BYTES):
    count = _dimensions(d)
    return shake_uniform_mod_q(H2_RSIS_DOMAIN, _payload(context, r, identity, message=message, salt=s),
                               q, count, max_trials_per_value=max_trials_per_value, max_bytes=max_bytes)


__all__ = ["sis_h1", "sis_h2", "rsis_h1", "rsis_h2"]
