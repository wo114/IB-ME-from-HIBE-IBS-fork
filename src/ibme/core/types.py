"""Base types and value-validation helpers shared by every IB-ME layer.

This module is dependency-free except for the frozen error hierarchy in
``ibme.core.errors``.  It defines:

* ``Identity`` -- the project-wide identity type (a *non-empty* byte string);
* ``validate_bytes`` / ``validate_identity`` -- normalising validators used by
  the encoders in ``ibme.core.encoding`` and the hash helpers in
  ``ibme.core.hashing``;
* ``constant_time_equal`` -- data-independent byte-string comparison used for
  identity matching (IMPLEMENTATION_SPEC section 1).

Error convention of this module: every rejected input (wrong type, empty
identity) raises :class:`~ibme.core.errors.EncodingError`, so callers only
need to catch project exceptions.
"""

from __future__ import annotations

from typing import TypeAlias

from .errors import EncodingError

#: An identity is a non-empty byte string.  CLI layers may accept UTF-8 text,
#: but it must be converted to ``bytes`` before touching any cryptographic
#: algorithm (IMPLEMENTATION_SPEC section 1).
Identity: TypeAlias = bytes

#: Types accepted anywhere a byte string is expected and immediately
#: normalised to immutable ``bytes``.
_BYTES_LIKE = (bytes, bytearray, memoryview)


def validate_bytes(value: object, *, name: str = "value") -> bytes:
    """Return ``value`` as immutable ``bytes``.

    Accepts ``bytes``, ``bytearray`` and ``memoryview``; anything else
    (``str`` in particular) is rejected.  Unlike :func:`validate_identity`
    the empty string is allowed, because message fields may be empty.
    """
    if not isinstance(value, _BYTES_LIKE):
        raise EncodingError(
            f"{name} must be bytes, got {type(value).__name__}"
        )
    return bytes(value)


def validate_identity(value: object, *, name: str = "identity") -> Identity:
    """Validate and normalise an identity (non-empty byte string).

    Raises :class:`~ibme.core.errors.EncodingError` if ``value`` is not a
    bytes-like object or is empty.
    """
    ident = validate_bytes(value, name=name)
    if not ident:
        raise EncodingError(f"{name} must be non-empty bytes")
    return ident


def constant_time_equal(a: bytes, b: bytes) -> bool:
    """Compare two byte strings without data-dependent branches.

    The comparison XOR-accumulates every byte position and only inspects the
    accumulated difference at the very end, so the control flow does not
    depend on the contents of ``a`` or ``b``.  Lengths are compared first and
    leaked: identities are public-length, length-prefixed fields, so this
    matches the reference-implementation requirement of IMPLEMENTATION_SPEC
    section 1 ("identity comparison uses constant-time comparison of the raw
    canonical byte strings").

    Notes:
        * accepts ``bytes``/``bytearray``/``memoryview`` (normalised first);
        * different lengths return ``False`` immediately;
        * any other type raises ``TypeError`` (mirroring
          ``hmac.compare_digest``);
        * Python is not a constant-time language; this is the standard
          best-effort reference implementation, not a hardened assembly
          routine.
    """
    if isinstance(a, str) or isinstance(b, str):
        raise TypeError(
            "constant_time_equal() does not accept str; encode to bytes first"
        )
    if not isinstance(a, _BYTES_LIKE) or not isinstance(b, _BYTES_LIKE):
        raise TypeError(
            "constant_time_equal() requires bytes-like arguments, got "
            f"{type(a).__name__} and {type(b).__name__}"
        )
    a_bytes = bytes(a)
    b_bytes = bytes(b)
    if len(a_bytes) != len(b_bytes):
        return False
    diff = 0
    for x, y in zip(a_bytes, b_bytes):
        diff |= x ^ y
    return diff == 0
