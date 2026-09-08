"""Project-wide exception hierarchy.

FROZEN INTERFACE (main AI): the names and semantics below must not be renamed,
moved or removed. Module owners may append new subclasses for their own layer,
but existing names are part of the cross-module contract.
"""

class IBMEError(Exception):
    """Base class for every error raised by this project."""


class EncodingError(IBMEError):
    """Malformed input when encoding identities, messages or protocol fields."""


class SerializationError(IBMEError):
    """Malformed or truncated serialized object (matrix, key, ciphertext)."""


class InvalidParameterError(IBMEError):
    """A Params object or an explicit argument violates the documented constraints."""


class DimensionError(IBMEError):
    """Matrix/vector dimension mismatch."""


class ModulusMismatchError(IBMEError):
    """Operations mixing objects defined modulo different q."""


class RandomnessError(IBMEError):
    """Invalid randomness source or entropy misuse."""
