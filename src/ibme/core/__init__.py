"""Core infrastructure: encoding, hashing, randomness, types and errors (owner: core task).

Public surface (M1 milestone):

* types: ``Identity``, ``validate_bytes``, ``validate_identity``,
  ``constant_time_equal``;
* hashing: the six frozen ``DOMAIN_*`` constants, ``shake256`` and the
  ``hash_identity`` / ``hash_pair`` / ``hash_message`` convenience wrappers;
* encoding: ``encode_bytes`` / ``encode_identity`` / ``encode_pair`` /
  ``encode_message`` plus the offset-based ``decode_*`` and the exact
  top-level ``parse_*`` family;
* randomness: the frozen ``read(n) -> bytes`` protocol (``RandomSource``)
  with ``SecureRandom`` (production CSPRNG) and ``DeterministicRandom``
  (test-only reproducible stream);
* errors: the frozen exception hierarchy re-exported for convenience.
"""

from .errors import (
    IBMEError,
    EncodingError,
    SerializationError,
    InvalidParameterError,
    DimensionError,
    ModulusMismatchError,
    RandomnessError,
)
from .hashing import (
    ALL_DOMAINS,
    DOMAIN_HIBE_ID,
    DOMAIN_IBS_H1,
    DOMAIN_IBS_H2,
    DOMAIN_ID,
    DOMAIN_MSG,
    DOMAIN_PAIR,
    hash_identity,
    hash_message,
    hash_pair,
    shake256,
)
from .encoding import (
    decode_bytes,
    decode_identity,
    decode_message,
    decode_pair,
    encode_bytes,
    encode_identity,
    encode_message,
    encode_pair,
    parse_bytes,
    parse_identity,
    parse_message,
    parse_pair,
)
from .randomness import DeterministicRandom, RandomSource, SecureRandom
from .types import (
    Identity,
    constant_time_equal,
    validate_bytes,
    validate_identity,
)

__all__ = [
    # errors (frozen hierarchy)
    "IBMEError",
    "EncodingError",
    "SerializationError",
    "InvalidParameterError",
    "DimensionError",
    "ModulusMismatchError",
    "RandomnessError",
    # types
    "Identity",
    "validate_bytes",
    "validate_identity",
    "constant_time_equal",
    # hashing
    "DOMAIN_ID",
    "DOMAIN_PAIR",
    "DOMAIN_MSG",
    "DOMAIN_HIBE_ID",
    "DOMAIN_IBS_H1",
    "DOMAIN_IBS_H2",
    "ALL_DOMAINS",
    "shake256",
    "hash_identity",
    "hash_pair",
    "hash_message",
    # encoding
    "encode_bytes",
    "encode_identity",
    "encode_pair",
    "encode_message",
    "decode_bytes",
    "decode_identity",
    "decode_pair",
    "decode_message",
    "parse_bytes",
    "parse_identity",
    "parse_pair",
    "parse_message",
    # randomness
    "RandomSource",
    "SecureRandom",
    "DeterministicRandom",
]
