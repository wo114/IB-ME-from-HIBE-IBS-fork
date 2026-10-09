"""Luo 2024 Section 3 IBSBackend adapter, for research only.

Algorithms and MATRIX-REF/1 bytes are unchanged from the M1 engine. This
adapter adds the frozen object/error/randomness contract and a strict research
configuration format. It does not admit these parameters as secure, enable a
CLI backend, or provide a complete IBME instance. security_claim: none.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import ClassVar

from ibme.core.errors import (
    EncodingError, IBMEError, InvalidParameterError, RandomnessError, SerializationError,
)
from ibme.core.hashing import hash_identity
from ibme.core.randomness import SecureRandom
from ibme.core.types import validate_bytes, validate_identity

from .api import IBSPublicKey, IBSMasterSecret, IBSSigningKey, IBSSignature
from . import luo_reference as reference


CONFIG_VERSION = "IBME/LUO2024/MATRIX-CONFIG/1"

__all__ = [
    "CONFIG_VERSION", "LuoMatrixParams", "LuoIBSBackend", "LuoPublicKey",
    "LuoMasterSecret", "LuoSigningKey", "LuoSignature", "LuoSamplingAbort",
]


def _decode(parser, *args):
    """Normalize strict engine-decoder failures to the package contract."""
    try:
        return parser(*args)
    except (TypeError, ValueError, IBMEError, OverflowError, reference.SamplingAbort) as exc:
        raise SerializationError(f"malformed Luo object: {exc}") from exc


def _encode(value):
    return _decode(value.to_bytes)


@dataclass(frozen=True)
class LuoMatrixParams(reference.MatrixParams):
    """Versioned research parameters; resource caps and safety status stay fixed.

    This is independent of the legacy lattice Params. No large modulus is
    silently truncated, and no configuration can promote a safety claim.
    MATRIX-REF/1 still has n<=16, m<=128, k<=32 and uint32 q: production
    dimensions require a separately reviewed format/engine extension.
    """

    security_claim: ClassVar[str] = "none"
    backend_admitted: ClassVar[bool] = False

    def __post_init__(self):
        try:
            super().__post_init__()
        except (TypeError, ValueError) as exc:
            raise InvalidParameterError(str(exc)) from exc

    @classmethod
    def from_bytes(cls, data):
        return _decode(super().from_bytes, data)

    def to_config(self) -> dict:
        return dict(
            config_version=CONFIG_VERSION,
            security_claim="none",
            backend_admitted=False,
            parameters={name: getattr(self, name) for name in reference.PARAM_FIELDS},
        )

    @classmethod
    def from_config(cls, config: dict):
        if not isinstance(config, dict) or set(config) != {
            "config_version", "security_claim", "backend_admitted", "parameters",
        }:
            raise InvalidParameterError("wrong Luo configuration fields")
        if (config["config_version"] != CONFIG_VERSION
                or config["security_claim"] != "none"
                or config["backend_admitted"] is not False):
            raise InvalidParameterError("unsupported configuration version or safety claim")
        fields = config["parameters"]
        if not isinstance(fields, dict) or set(fields) != set(reference.PARAM_FIELDS):
            raise InvalidParameterError("wrong Luo parameter fields")
        return cls(**fields)

    def to_json(self) -> str:
        return json.dumps(self.to_config(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, data):
        if not isinstance(data, (str, bytes)) or len(data) > 4096:
            raise InvalidParameterError("Luo JSON configuration must be at most 4096 bytes/characters")

        def unique_fields(pairs):
            fields = {}
            for key, value in pairs:
                if key in fields:
                    raise InvalidParameterError("duplicate Luo configuration field")
                fields[key] = value
            return fields

        try:
            config = json.loads(data, object_pairs_hook=unique_fields)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise InvalidParameterError("malformed Luo JSON configuration") from exc
        return cls.from_config(config)


@dataclass(frozen=True, eq=False, repr=False)
class LuoPublicKey(IBSPublicKey):
    _reference: reference.PublicKey

    def __post_init__(self):
        if not isinstance(self._reference, reference.PublicKey):
            raise TypeError("expected Luo reference PublicKey")
        self._reference.__post_init__()

    @property
    def params(self) -> LuoMatrixParams:
        return LuoMatrixParams(**{
            name: getattr(self._reference.params, name) for name in reference.PARAM_FIELDS
        })

    @property
    def context(self) -> bytes:
        return self._reference.context

    def __repr__(self):
        return "LuoPublicKey(security_claim='none')"

    def to_bytes(self) -> bytes:
        return _encode(self._reference)

    @classmethod
    def from_bytes(cls, data):
        return cls(_decode(reference.PublicKey.from_bytes, data))


@dataclass(frozen=True, eq=False, repr=False)
class LuoMasterSecret(IBSMasterSecret):
    _state: reference.MasterState

    # The serialized identity cache changes on first extraction. Hashing a
    # mutable master state as an immutable value would break dict/set semantics.
    __hash__ = None

    def __post_init__(self):
        if not isinstance(self._state, reference.MasterState):
            raise TypeError("expected Luo reference MasterState")
        self._state.__post_init__()

    @property
    def public_key(self) -> LuoPublicKey:
        return LuoPublicKey(self._state.public)

    @property
    def cached_identities(self) -> tuple[bytes, ...]:
        return self._state.cached_identities

    def __repr__(self):
        return f"LuoMasterSecret(cached_identities={len(self.cached_identities)}, secrets=<redacted>)"

    def to_bytes(self) -> bytes:
        """PRIVATE snapshot; includes persistent keys, excludes RNG state."""
        return _encode(self._state)

    @classmethod
    def from_bytes(cls, data):
        return cls(_decode(reference.MasterState.from_bytes, data))


@dataclass(frozen=True, eq=False, repr=False)
class LuoSigningKey(IBSSigningKey):
    _reference: reference.SigningKey
    _digest: bytes = field(init=False, repr=False)

    def __post_init__(self):
        if not isinstance(self._reference, reference.SigningKey):
            raise TypeError("expected Luo reference SigningKey")
        _encode(self._reference)  # validate the user equation before accepting it
        object.__setattr__(self, "_digest", hash_identity(self._reference.identity, 32))

    @property
    def identity(self) -> bytes:
        return self._reference.identity

    @property
    def identity_digest(self) -> bytes:
        return self._digest

    @property
    def public_key(self) -> LuoPublicKey:
        return LuoPublicKey(self._reference.public)

    def __repr__(self):
        return f"LuoSigningKey(identity_bytes={len(self.identity)}, secrets=<redacted>)"

    def to_bytes(self) -> bytes:
        return _encode(self._reference)

    @classmethod
    def from_bytes(cls, data):
        return cls(_decode(reference.SigningKey.from_bytes, data))


@dataclass(frozen=True, eq=False, repr=False)
class LuoSignature(IBSSignature):
    _reference: reference.Signature

    def __post_init__(self):
        if not isinstance(self._reference, reference.Signature):
            raise TypeError("expected Luo reference Signature")

    def __repr__(self):
        return "LuoSignature(security_claim='none')"

    def to_bytes(self) -> bytes:
        return _encode(self._reference)

    @classmethod
    def from_bytes(cls, data, pk: LuoPublicKey):
        if not isinstance(pk, LuoPublicKey):
            raise TypeError("expected LuoPublicKey")
        return cls(_decode(reference.Signature.from_bytes, pk._reference, data))


class LuoSamplingAbort(reference.SamplingAbort, IBMEError):
    """Sampling or persistent-cache budget exhausted; no key/signature issued."""


class _CheckedRandom:
    def __init__(self, source):
        if not callable(getattr(source, "read", None)):
            raise RandomnessError("random source must provide read(n)")
        self.source = source

    def read(self, count: int) -> bytes:
        data = self.source.read(count)
        if not isinstance(data, bytes) or len(data) != count:
            raise RandomnessError("random source must return exactly the requested bytes")
        return data


def _operation(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except reference.SamplingAbort as exc:
        raise LuoSamplingAbort(str(exc)) from exc
    except RandomnessError:
        raise
    except (TypeError, ValueError, IBMEError, OverflowError) as exc:
        raise InvalidParameterError(f"invalid Luo operation input: {exc}") from exc


class LuoIBSBackend:
    """Frozen IBS contract with real matrix operations; research use only.

    Explicit LuoMatrixParams are required at Setup: no automatic safe preset.
    State is owned by the master key, never by a hidden backend key directory.
    Verification uses only the supplied public key and signature.
    """

    security_claim = "none"
    backend_admitted = False
    research_only = True

    def __init__(self, *, rng=None):
        self._rng = _CheckedRandom(SecureRandom() if rng is None else rng)

    def setup(self, params: LuoMatrixParams):
        if not isinstance(params, LuoMatrixParams):
            raise TypeError("expected explicit LuoMatrixParams")
        public, master = _operation(reference.setup, params, rng=self._rng)
        return LuoPublicKey(public), LuoMasterSecret(master)

    def key_extract(self, msk: LuoMasterSecret, identity: bytes):
        if not isinstance(msk, LuoMasterSecret):
            raise TypeError("expected LuoMasterSecret")
        ident = validate_identity(identity, max_bytes=msk.public_key.params.identity_max_bytes)
        return LuoSigningKey(_operation(reference.key_extract, msk._state, ident, rng=self._rng))

    def sign(self, sk: LuoSigningKey, message: bytes):
        if not isinstance(sk, LuoSigningKey):
            raise TypeError("expected LuoSigningKey")
        msg = validate_bytes(message, name="message")
        if len(msg) > sk.public_key.params.message_max_bytes:
            raise EncodingError("message exceeds Luo message_max_bytes")
        return LuoSignature(_operation(reference.sign, sk._reference, msg, rng=self._rng))

    def verify(self, pk, identity, message, signature) -> bool:
        if not isinstance(pk, LuoPublicKey) or not isinstance(signature, LuoSignature):
            return False
        return reference.verify(pk._reference, identity, message, signature._reference)

    def load_signature(self, pk: LuoPublicKey, data: bytes):
        return LuoSignature.from_bytes(data, pk)
