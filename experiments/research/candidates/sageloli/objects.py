"""Strict Sageloli SIS/RSIS parameters and object envelopes.

The backend owns H1/H2, trapdoor equations and finite Gaussian sampling. This
module owns public shapes, identity/salt binding, the persistent issuance
ledger and canonical wire encoding. A single object surface dispatches to the
matrix or polynomial route from the explicit parameter class.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from threading import RLock
import json

from ibme.core.errors import EncodingError, InvalidParameterError, SerializationError
from ibme.core.hashing import hash_identity
from ibme.core.types import validate_identity
from ibme.ibs.api import IBSPublicKey, IBSMasterSecret, IBSSigningKey, IBSSignature

from . import codec
from .config import SISParams, RSISParams

MAX_WIRE = codec.MAX_WIRE_BYTES
SISParamsAlias = SISParams
RSISParamsAlias = RSISParams
SisParams = SISParams
RsisParams = RSISParams


def _params_bytes(params) -> bytes:
    if not isinstance(params, (SISParams, RSISParams)):
        raise SerializationError("SISParams or RSISParams required")
    return json.dumps(params.record(), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _params_from_bytes(raw):
    try:
        record = json.loads(bytes(raw).decode("utf-8"))
        if not isinstance(record, dict): raise ValueError("parameter record must be an object")
        if {"d", "l"} <= set(record): return RSISParams.from_record(record)
        if {"n", "m"} <= set(record): return SISParams.from_record(record)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, OverflowError):
        pass
    raise SerializationError("invalid Sageloli parameter snapshot")


def _is_sis(params): return isinstance(params, SISParams)
def _is_rsis(params): return isinstance(params, RSISParams)


def _shape(params, kind):
    if _is_sis(params):
        return {"public": (params.n, params.m), "root": (params.m - params.nk, params.nk),
                "identity": (params.m, params.nk), "signature": (params.m + params.nk,)}[kind]
    if _is_rsis(params):
        # The backend keeps ring objects in their expanded negacyclic matrix
        # form for a single public verifier: d x (d*l), d(l-k) x (d*k),
        # d*l x d*k, and a flat d(l+k)-coefficient response.
        return {"public": (params.d, params.d * params.l),
                "root": (params.d * (params.l - params.k), params.d * params.k),
                "identity": (params.d * params.l, params.d * params.k),
                "signature": (params.d * (params.l + params.k),)}[kind]
    raise SerializationError("unknown Sageloli parameter route")


def _product(shape):
    result = 1
    for value in shape: result *= value
    return result


def _flatten(value, shape, *, signed=True, modulus=None):
    def walk(node, depth):
        if depth == len(shape):
            if type(node) is not int: raise SerializationError("coefficient must be an int")
            if not signed and node < 0: raise SerializationError("negative public coefficient")
            if modulus is not None and not signed and node >= modulus: raise SerializationError("public coefficient outside modulus")
            if not codec._I64_MIN <= node <= codec._I64_MAX: raise SerializationError("coefficient outside int64")
            return node
        if not isinstance(node, (tuple, list)) or len(node) != shape[depth]: raise SerializationError("Sageloli tensor dimension mismatch")
        return tuple(walk(item, depth + 1) for item in node)
    return walk(value, 0)


def _tensor_bytes(value, shape, *, signed=True):
    flat = []
    def walk(node, depth):
        if depth == len(shape): flat.append(node); return
        for item in node: walk(item, depth + 1)
    walk(value, 0)
    return codec.u32(len(shape)) + b"".join(codec.u32(n) for n in shape) + codec.pack_ints(flat, signed=signed)


def _tensor_from_bytes(raw, shape, *, signed=True):
    raw = bytes(raw); rank, pos = codec.read_u32(raw)
    if rank != len(shape): raise SerializationError("tensor rank mismatch")
    dims = []
    for _ in shape:
        dim, pos = codec.read_u32(raw, pos); dims.append(dim)
    if tuple(dims) != tuple(shape): raise SerializationError("tensor dimensions mismatch")
    flat = codec.unpack_ints(raw[pos:], expected=_product(shape), signed=signed)
    def build(offset, depth):
        if depth == len(shape): return flat[offset], offset + 1
        out = []
        for _ in range(shape[depth]):
            item, offset = build(offset, depth + 1); out.append(item)
        return tuple(out), offset
    value, end = build(0, 0)
    if end != len(flat): raise SerializationError("tensor coefficient count mismatch")
    return value


def _restore(cls, raw, kind, count, convert):
    fields = codec.decode(raw, kind, count)
    try:
        result = cls(**convert(fields))
        if result.to_bytes() != bytes(raw): raise SerializationError("noncanonical reconstructed object")
        return result
    except (EncodingError, InvalidParameterError, SerializationError, TypeError, ValueError, OverflowError) as exc:
        if isinstance(exc, SerializationError) and str(exc) == "noncanonical reconstructed object": raise
        raise SerializationError("invalid Sageloli object") from exc


@dataclass(frozen=True, eq=False, repr=False)
class PublicKey(IBSPublicKey):
    params: object
    a: tuple

    def __post_init__(self):
        if not _is_sis(self.params) and not _is_rsis(self.params): raise SerializationError("Sageloli parameters required")
        object.__setattr__(self, "a", _flatten(self.a, _shape(self.params, "public"), signed=False, modulus=self.params.q))

    @property
    def context(self): return sha256(self.to_bytes()).digest()
    @property
    def route(self): return "sis" if _is_sis(self.params) else "rsis"

    def to_bytes(self):
        kind = b"SIS-PK" if _is_sis(self.params) else b"RSIS-PK"
        return codec.encode(kind, _params_bytes(self.params), _tensor_bytes(self.a, _shape(self.params, "public"), signed=False))

    @classmethod
    def from_bytes(cls, raw):
        try: raw = bytes(raw)
        except (TypeError, ValueError) as exc: raise SerializationError("public key encoding must be bytes") from exc
        if raw.startswith(codec.MAGIC + codec.blob(b"SIS-PK")):
            fields = codec.decode(raw, b"SIS-PK", 2); params = _params_from_bytes(fields[0]); kind = b"SIS-PK"
            if not _is_sis(params): raise SerializationError("SIS key has non-SIS parameters")
        elif raw.startswith(codec.MAGIC + codec.blob(b"RSIS-PK")):
            fields = codec.decode(raw, b"RSIS-PK", 2); params = _params_from_bytes(fields[0]); kind = b"RSIS-PK"
            if not _is_rsis(params): raise SerializationError("RSIS key has non-RSIS parameters")
        else: raise SerializationError("Sageloli public-key kind mismatch")
        target = cls if cls is not PublicKey else (SisPublicKey if kind == b"SIS-PK" else RsisPublicKey)
        return _restore(target, raw, kind, 2, lambda f: {"params": params, "a": _tensor_from_bytes(f[1], _shape(params, "public"), signed=False)})

    def __repr__(self): return f"Sageloli{self.route.upper()}PublicKey(security_claim='none')"


@dataclass(eq=False, repr=False)
class MasterSecret(IBSMasterSecret):
    public_key: PublicKey
    trapdoor: tuple = field(repr=False)
    states: dict = field(default_factory=dict, repr=False)
    __hash__ = None

    def __post_init__(self):
        if not isinstance(self.public_key, PublicKey): raise SerializationError("Sageloli public key required")
        p = self.public_key.params
        object.__setattr__(self, "trapdoor", _flatten(self.trapdoor, _shape(p, "root")))
        if not isinstance(self.states, dict) or len(self.states) > p.max_users: raise SerializationError("invalid issuance ledger")
        for identity, entry in self.states.items():
            identity = validate_identity(identity, max_bytes=p.identity_max_bytes)
            if not isinstance(entry, tuple) or len(entry) != 2: raise SerializationError("invalid ledger entry")
            status, key = entry
            if status not in ("pending", "failed", "issued"): raise SerializationError("invalid ledger status")
            if status == "issued":
                if not isinstance(key, SigningKey) or key.identity != identity or key.public_key.context != self.public_key.context: raise SerializationError("issued key binding mismatch")
            elif key is not None: raise SerializationError("unissued ledger entry contains key")
        object.__setattr__(self, "_cache_lock", RLock())

    @property
    def public(self): return self.public_key
    @property
    def cached_identities(self):
        with self._cache_lock:
            return tuple(sorted(self.states))
    @property
    def cache(self): return self.states
    def __repr__(self): return f"SageloliMasterSecret(route={self.public_key.route}, identities={len(self.states)}, secrets=<redacted>)"

    def _state_bytes(self):
        with self._cache_lock:
            out = bytearray(codec.u32(len(self.states)))
            for identity in sorted(self.states):
                status, key = self.states[identity]
                out.extend(codec.blob(identity)); out.extend(codec.blob(status.encode("ascii")))
                out.extend(codec.blob(key.to_bytes() if key is not None else b""))
            return bytes(out)

    def to_bytes(self):
        kind = b"SIS-MSK" if _is_sis(self.public_key.params) else b"RSIS-MSK"
        return codec.encode(kind, self.public_key.to_bytes(), _tensor_bytes(self.trapdoor, _shape(self.public_key.params, "root")), self._state_bytes())

    @classmethod
    def from_bytes(cls, raw):
        try: raw = bytes(raw)
        except (TypeError, ValueError) as exc: raise SerializationError("master key encoding must be bytes") from exc
        if raw.startswith(codec.MAGIC + codec.blob(b"SIS-MSK")): kind = b"SIS-MSK"
        elif raw.startswith(codec.MAGIC + codec.blob(b"RSIS-MSK")): kind = b"RSIS-MSK"
        else: raise SerializationError("Sageloli master-key kind mismatch")
        fields = codec.decode(raw, kind, 3); pk = PublicKey.from_bytes(fields[0]); p = pk.params
        if (kind == b"SIS-MSK") != _is_sis(p): raise SerializationError("master route/parameter mismatch")
        trap = _tensor_from_bytes(fields[1], _shape(p, "root")); state_raw = fields[2]; count, pos = codec.read_u32(state_raw)
        if count > p.max_users: raise SerializationError("ledger exceeds max_users")
        states, previous = {}, None
        for _ in range(count):
            identity, pos = codec.read_blob(state_raw, pos, what="identity"); status_raw, pos = codec.read_blob(state_raw, pos, what="status"); key_raw, pos = codec.read_blob(state_raw, pos, what="key")
            if previous is not None and identity <= previous: raise SerializationError("ledger identities are not sorted")
            previous = identity; identity = validate_identity(identity, max_bytes=p.identity_max_bytes)
            try: status = status_raw.decode("ascii")
            except UnicodeDecodeError as exc: raise SerializationError("invalid ledger status encoding") from exc
            if status not in ("pending", "failed", "issued"): raise SerializationError("invalid ledger status")
            if status == "issued":
                key = SigningKey.from_bytes(key_raw)
                if key.identity != identity or key.public_key.context != pk.context: raise SerializationError("issued key binding mismatch")
            else:
                if key_raw: raise SerializationError("unissued identity contains key")
                key = None
            states[identity] = (status, key)
        if pos != len(state_raw): raise SerializationError("ledger trailing bytes")
        target = cls if cls is not MasterSecret else (SisMasterSecret if kind == b"SIS-MSK" else RsisMasterSecret)
        return _restore(target, raw, kind, 3, lambda _: {"public_key": pk, "trapdoor": trap, "states": states})


@dataclass(frozen=True, eq=False, repr=False)
class SigningKey(IBSSigningKey):
    public_key: PublicKey
    _identity: bytes
    identity_salt: bytes
    trapdoor: tuple = field(repr=False)

    def __post_init__(self):
        if not isinstance(self.public_key, PublicKey): raise SerializationError("Sageloli public key required")
        p = self.public_key.params
        object.__setattr__(self, "_identity", validate_identity(self._identity, max_bytes=p.identity_max_bytes))
        if type(self.identity_salt) is not bytes or not 1 <= len(self.identity_salt) <= 64: raise SerializationError("invalid identity salt")
        object.__setattr__(self, "trapdoor", _flatten(self.trapdoor, _shape(p, "identity")))

    @property
    def identity(self): return self._identity
    @property
    def identity_digest(self): return hash_identity(self.identity, 32)
    def __repr__(self): return f"SageloliSigningKey(route={self.public_key.route}, identity_bytes={len(self.identity)}, secrets=<redacted>)"

    def to_bytes(self):
        kind = b"SIS-SK" if _is_sis(self.public_key.params) else b"RSIS-SK"
        return codec.encode(kind, self.public_key.to_bytes(), self.identity, self.identity_salt, _tensor_bytes(self.trapdoor, _shape(self.public_key.params, "identity")))

    @classmethod
    def from_bytes(cls, raw):
        try: raw = bytes(raw)
        except (TypeError, ValueError) as exc: raise SerializationError("signing key encoding must be bytes") from exc
        if raw.startswith(codec.MAGIC + codec.blob(b"SIS-SK")): kind = b"SIS-SK"
        elif raw.startswith(codec.MAGIC + codec.blob(b"RSIS-SK")): kind = b"RSIS-SK"
        else: raise SerializationError("Sageloli signing-key kind mismatch")
        fields = codec.decode(raw, kind, 4); pk = PublicKey.from_bytes(fields[0]); p = pk.params
        if (kind == b"SIS-SK") != _is_sis(p): raise SerializationError("signing-key route/parameter mismatch")
        trap = _tensor_from_bytes(fields[3], _shape(p, "identity"))
        target = cls if cls is not SigningKey else (SisSigningKey if kind == b"SIS-SK" else RsisSigningKey)
        return _restore(target, raw, kind, 4, lambda _: {"public_key": pk, "_identity": fields[1], "identity_salt": fields[2], "trapdoor": trap})


@dataclass(frozen=True, eq=False, repr=False)
class Signature(IBSSignature):
    context: bytes
    identity_salt: bytes
    message_salt: bytes
    z: object

    def __post_init__(self):
        if type(self.context) is not bytes or len(self.context) != 32: raise SerializationError("invalid signature context")
        if type(self.identity_salt) is not bytes or not 1 <= len(self.identity_salt) <= 64: raise SerializationError("invalid identity salt")
        if type(self.message_salt) is not bytes or not 1 <= len(self.message_salt) <= 64: raise SerializationError("invalid message salt")
        if not isinstance(self.z, (tuple, list)) or not self.z: raise SerializationError("empty signature response")

    def to_bytes(self):
        if not isinstance(self.z[0], (tuple, list)):
            zraw = codec.pack_ints(self.z)
        else:
            zraw = _tensor_bytes(self.z, (len(self.z), len(self.z[0])))
        return codec.encode(b"SIG", self.context, self.identity_salt, self.message_salt, zraw)

    @classmethod
    def from_bytes(cls, raw, public_key):
        if not isinstance(public_key, PublicKey): raise TypeError("Sageloli public key required")
        fields = codec.decode(raw, b"SIG", 4)
        if fields[0] != public_key.context: raise SerializationError("cross-public-key signature")
        shape = _shape(public_key.params, "signature")
        z = codec.unpack_ints(fields[3], expected=_product(shape)) if len(shape) == 1 else _tensor_from_bytes(fields[3], shape)
        return _restore(cls, raw, b"SIG", 4, lambda _: {"context": fields[0], "identity_salt": fields[1], "message_salt": fields[2], "z": z})

    def __repr__(self): return "SageloliSignature(security_claim='none')"


class SisPublicKey(PublicKey):
    pass


class RsisPublicKey(PublicKey):
    pass


class SisMasterSecret(MasterSecret):
    pass


class RsisMasterSecret(MasterSecret):
    pass


class SisSigningKey(SigningKey):
    pass


class RsisSigningKey(SigningKey):
    pass


SISPublicKey = SisPublicKey
RSISPublicKey = RsisPublicKey
SISMasterSecret = SisMasterSecret
RSISMasterSecret = RsisMasterSecret
SISSigningKey = SisSigningKey
RSISSigningKey = RsisSigningKey
SISSignature = RSISSignature = Signature
SisSignature = RsisSignature = Signature
SisParams = SISParams
RsisParams = RSISParams

__all__ = ["SISParams", "RSISParams", "SisParams", "RsisParams", "SISParamsAlias", "RSISParamsAlias", "PublicKey", "MasterSecret", "SigningKey", "Signature", "SisPublicKey", "RsisPublicKey", "SisMasterSecret", "RsisMasterSecret", "SisSigningKey", "RsisSigningKey", "SISPublicKey", "RSISPublicKey", "SISMasterSecret", "RSISMasterSecret", "SISSigningKey", "RSISSigningKey", "SISSignature", "RSISSignature", "MAX_WIRE"]
