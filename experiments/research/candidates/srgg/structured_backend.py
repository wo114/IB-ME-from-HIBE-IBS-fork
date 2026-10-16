"""Five-method adapter and strict objects for structured SRGG research.

Arithmetic and hashes are exactly structured_execution's. Numerical sampling
uses the single query-bounded-deep profile. No legacy backend, registry,
parameter admission or security claim is changed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
from math import isqrt

from ibme.core.errors import EncodingError, SerializationError
from ibme.core.hashing import hash_identity
from ibme.core.randomness import SecureRandom
from ibme.core.types import validate_bytes, validate_identity
from ibme.ibs.api import IBSPublicKey, IBSMasterSecret, IBSSigningKey, IBSSignature
from experiments.research.gaussian_reference import SamplingAbort
from . import structured_execution as raw


SCHEMA = "IBME/SRGG-STRUCTURED-OBJECT/1"
PROFILE = "query-bounded-deep"
MAX_WIRE = 2*1024*1024
MAX_USERS = 64


def _encode(record):
    data = json.dumps(record, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")
    if len(data) > MAX_WIRE:
        raise SerializationError("structured SRGG object exceeds wire capacity")
    return data


def _decode(data, fields):
    try:
        if type(data) is not bytes or not 2 <= len(data) <= MAX_WIRE:
            raise ValueError("bounded bytes required")
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate field")
                result[key] = value
            return result
        record = json.loads(data, object_pairs_hook=unique)
        if type(record) is not dict or set(record) != set(fields) or _encode(record) != data:
            raise ValueError("noncanonical object")
        return record
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise SerializationError("invalid structured SRGG object") from None


def _hex(value, *, maximum=MAX_WIRE):
    if type(value) is not str or len(value) > 2*maximum:
        raise SerializationError("invalid structured SRGG hex field")
    try:
        decoded = bytes.fromhex(value)
    except ValueError:
        raise SerializationError("invalid structured SRGG hex field") from None
    if decoded.hex() != value:
        raise SerializationError("noncanonical structured SRGG hex field")
    return decoded


def _envelope(data, kind, fields):
    record = _decode(data, ("schema", "profile", "kind", *fields))
    if record["schema"] != SCHEMA or record["profile"] != PROFILE or record["kind"] != kind:
        raise SerializationError("structured SRGG object version/profile/kind mismatch")
    return record


def _record(kind, **fields):
    return {"schema": SCHEMA, "profile": PROFILE, "kind": kind, **fields}


def _identity(value):
    return validate_identity(value, max_bytes=4096)


def _message(value):
    value = validate_bytes(value, name="message")
    if len(value) > 65536:
        raise EncodingError("structured SRGG message capacity exceeded")
    return value


@dataclass(frozen=True, eq=False)
class PublicKey(IBSPublicKey):
    value: raw.Public

    def __post_init__(self):
        if type(self.value) is not raw.Public:
            raise TypeError("structured execution Public required")

    @property
    def params(self): return self.value.params

    @property
    def context(self): return self.value.context

    def to_bytes(self):
        data = self.value.to_bytes()
        if len(data) > MAX_WIRE:
            raise SerializationError("structured SRGG public exceeds wire capacity")
        return data

    @classmethod
    def from_bytes(cls, data):
        record = _decode(data, ("schema", "params", "seed", "b"))
        try:
            if record["schema"] != raw.SCHEMA or type(record["params"]) is not dict:
                raise ValueError("public schema mismatch")
            params = raw.ExecutionParams(**record["params"])
            seed = _hex(record["seed"], maximum=32)
            if len(seed) != 32:
                raise ValueError("seed length mismatch")
            result = cls(raw.Public(params, seed, raw.public_matrix(params, seed), record["b"]))
            if result.to_bytes() != data:
                raise ValueError("public record changed")
            return result
        except (ValueError, TypeError, KeyError, OverflowError):
            raise SerializationError("invalid structured SRGG public key") from None


@dataclass(frozen=True, eq=False, repr=False)
class SigningKey(IBSSigningKey):
    public_key: PublicKey
    _identity: bytes
    tail: tuple = field(repr=False)
    value: raw.Key = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        if type(self.public_key) is not PublicKey:
            raise TypeError("structured PublicKey required")
        _identity(self.identity)
        value = raw.Key(self.public_key.value, self.identity, self.tail)
        object.__setattr__(self, "tail", value.tail)
        object.__setattr__(self, "value", value)

    def __repr__(self): return "StructuredSRGGSigningKey(private=<redacted>)"

    @property
    def identity(self): return self._identity

    @property
    def identity_digest(self): return hash_identity(self.identity, 32)

    def to_bytes(self):
        return _encode(_record("key", public=self.public_key.to_bytes().hex(),
                               identity=self.identity.hex(), tail=self.tail))

    @classmethod
    def from_bytes(cls, data):
        record = _envelope(data, "key", ("public", "identity", "tail"))
        try:
            result = cls(PublicKey.from_bytes(_hex(record["public"])),
                         _hex(record["identity"], maximum=4096), record["tail"])
            if result.to_bytes() != data:
                raise ValueError("key changed")
            return result
        except (ValueError, TypeError, EncodingError, OverflowError):
            raise SerializationError("invalid structured SRGG signing key") from None


@dataclass(eq=False, repr=False)
class MasterSecret(IBSMasterSecret):
    public_key: PublicKey
    witness: tuple = field(repr=False)
    states: dict = field(default_factory=dict, repr=False)
    __hash__ = None

    def __post_init__(self):
        if type(self.public_key) is not PublicKey:
            raise TypeError("structured PublicKey required")
        self.witness = raw.Master(self.public_key.value, self.witness).witness
        if type(self.states) is not dict:
            raise ValueError("structured issuance cache required")
        self.states = dict(self.states)
        self._entries()

    def __repr__(self): return "StructuredSRGGMasterSecret(private=<redacted>)"

    def _entries(self):
        if type(self.states) is not dict or len(self.states) > MAX_USERS:
            raise SerializationError("structured SRGG cache exceeds capacity")
        entries = []
        for identity, entry in self.states.items():
            _identity(identity)
            if type(entry) is not tuple or len(entry) != 2:
                raise SerializationError("invalid structured SRGG cache entry")
            status, key = entry
            if type(status) is not str or status not in ("pending", "failed", "issued"):
                raise SerializationError("invalid structured SRGG cache status")
            if status == "issued":
                if (type(key) is not SigningKey or key.identity != identity
                        or key.public_key != self.public_key):
                    raise SerializationError("structured SRGG cached key mismatch")
                tail = key.tail
            elif key is not None:
                raise SerializationError("unissued structured key must be absent")
            else:
                tail = None
            entries.append([identity.hex(), status, tail])
        return sorted(entries, key=lambda entry: bytes.fromhex(entry[0]))

    def to_bytes(self):
        return _encode(_record("master", public=self.public_key.to_bytes().hex(),
            witness=self.witness, entries=self._entries()))

    @classmethod
    def from_bytes(cls, data):
        record = _envelope(data, "master", ("public", "witness", "entries"))
        try:
            rows = record["entries"]
            if type(rows) is not list or len(rows) > MAX_USERS:
                raise ValueError("cache capacity exceeded")
            parsed, previous = [], None
            for row in rows:
                if type(row) is not list or len(row) != 3:
                    raise ValueError("cache row mismatch")
                identity = _identity(_hex(row[0], maximum=4096))
                if previous is not None and identity <= previous:
                    raise ValueError("duplicate or unsorted identity")
                previous = identity
                status, tail = row[1:]
                if type(status) is not str or status not in ("pending", "failed", "issued"):
                    raise ValueError("cache status mismatch")
                if (status != "issued" and tail is not None) or (status == "issued" and tail is None):
                    raise ValueError("cache key/status mismatch")
                parsed.append((identity, status, tail))
            public = PublicKey.from_bytes(_hex(record["public"]))
            states = {identity: (status, SigningKey(public, identity, tail)
                      if status == "issued" else None) for identity, status, tail in parsed}
            result = cls(public, record["witness"], states)
            if result.to_bytes() != data:
                raise ValueError("master record changed")
            return result
        except (ValueError, TypeError, EncodingError, OverflowError):
            raise SerializationError("invalid structured SRGG master secret") from None


@dataclass(frozen=True, eq=False, repr=False)
class Signature(IBSSignature):
    context: bytes
    response: tuple
    challenge: tuple

    def __post_init__(self):
        if type(self.context) is not bytes or len(self.context) != 32:
            raise ValueError("32-byte structured public context required")
        if not isinstance(self.challenge, (tuple, list)):
            raise ValueError("binary challenge required")
        n = len(self.challenge)
        if not 2 <= n <= 512 or n & (n-1) or any(type(c) is not int or c not in (0, 1) for c in self.challenge):
            raise ValueError("bounded binary challenge required")
        if not isinstance(self.response, (tuple, list)) or not 1 <= len(self.response) <= 41:
            raise ValueError("bounded response required")
        if any(not isinstance(poly, (tuple, list)) or len(poly) != n or any(
                type(x) is not int or abs(x).bit_length() > 256 for x in poly) for poly in self.response):
            raise ValueError("bounded exact response coordinates required")
        object.__setattr__(self, "challenge", tuple(self.challenge))
        object.__setattr__(self, "response", tuple(tuple(poly) for poly in self.response))

    def __repr__(self): return "StructuredSRGGSignature(values=<redacted>)"

    def to_bytes(self):
        return _encode(_record("signature", context=self.context.hex(),
            response=self.response, challenge=self.challenge))

    @classmethod
    def from_bytes(cls, data):
        record = _envelope(data, "signature", ("context", "response", "challenge"))
        try:
            result = cls(_hex(record["context"], maximum=32), record["response"], record["challenge"])
            if result.to_bytes() != data:
                raise ValueError("signature record changed")
            return result
        except (ValueError, TypeError, OverflowError):
            raise SerializationError("invalid structured SRGG signature") from None


def signature_shape(public, signature):
    return (type(public) is PublicKey and type(signature) is Signature
        and signature.context == public.context
        and len(signature.challenge) == public.params.degree
        and len(signature.response) == public.params.columns+1
        and sum(x*x for poly in signature.response for x in poly) <= public.params.signature_norm_cap)


class Backend:
    security_claim = "none"
    backend_admitted = False
    parameters_are_formal = False
    nist_security_category = None

    def __init__(self, *, rng=None):
        self.rng = SecureRandom() if rng is None else rng
        if not callable(getattr(self.rng, "read", None)):
            raise TypeError("random source with read(n) required")

    def _execution(self, params):
        if type(params) is not raw.ExecutionParams:
            raise TypeError("complete structured ExecutionParams required")
        series, scalar = raw.sampler_profile(PROFILE)
        return raw.Execution(params, rng=self.rng, series_options=series, scalar_options=scalar)

    def setup(self, params):
        public, master = self._execution(params).setup()
        key = PublicKey(public)
        return key, MasterSecret(key, master.witness)

    def key_extract(self, master, identity):
        if type(master) is not MasterSecret:
            raise TypeError("structured MasterSecret required")
        identity = _identity(identity)
        master._entries()
        if identity in master.states:
            status, key = master.states[identity]
            if status == "issued":
                return key
            raise SamplingAbort("structured identity pending/failed; no reselection")
        if len(master.states) >= MAX_USERS:
            raise SamplingAbort("structured fixed identity capacity exceeded")
        master.states[identity] = ("pending", None)
        try:
            value = self._execution(master.public_key.params).key_extract(
                raw.Master(master.public_key.value, master.witness), identity)
            key = SigningKey(master.public_key, identity, value.tail)
            master.states[identity] = ("issued", key)
            return key
        except BaseException:
            master.states[identity] = ("failed", None)
            raise

    def sign(self, key, message):
        if type(key) is not SigningKey:
            raise TypeError("structured SigningKey required")
        message = _message(message)
        value = self._execution(key.public_key.params).sign(key.value, message)
        return Signature(value.context, value.response, value.challenge)

    def verify(self, public, identity, message, signature):
        try:
            if not signature_shape(public, signature):
                return False
            identity, message = _identity(identity), _message(message)
            ring = raw.ExactRing(public.params)
            commitment = ring.recover(public.value, raw.identity_target(public.value, identity),
                                      signature.response, signature.challenge)
            return raw.message_challenge(public.value, commitment, message) == signature.challenge
        except (EncodingError, SerializationError, ValueError, TypeError, AttributeError, OverflowError):
            return False

    def load_signature(self, public, data):
        if type(public) is not PublicKey:
            raise TypeError("structured PublicKey required")
        signature = Signature.from_bytes(data)
        if not signature_shape(public, signature):
            raise SerializationError("structured signature context/dimension/norm mismatch")
        return signature


def signature_size(params):
    if type(params) is not raw.ExecutionParams:
        raise TypeError("structured ExecutionParams required")
    cap = isqrt(params.signature_norm_cap)
    return len(Signature(bytes(32), ((-cap,)*params.degree,)*(params.columns+1),
                         (1,)*params.degree).to_bytes())
