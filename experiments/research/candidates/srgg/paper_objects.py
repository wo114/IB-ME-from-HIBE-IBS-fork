"""Strict, separate objects for the published SRGG parameter reproduction.

These formats preserve the paper's compressed user key and do not import the
optimization candidate's raw/user norm gates. Coefficient and wire bounds are
resource limits, not claims about the paper's sampling or security.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256

from ibme.core.errors import EncodingError, SerializationError
from ibme.core.hashing import hash_identity
from ibme.ibs.api import IBSPublicKey, IBSMasterSecret, IBSSigningKey, IBSSignature

from .paper_algebra import PaperRing, identity_target, public_matrix
from .paper_parameters import PaperParams
from .structured_backend import _decode, _encode, _hex, _identity, _message


SCHEMA = "IBME/SRGG-PAPER-OBJECT/1"
MAX_WIRE = 2*1024*1024
MAX_USERS = 64


def _record(kind, **fields):
    if type(kind) is not str or not kind or set(fields) & {"schema", "kind"}:
        raise ValueError("paper object kind/fields required")
    return {"schema": SCHEMA, "kind": kind, **fields}


def _envelope(data, kind, fields):
    record = _decode(data, ("schema", "kind", *fields))
    if (type(record["schema"]) is not str or record["schema"] != SCHEMA
            or type(record["kind"]) is not str or record["kind"] != kind):
        raise SerializationError("paper SRGG object schema/kind mismatch")
    return record


def _parameters(record):
    """Reject Python's bool/int equality aliases in parameter records."""
    if type(record) is not dict:
        raise ValueError("paper parameter record required")
    params = PaperParams.from_record(record)
    expected = params.record()
    if set(record) != set(expected) or any(
            type(record[name]) is not type(value) or record[name] != value
            for name, value in expected.items()):
        raise ValueError("paper parameter source/convention mismatch")
    return params


@dataclass(frozen=True, eq=False)
class PublicKey(IBSPublicKey):
    params: PaperParams
    seed: bytes
    a_hat: tuple
    b: tuple

    def __post_init__(self):
        if type(self.params) is not PaperParams:
            raise TypeError("published PaperParams required")
        _parameters(self.params.record())
        if type(self.seed) is not bytes or len(self.seed) != 32:
            raise ValueError("32-byte paper public seed required")
        p, ring = self.params, PaperRing(self.params)
        a_hat = ring.matrix(self.a_hat, p.rank, p.rank, p.modulus)
        b = ring.matrix(self.b, p.rank, p.rank*p.digits, p.modulus)
        if a_hat != public_matrix(p, self.seed):
            raise ValueError("paper seed/public matrix mismatch")
        object.__setattr__(self, "a_hat", a_hat)
        object.__setattr__(self, "b", b)
        self.to_bytes()

    @property
    def context(self):
        return sha256(self.to_bytes()).digest()

    def to_bytes(self):
        return _encode(_record("public", params=self.params.record(),
                               seed=self.seed.hex(), b=self.b))

    @classmethod
    def from_bytes(cls, data):
        record = _envelope(data, "public", ("params", "seed", "b"))
        try:
            params = _parameters(record["params"])
            seed = _hex(record["seed"], maximum=32)
            result = cls(params, seed, public_matrix(params, seed), record["b"])
            if result.to_bytes() != data:
                raise ValueError("paper public record changed")
            return result
        except (ValueError, TypeError, KeyError, OverflowError):
            raise SerializationError("invalid paper SRGG public key") from None


@dataclass(frozen=True, eq=False, repr=False)
class SigningKey(IBSSigningKey):
    public_key: PublicKey
    _identity: bytes
    tail: tuple = field(repr=False)
    full: tuple = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        if type(self.public_key) is not PublicKey:
            raise TypeError("paper PublicKey required")
        identity = _identity(self._identity)
        p, ring = self.public_key.params, PaperRing(self.public_key.params)
        tail = ring.vector(self.tail, (1+p.digits)*p.rank)
        full = ring.reconstruct(self.public_key,
                                identity_target(self.public_key, identity), tail)
        # PaperRing checks exact 256-bit coordinates, not a sampling norm class.
        full = ring.vector(full, p.columns)
        object.__setattr__(self, "_identity", identity)
        object.__setattr__(self, "tail", tail)
        object.__setattr__(self, "full", full)
        self.to_bytes()

    def __repr__(self):
        return "PaperSRGGSigningKey(private=<redacted>)"

    @property
    def identity(self):
        return self._identity

    @property
    def identity_digest(self):
        return hash_identity(self.identity, 32)

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
                raise ValueError("paper key record changed")
            return result
        except (ValueError, TypeError, EncodingError, OverflowError):
            raise SerializationError("invalid paper SRGG signing key") from None


@dataclass(eq=False, repr=False)
class MasterSecret(IBSMasterSecret):
    public_key: PublicKey
    witness: tuple = field(repr=False)
    states: dict = field(default_factory=dict, repr=False)
    __hash__ = None

    def __post_init__(self):
        if type(self.public_key) is not PublicKey:
            raise TypeError("paper PublicKey required")
        p, ring = self.public_key.params, PaperRing(self.public_key.params)
        witness = ring.matrix(self.witness, 2*p.rank, p.rank*p.digits)
        if (any(x not in (-1, 0, 1) for row in witness for poly in row for x in poly)
                or not ring.trapdoor_relation(self.public_key, witness)):
            raise ValueError("paper CBD1 trapdoor/public relation mismatch")
        self.witness = witness
        if type(self.states) is not dict:
            raise ValueError("paper issuance cache required")
        self.states = dict(self.states)
        self._entries()

    def __repr__(self):
        return "PaperSRGGMasterSecret(private=<redacted>)"

    def _entries(self):
        if type(self.states) is not dict or len(self.states) > MAX_USERS:
            raise SerializationError("paper SRGG cache exceeds capacity")
        entries = []
        for identity, entry in self.states.items():
            if type(identity) is not bytes:
                raise SerializationError("canonical paper cache identity bytes required")
            _identity(identity)
            if type(entry) is not tuple or len(entry) != 2:
                raise SerializationError("invalid paper SRGG cache entry")
            status, key = entry
            if type(status) is not str or status not in ("pending", "failed", "issued"):
                raise SerializationError("invalid paper SRGG cache status")
            if status == "issued":
                if (type(key) is not SigningKey or key.identity != identity
                        or key.public_key != self.public_key):
                    raise SerializationError("paper SRGG cached key mismatch")
                tail = key.tail
            elif key is not None:
                raise SerializationError("unissued paper key must be absent")
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
                raise ValueError("paper cache capacity exceeded")
            parsed, previous = [], None
            for row in rows:
                if type(row) is not list or len(row) != 3:
                    raise ValueError("paper cache row mismatch")
                identity = _identity(_hex(row[0], maximum=4096))
                if previous is not None and identity <= previous:
                    raise ValueError("duplicate or unsorted paper identity")
                previous = identity
                status, tail = row[1:]
                if type(status) is not str or status not in ("pending", "failed", "issued"):
                    raise ValueError("paper cache status mismatch")
                if (status != "issued" and tail is not None) or (status == "issued" and tail is None):
                    raise ValueError("paper cache key/status mismatch")
                parsed.append((identity, status, tail))
            public = PublicKey.from_bytes(_hex(record["public"]))
            states = {identity: (status, SigningKey(public, identity, tail)
                      if status == "issued" else None) for identity, status, tail in parsed}
            result = cls(public, record["witness"], states)
            if result.to_bytes() != data:
                raise ValueError("paper master record changed")
            return result
        except (ValueError, TypeError, EncodingError, OverflowError):
            raise SerializationError("invalid paper SRGG master secret") from None


@dataclass(frozen=True, eq=False, repr=False)
class Signature(IBSSignature):
    context: bytes
    response: tuple
    challenge: tuple

    def __post_init__(self):
        if type(self.context) is not bytes or len(self.context) != 32:
            raise ValueError("32-byte paper public context required")
        if not isinstance(self.challenge, (tuple, list)):
            raise ValueError("binary paper challenge required")
        n = len(self.challenge)
        if (not 2 <= n <= 512 or n & (n-1)
                or any(type(c) is not int or c not in (0, 1) for c in self.challenge)):
            raise ValueError("bounded binary paper challenge required")
        if not isinstance(self.response, (tuple, list)) or not 1 <= len(self.response) <= 17:
            raise ValueError("bounded paper response required")
        if any(not isinstance(poly, (tuple, list)) or len(poly) != n or any(
                type(x) is not int or abs(x).bit_length() > 256 for x in poly)
                for poly in self.response):
            raise ValueError("bounded exact paper response coordinates required")
        object.__setattr__(self, "challenge", tuple(self.challenge))
        object.__setattr__(self, "response", tuple(tuple(poly) for poly in self.response))
        self.to_bytes()

    def __repr__(self):
        return "PaperSRGGSignature(values=<redacted>)"

    def to_bytes(self):
        return _encode(_record("signature", context=self.context.hex(),
                               response=self.response, challenge=self.challenge))

    @classmethod
    def from_bytes(cls, data):
        record = _envelope(data, "signature", ("context", "response", "challenge"))
        try:
            result = cls(_hex(record["context"], maximum=32),
                         record["response"], record["challenge"])
            if result.to_bytes() != data:
                raise ValueError("paper signature record changed")
            return result
        except (ValueError, TypeError, OverflowError):
            raise SerializationError("invalid paper SRGG signature") from None
