"""Own-version structured H/G objects and fixed issuance snapshots.

Opaque private snapshots are plaintext private key material. Parsing checks
equations, norms, contexts and fixed-state shape, not sampling provenance or
anti-rollback. The shared CLI owns crash-safe on-disk transactions.
"""

from dataclasses import dataclass, field
from hmac import compare_digest
from threading import RLock

from ibme.core.encoding import encode_bytes
from ibme.core.errors import InvalidParameterError, SerializationError, EncodingError
from ibme.core.types import validate_identity
from ibme.lattice.chkp.identity import Reader, ROHIBEContext
from ibme.lattice.chkp.leaf_state import SeedScope, FixedSeedState, FixedSeedKey
from .params import StructuredHIBEParams

MAGIC = b"IBME:MP12-STRUCTURED-HG:OBJECT:v1"
MAX_BYTES = 32*2**20
MAX_PUBLIC = 2*2**20


def _frame(kind, *values):
    raw = MAGIC+encode_bytes(kind)+b"".join(encode_bytes(v) for v in values)
    if len(raw) > MAX_BYTES:
        raise SerializationError("structured HIBE snapshot resource limit")
    return raw


def _reader(raw, kind):
    r = Reader(raw, maximum=MAX_BYTES)
    if r.take(len(MAGIC)) != MAGIC or r.blob(32) != kind:
        raise SerializationError("unknown structured HIBE object/version")
    return r


def seed_scope(public, receiver):
    p = public.params
    return SeedScope(public.oracle, receiver, p.leaf_width_squared,
        p.to_bytes(), max_children=p.max_children)


def _single_leaf(key):
    state = FixedSeedState(key.plan.scope)
    state.resolve(key.plan.sender, lambda plan: key.preimages)
    return state.to_bytes()


@dataclass(frozen=True)
class StructuredPublicKey:
    params: StructuredHIBEParams
    oracle: ROHIBEContext = field(repr=False)

    security_claim = "none"
    backend_admitted = False
    parameters_are_formal = False

    def __post_init__(self):
        p, o = self.params, self.oracle
        if (not isinstance(p, StructuredHIBEParams) or not isinstance(o, ROHIBEContext)
                or (o.n, o.m, o.q, o.identity_bytes) != (p.n, p.m, p.q, p.identity_bytes)
                or o.public_configuration != p.to_bytes()
                or any(o.root_rows[i][j] != int(i == j) for i in range(p.n) for j in range(p.n))):
            raise InvalidParameterError("structured HIBE public root/profile mismatch")

    @property
    def context(self): return self.oracle.context

    def to_bytes(self): return _frame(b"PUBLIC", self.params.to_bytes(), self.oracle.to_bytes())

    @classmethod
    def from_bytes(cls, raw):
        r = _reader(raw, b"PUBLIC")
        try:
            p = StructuredHIBEParams.from_bytes(r.blob(4096))
            o = ROHIBEContext.from_bytes(r.blob(MAX_PUBLIC))
            r.finish()
            result = cls(p, o)
            if result.to_bytes() != bytes(raw): raise ValueError("noncanonical public key")
            return result
        except (TypeError, ValueError, InvalidParameterError, EncodingError) as exc:
            raise SerializationError("invalid structured HIBE public key") from exc


def _trapdoor(public, trapdoor, receiver=None):
    from ibme.lattice.matrix_sampling.mp12_structured import StructuredTrapdoor
    p = public.params
    if not isinstance(trapdoor, StructuredTrapdoor) or (trapdoor.n, trapdoor.q) != (p.n, p.q):
        raise InvalidParameterError("structured HIBE requires a validated structured trapdoor")
    if receiver is None:
        bound, rows, prefix = p.root_bound, public.oracle.root_rows, 2*p.n
    else:
        bound, rows, prefix = p.parent_bound, public.oracle.parent_rows(receiver), 2*p.m-p.w
        limit = p.parent_sample_dimension*p.parent_width_squared
        if any(sum(trapdoor.r[i][j]**2 for i in range(trapdoor.prefix)) > limit for j in range(trapdoor.w)):
            raise InvalidParameterError("structured HIBE parent column norm limit")
    if (trapdoor.prefix != prefix or trapdoor.frobenius_squared_bound != bound
            or trapdoor.public.rows != rows):
        raise InvalidParameterError("structured HIBE trapdoor context/identity/declared-bound mismatch")


@dataclass(frozen=True, repr=False)
class StructuredLevel1Key:
    public_key: StructuredPublicKey
    identity: bytes
    trapdoor: object = field(repr=False)
    leaves: object = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        if not isinstance(self.public_key, StructuredPublicKey):
            raise InvalidParameterError("structured HIBE public context required")
        identity = validate_identity(self.identity, max_bytes=self.params.identity_bytes)
        object.__setattr__(self, "identity", identity)
        _trapdoor(self.public_key, self.trapdoor, identity)
        expected = seed_scope(self.public_key, identity)
        if self.leaves is None:
            object.__setattr__(self, "leaves", FixedSeedState(expected))
        elif not isinstance(self.leaves, FixedSeedState) or self.leaves.scope.to_bytes() != expected.to_bytes():
            raise InvalidParameterError("structured HIBE leaf state context/profile mismatch")

    @property
    def params(self): return self.public_key.params

    def __repr__(self): return "StructuredLevel1Key(RESEARCH, private state hidden)"

    def to_bytes(self):
        return _frame(b"LEVEL1", self.public_key.to_bytes(), self.identity,
            self.trapdoor.to_bytes(), self.leaves.to_bytes())

    @classmethod
    def from_bytes(cls, raw):
        from ibme.lattice.matrix_sampling.mp12_structured import StructuredTrapdoor
        r = _reader(raw, b"LEVEL1")
        try:
            public = StructuredPublicKey.from_bytes(r.blob(MAX_PUBLIC))
            receiver = r.blob(public.params.identity_bytes)
            t = StructuredTrapdoor.from_bytes(r.blob(MAX_BYTES))
            leaves = FixedSeedState.from_bytes(r.blob(MAX_BYTES), expected_scope=seed_scope(public, receiver))
            r.finish()
            return cls(public, receiver, t, leaves)
        except (TypeError, ValueError, InvalidParameterError, EncodingError) as exc:
            raise SerializationError("invalid structured HIBE first-level key") from exc


class StructuredMasterSecret:
    def __init__(self, public_key, trapdoor):
        if not isinstance(public_key, StructuredPublicKey):
            raise InvalidParameterError("structured HIBE public context required")
        _trapdoor(public_key, trapdoor)
        self.public_key, self.trapdoor = public_key, trapdoor
        self._entries, self._lock = {}, RLock()

    @property
    def params(self): return self.public_key.params

    def __repr__(self): return "StructuredMasterSecret(RESEARCH, private state hidden)"

    def lookup(self, receiver):
        receiver = validate_identity(receiver, max_bytes=self.params.identity_bytes)
        with self._lock:
            if receiver not in self._entries: raise KeyError("receiver not yet issued")
            value = self._entries[receiver]
            if value is None: raise InvalidParameterError("structured receiver failed/pending; no reissue")
            return value

    def issue(self, receiver, generate):
        receiver = validate_identity(receiver, max_bytes=self.params.identity_bytes)
        with self._lock:
            if receiver in self._entries: return self.lookup(receiver)
            if len(self._entries) >= self.params.max_receivers:
                raise InvalidParameterError("structured receiver capacity; no eviction")
            self._entries[receiver] = None
            value = generate()
            if (not isinstance(value, StructuredLevel1Key) or value.identity != receiver
                    or value.public_key.to_bytes() != self.public_key.to_bytes()):
                raise InvalidParameterError("structured issued receiver binding")
            self._entries[receiver] = value
            try: self.to_bytes()
            except Exception:
                self._entries[receiver] = None
                raise
            return value

    def to_bytes(self):
        with self._lock:
            body = len(self._entries).to_bytes(4, "big")
            for identity, value in sorted(self._entries.items()):
                body += encode_bytes(identity)+bytes([int(value is not None)])
                if value is not None: body += encode_bytes(value.to_bytes())
            return _frame(b"MASTER", self.public_key.to_bytes(), self.trapdoor.to_bytes(), body)

    @classmethod
    def from_bytes(cls, raw):
        from ibme.lattice.matrix_sampling.mp12_structured import StructuredTrapdoor
        r = _reader(raw, b"MASTER")
        try:
            public = StructuredPublicKey.from_bytes(r.blob(MAX_PUBLIC))
            t = StructuredTrapdoor.from_bytes(r.blob(MAX_BYTES))
            entries = Reader(r.blob(MAX_BYTES), maximum=MAX_BYTES)
            r.finish()
            result = cls(public, t)
            count, previous = entries.number(), None
            if count > public.params.max_receivers: raise ValueError("structured master capacity")
            for _ in range(count):
                receiver = validate_identity(entries.blob(public.params.identity_bytes), max_bytes=public.params.identity_bytes)
                if previous is not None and receiver <= previous: raise ValueError("duplicate/unordered receiver")
                previous = receiver
                status = entries.number(1)
                if status not in (0, 1): raise ValueError("structured receiver status")
                value = None if status == 0 else StructuredLevel1Key.from_bytes(entries.blob(MAX_BYTES))
                if value is not None and (value.identity != receiver or value.public_key.to_bytes() != public.to_bytes()):
                    raise ValueError("structured cached receiver binding")
                result._entries[receiver] = value
            entries.finish()
            if result.to_bytes() != bytes(raw): raise ValueError("noncanonical structured master")
            return result
        except (TypeError, ValueError, InvalidParameterError, EncodingError) as exc:
            raise SerializationError("invalid structured HIBE master snapshot") from exc


@dataclass(frozen=True, repr=False)
class StructuredLevel2Key:
    public_key: StructuredPublicKey
    key: FixedSeedKey = field(repr=False)

    def __post_init__(self):
        if (not isinstance(self.public_key, StructuredPublicKey) or not isinstance(self.key, FixedSeedKey)
                or self.key.plan.scope.to_bytes() != seed_scope(self.public_key, self.key.plan.scope.receiver).to_bytes()):
            raise InvalidParameterError("structured HIBE fixed leaf context/profile mismatch")

    @property
    def params(self): return self.public_key.params

    @property
    def parent_identity(self): return self.key.plan.scope.receiver

    @property
    def child_identity(self): return self.key.plan.sender

    def __repr__(self): return "StructuredLevel2Key(RESEARCH, private preimages hidden)"

    def to_bytes(self):
        return _frame(b"LEVEL2", self.public_key.to_bytes(), self.parent_identity,
            self.child_identity, _single_leaf(self.key))

    @classmethod
    def from_bytes(cls, raw):
        r = _reader(raw, b"LEVEL2")
        try:
            public = StructuredPublicKey.from_bytes(r.blob(MAX_PUBLIC))
            receiver, sender = r.blob(public.params.identity_bytes), r.blob(public.params.identity_bytes)
            snapshot = r.blob(MAX_BYTES)
            r.finish()
            state = FixedSeedState.from_bytes(snapshot, expected_scope=seed_scope(public, receiver))
            key = state.lookup(sender)
            if _single_leaf(key) != snapshot: raise ValueError("leaf must contain exactly one ready address")
            return cls(public, key)
        except (KeyError, TypeError, ValueError, InvalidParameterError, EncodingError) as exc:
            raise SerializationError("invalid structured HIBE fixed leaf") from exc


@dataclass(frozen=True, repr=False)
class StructuredCiphertext:
    capsule: object = field(repr=False)

    def __post_init__(self):
        from ibme.lattice.chkp.seed_kem import SeedCapsule
        if not isinstance(self.capsule, SeedCapsule):
            raise InvalidParameterError("structured HIBE seed capsule required")

    def to_bytes(self): return _frame(b"CIPHERTEXT", self.capsule.to_bytes())

    @classmethod
    def from_bytes(cls, raw):
        from ibme.lattice.chkp.seed_kem import SeedCapsule
        r = _reader(raw, b"CIPHERTEXT")
        capsule = SeedCapsule.from_bytes(r.blob(MAX_PUBLIC))
        r.finish()
        return cls(capsule)


def check_object(value, params):
    if not isinstance(value, (StructuredPublicKey, StructuredMasterSecret, StructuredLevel1Key, StructuredLevel2Key)) or value.params != params:
        raise SerializationError("structured HIBE object differs from complete selected parameters")
