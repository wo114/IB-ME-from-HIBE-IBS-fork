"""Self-contained CHKP object wire; public parameters never name private data.

Private objects include the complete public context and canonical state. The
trusted suite checks that context after decoding. No global key registry,
sampling, root generation or native conversion is used during restoration.
These snapshots are sensitive plaintext, not authenticated storage.
"""

from dataclasses import dataclass, field
from hmac import compare_digest

from ibme.core.encoding import encode_bytes
from ibme.core.errors import InvalidParameterError, SerializationError

from .params import CHKPParams

MAGIC = b"IBME:CHKP:OBJECT:v1"
MAX_OBJECT_BYTES = 16*2**20
MAX_PUBLIC_BYTES = 2*2**20


def _frame(kind, *values):
    raw = MAGIC + encode_bytes(kind) + b"".join(encode_bytes(value) for value in values)
    if len(raw) > MAX_OBJECT_BYTES:
        raise SerializationError("CHKP object exceeds its private wire budget")
    return raw


def _reader(data, kind):
    from ibme.lattice.chkp.identity import Reader
    reader = Reader(data, maximum=MAX_OBJECT_BYTES)
    if reader.take(len(MAGIC)) != MAGIC or reader.blob(32) != kind:
        raise SerializationError("unknown CHKP object type or version")
    return reader


def _scope(public):
    from ibme.lattice.chkp.delegation_state import DelegationScope
    p = public.params
    # The complete public parameter encoding is also the fixed sampler profile.
    # This contains no basis-dependent geometry, scalar widths or diagnostics.
    profile = p.to_bytes()
    return DelegationScope(public.oracle, p.root_gs_squared_bound,
                           p.parent_width_squared, p.leaf_width_squared,
                           profile, profile, epsilon_bits=p.epsilon_bits,
                           max_receivers=p.max_receivers)


def _same_scope(actual, expected):
    if not compare_digest(actual.to_bytes(), expected.to_bytes()):
        raise InvalidParameterError("CHKP secret differs from its public parameter context")


def _single_leaf_snapshot(key):
    from ibme.lattice.chkp.leaf_state import FixedSeedState
    state = FixedSeedState(key.plan.scope)
    state.resolve(key.plan.sender, lambda plan: key.preimages)
    return state.to_bytes()


@dataclass(frozen=True)
class CHKPPublicKey:
    params: CHKPParams
    oracle: object = field(repr=False)

    security_claim = "none"
    backend_admitted = False
    parameters_are_formal = False

    def __post_init__(self):
        from ibme.lattice.chkp.identity import ROHIBEContext
        if not isinstance(self.params, CHKPParams) or not isinstance(self.oracle, ROHIBEContext):
            raise InvalidParameterError("CHKP needs canonical parameters and public root")
        p, o = self.params, self.oracle
        if ((o.n, o.m, o.q, o.identity_bytes) != (p.n, p.m, p.q, p.identity_bytes)
                or o.public_configuration != p.to_bytes()):
            raise InvalidParameterError("CHKP public root differs from complete parameter snapshot")

    @property
    def context(self):
        return self.oracle.context

    def to_bytes(self):
        return _frame(b"PUBLIC", self.params.to_bytes(), self.oracle.to_bytes())

    @classmethod
    def from_bytes(cls, data):
        from ibme.lattice.chkp.identity import ROHIBEContext
        r = _reader(data, b"PUBLIC")
        try:
            params = CHKPParams.from_bytes(r.blob(4096))
            oracle = ROHIBEContext.from_bytes(r.blob(MAX_PUBLIC_BYTES))
            r.finish()
            result = cls(params, oracle)
            if result.to_bytes() != bytes(data):
                raise SerializationError("noncanonical CHKP public key")
            return result
        except (TypeError, ValueError, InvalidParameterError) as exc:
            raise SerializationError("invalid CHKP public key") from exc


@dataclass(frozen=True, repr=False)
class CHKPMasterSecret:
    public_key: CHKPPublicKey
    state: object = field(repr=False)

    def __post_init__(self):
        from ibme.lattice.chkp.delegation_state import MasterTreeState
        if not isinstance(self.public_key, CHKPPublicKey) or not isinstance(self.state, MasterTreeState):
            raise InvalidParameterError("canonical CHKP master state required")
        _same_scope(self.state.scope, _scope(self.public_key))

    @property
    def params(self):
        return self.public_key.params

    def __repr__(self):
        return "CHKPMasterSecret(RESEARCH, private state hidden)"

    def to_bytes(self):
        return _frame(b"MASTER", self.public_key.to_bytes(), self.state.to_bytes())

    @classmethod
    def from_bytes(cls, data):
        from ibme.lattice.chkp.delegation_state import MasterTreeState
        r = _reader(data, b"MASTER")
        public = CHKPPublicKey.from_bytes(r.blob(MAX_PUBLIC_BYTES))
        try:
            state = MasterTreeState.from_bytes(r.blob(MAX_OBJECT_BYTES), expected_scope=_scope(public))
            r.finish()
            return cls(public, state)
        except (TypeError, ValueError, InvalidParameterError) as exc:
            raise SerializationError("invalid CHKP master snapshot") from exc


@dataclass(frozen=True, repr=False)
class CHKPLevel1SecretKey:
    public_key: CHKPPublicKey
    state: object = field(repr=False)

    def __post_init__(self):
        from ibme.lattice.chkp.delegation_state import ReceiverState
        if not isinstance(self.public_key, CHKPPublicKey) or not isinstance(self.state, ReceiverState):
            raise InvalidParameterError("canonical CHKP receiver state required")
        _same_scope(self.state.scope, _scope(self.public_key))

    @property
    def params(self):
        return self.public_key.params

    @property
    def identity(self):
        return self.state.identity

    def __repr__(self):
        return "CHKPLevel1SecretKey(RESEARCH, private state hidden)"

    def to_bytes(self):
        return _frame(b"LEVEL1", self.public_key.to_bytes(), self.state.to_bytes())

    @classmethod
    def from_bytes(cls, data):
        from ibme.lattice.chkp.delegation_state import ReceiverState
        r = _reader(data, b"LEVEL1")
        public = CHKPPublicKey.from_bytes(r.blob(MAX_PUBLIC_BYTES))
        try:
            state = ReceiverState.from_bytes(r.blob(MAX_OBJECT_BYTES), expected_scope=_scope(public))
            r.finish()
            return cls(public, state)
        except (TypeError, ValueError, InvalidParameterError) as exc:
            raise SerializationError("invalid CHKP receiver snapshot") from exc


@dataclass(frozen=True, repr=False)
class CHKPLevel2SecretKey:
    public_key: CHKPPublicKey
    key: object = field(repr=False)

    def __post_init__(self):
        from ibme.lattice.chkp.leaf_state import FixedSeedKey
        if not isinstance(self.public_key, CHKPPublicKey) or not isinstance(self.key, FixedSeedKey):
            raise InvalidParameterError("canonical CHKP fixed leaf key required")
        _same_scope(self.key.plan.scope, _scope(self.public_key).seed_scope(self.key.plan.scope.receiver))

    @property
    def params(self):
        return self.public_key.params

    @property
    def parent_identity(self):
        return self.key.plan.scope.receiver

    @property
    def child_identity(self):
        return self.key.plan.sender

    def __repr__(self):
        return "CHKPLevel2SecretKey(RESEARCH, fixed private preimages hidden)"

    def to_bytes(self):
        return _frame(b"LEVEL2", self.public_key.to_bytes(), self.parent_identity,
                      self.child_identity, _single_leaf_snapshot(self.key))

    @classmethod
    def from_bytes(cls, data):
        from ibme.lattice.chkp.leaf_state import FixedSeedState
        r = _reader(data, b"LEVEL2")
        public = CHKPPublicKey.from_bytes(r.blob(MAX_PUBLIC_BYTES))
        try:
            receiver, sender = r.blob(public.params.identity_bytes), r.blob(public.params.identity_bytes)
            raw = r.blob(MAX_OBJECT_BYTES)
            r.finish()
            scope = _scope(public).seed_scope(receiver)
            state = FixedSeedState.from_bytes(raw, expected_scope=scope)
            key = state.lookup(sender)
            # A standalone leaf object contains exactly its own ready address;
            # no hidden additional addresses or failed state are accepted.
            if _single_leaf_snapshot(key) != raw:
                raise SerializationError("CHKP leaf wire must contain exactly one ready address")
            return cls(public, key)
        except (KeyError, TypeError, ValueError, InvalidParameterError) as exc:
            raise SerializationError("invalid CHKP fixed leaf snapshot") from exc


@dataclass(frozen=True, repr=False)
class CHKPCiphertext:
    capsule: object = field(repr=False)

    security_claim = "none"
    backend_admitted = False

    def __post_init__(self):
        from ibme.lattice.chkp.seed_kem import SeedCapsule
        if not isinstance(self.capsule, SeedCapsule):
            raise InvalidParameterError("canonical CHKP seed capsule required")

    def to_bytes(self):
        return self.capsule.to_bytes()

    @classmethod
    def from_bytes(cls, data):
        from ibme.lattice.chkp.seed_kem import SeedCapsule
        return cls(SeedCapsule.from_bytes(data))


def check_object(value, params):
    if not isinstance(value, (CHKPPublicKey, CHKPMasterSecret, CHKPLevel1SecretKey, CHKPLevel2SecretKey)):
        raise SerializationError("selected CHKP object type mismatch")
    if value.params != params:
        raise SerializationError("CHKP object differs from the complete selected parameter snapshot")
