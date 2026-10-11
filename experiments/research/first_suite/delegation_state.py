"""Single-owner master/parent state around the real first-suite CHKP oracles.

CHKP section 5.2--5.3: complete parent bases permit delegation; terminal
preimages remain fixed. These objects bind actual matrices, complete integer
bases, published GS/width bounds and canonical child snapshots. They do NOT
implement GenBasis/RandBasis/GPV, certify a callback's distribution, or provide
the byte HIBE/CLI. Independent clones, stale snapshots and multiple issuers
remain outside the unique-owner consistency model.
"""

from dataclasses import dataclass, field
from fractions import Fraction
from threading import RLock

from sage.all import QQ, matrix

from ibme.core.encoding import encode_bytes
from ibme.core.errors import EncodingError, InvalidParameterError, SerializationError
from ibme.core.types import validate_identity
from experiments.research.chkp_basis import KernelBasis, ModMatrixReference
from experiments.research.ibme_joint_parameters import smoothing_factor

from .identity import Reader, ROHIBEContext, SEED_BITS, checked_bytes, checked_int
from .leaf_state import (MAX_WIRE, VECTOR_BITS, FixedSeedState, SeedScope,
                         _read_signed, _signed, _uint, _width)

MASTER_MAGIC = b"IBME:CHKP:MASTER-TREE:v1"
PARENT_MAGIC = b"IBME:CHKP:DELEGATED-PARENT:v1"
MAX_RECEIVERS = 8
MAX_BASIS_ENTRIES = 2**20


def _rational(value):
    value = _width(value)
    return _uint(value.numerator) + _uint(value.denominator)


@dataclass(frozen=True, repr=False)
class DelegationScope:
    oracle: ROHIBEContext
    root_gs_squared_bound: Fraction
    parent_width_squared: Fraction
    leaf_width_squared: Fraction
    parent_profile: bytes
    leaf_profile: bytes
    epsilon_bits: int = 32
    max_receivers: int = MAX_RECEIVERS

    def __post_init__(self):
        if not isinstance(self.oracle, ROHIBEContext):
            raise InvalidParameterError("canonical ROHIBE root required")
        for name in ("root_gs_squared_bound", "parent_width_squared", "leaf_width_squared"):
            object.__setattr__(self, name, _width(getattr(self, name)))
        for name in ("parent_profile", "leaf_profile"):
            object.__setattr__(self, name, checked_bytes(getattr(self, name), name, 4096))
        checked_int(self.epsilon_bits, "epsilon bits", 2, 64)
        checked_int(self.max_receivers, "receiver capacity", 1, MAX_RECEIVERS)
        if self.root_gs_squared_bound < 1:
            raise InvalidParameterError("complete integer kernel root GS upper bound must be >= 1")
        parent_dimension, leaf_dimension = 2 * self.oracle.m, 3 * self.oracle.m
        if self.parent_width_squared < 4 * self.root_gs_squared_bound * smoothing_factor(parent_dimension, self.epsilon_bits):
            raise InvalidParameterError("published parent width fails existing C1-exec rule")
        if self.leaf_width_squared < 4 * self.parent_gs_squared_bound * smoothing_factor(leaf_dimension, self.epsilon_bits):
            raise InvalidParameterError("published leaf width fails existing C1-exec rule")

    @property
    def parent_gs_squared_bound(self):
        return self.parent_width_squared * 2 * self.oracle.m

    def seed_scope(self, receiver):
        return SeedScope(self.oracle, receiver, self.leaf_width_squared, self.leaf_profile)

    def to_bytes(self):
        return (encode_bytes(self.oracle.to_bytes()) + _rational(self.root_gs_squared_bound)
                + _rational(self.parent_width_squared) + _rational(self.leaf_width_squared)
                + encode_bytes(self.parent_profile) + encode_bytes(self.leaf_profile)
                + self.epsilon_bits.to_bytes(4, "big") + self.max_receivers.to_bytes(4, "big"))


def _basis_size_gate(dimension):
    if type(dimension) is not int or dimension < 1 or dimension**2 > MAX_BASIS_ENTRIES:
        raise InvalidParameterError("complete integer basis entry budget exceeded")


def validate_basis(basis, public_rows, q, gs_squared_upper):
    """Exact primitive-side binding; distribution/GenBasis remain separate."""
    dimension = len(public_rows[0])
    _basis_size_gate(dimension)
    if not isinstance(basis, KernelBasis) or basis.public.q != q or basis.public.rows != public_rows:
        raise InvalidParameterError("secret basis differs from real root/identity public matrix")
    if len(basis.basis_rows) != dimension or any(len(row) != dimension for row in basis.basis_rows):
        raise InvalidParameterError("wrong complete integer basis shape")
    if any(type(x) is not int or abs(x) >= 2**VECTOR_BITS for row in basis.basis_rows for x in row):
        raise InvalidParameterError("basis integer exceeds private wire budget")
    checked = KernelBasis(ModMatrixReference(public_rows, q), basis.basis_rows)
    # Orthogonal projection cannot increase norm: ||b_i*|| <= ||b_i||.
    # This exact sufficient certificate avoids expensive rational GS when all
    # column norms already satisfy the declared bound. If it does not certify
    # the input, preserve the exact GS check; no previously valid key is lost.
    upper = QQ(str(gs_squared_upper))
    column_norms = tuple(sum(row[j] * row[j] for row in checked.basis_rows) for j in range(dimension))
    if max(column_norms) <= upper:
        return checked
    orthogonal, _ = matrix(QQ, checked.basis_rows).transpose().gram_schmidt()
    if max(row.dot_product(row) for row in orthogonal.rows()) > upper:
        raise InvalidParameterError("secret basis exceeds declared Gram-Schmidt upper bound")
    return checked


def _dump_basis(basis):
    dimension = basis.public.ncols
    _basis_size_gate(dimension)
    return dimension.to_bytes(4, "big") + b"".join(_signed(x) for row in basis.basis_rows for x in row)


def _load_basis(raw, public_rows, q):
    r = Reader(raw, maximum=MAX_WIRE)
    dimension = len(public_rows[0])
    _basis_size_gate(dimension)
    if r.number() != dimension or len(r.data) - r.pos < dimension**2 * 6:
        raise SerializationError("wrong/truncated private basis dimensions")
    rows = tuple(tuple(_read_signed(r) for _ in range(dimension)) for _ in range(dimension))
    r.finish()
    try:
        # The enclosing master/receiver constructor performs binding/GS once.
        # Parse and certify the complete kernel here; do not duplicate GS.
        return KernelBasis(ModMatrixReference(public_rows, q), rows)
    except (ValueError, InvalidParameterError) as exc:
        raise SerializationError("invalid private basis binding: " + str(exc)) from exc


@dataclass(frozen=True, repr=False)
class ParentDelegationPlan:
    scope: DelegationScope
    receiver: bytes
    root_basis: KernelBasis = field(repr=False)


@dataclass(frozen=True, repr=False)
class LeafDelegationPlan:
    parent_basis: KernelBasis = field(repr=False)
    seed_plan: object = field(repr=False)


class ParentAddressBlocked(InvalidParameterError):
    """The receiver's earlier delegation failed; do not retry it."""


class ReceiverState:
    security_claim = "none"
    backend_admitted = False

    def __init__(self, scope, receiver, basis, *, seed_state=None):
        if not isinstance(scope, DelegationScope):
            raise InvalidParameterError("validated delegation scope required")
        identity = validate_identity(receiver, max_bytes=scope.oracle.identity_bytes)
        self._scope, self._identity = scope, identity
        self._basis = validate_basis(basis, scope.oracle.parent_rows(identity), scope.oracle.q, scope.parent_gs_squared_bound)
        expected = scope.seed_scope(identity)
        if seed_state is not None and (not isinstance(seed_state, FixedSeedState) or seed_state.scope != expected):
            raise InvalidParameterError("parent and fixed child state have different scopes")
        self._seeds = FixedSeedState(expected) if seed_state is None else seed_state
        self._lock, self._owner_reserve = RLock(), None

    @property
    def identity(self): return self._identity

    @property
    def scope(self): return self._scope

    def __repr__(self): return "ReceiverState(RESEARCH, parent basis/private child state hidden)"

    def lookup(self, sender):
        with self._lock:
            return self._seeds.lookup(sender)

    def derive(self, sender, generate):
        if not callable(generate):
            raise TypeError("trusted leaf sampler adapter required")
        sender = validate_identity(sender, max_bytes=self.scope.oracle.identity_bytes)
        with self._lock:
            try:
                return self._seeds.lookup(sender)
            except KeyError:
                pass
            growth = 4 + len(sender) + 1 + SEED_BITS * self.scope.oracle.leaf_dimension * (5 + VECTOR_BITS // 8)
            if len(self.to_bytes()) + growth > MAX_WIRE:
                raise InvalidParameterError("parent plus future leaf private wire exceeds budget")
            if self._owner_reserve is not None:
                self._owner_reserve(growth)
            return self._seeds.resolve(sender, lambda plan: generate(LeafDelegationPlan(self._basis, plan)))

    def to_bytes(self):
        with self._lock:
            raw = (PARENT_MAGIC + encode_bytes(self.scope.to_bytes()) + encode_bytes(self.identity)
                   + encode_bytes(_dump_basis(self._basis)) + encode_bytes(self._seeds.to_bytes()))
            if len(raw) > MAX_WIRE:
                raise SerializationError("receiver private wire exceeds budget")
            return raw

    @classmethod
    def from_bytes(cls, data, *, expected_scope, expected_identity=None):
        if not isinstance(expected_scope, DelegationScope):
            raise TypeError("trusted delegation scope required")
        r = Reader(data, maximum=MAX_WIRE)
        if r.take(len(PARENT_MAGIC)) != PARENT_MAGIC or r.blob(MAX_WIRE) != expected_scope.to_bytes():
            raise SerializationError("receiver private version or scope mismatch")
        try:
            identity = validate_identity(r.blob(expected_scope.oracle.identity_bytes), max_bytes=expected_scope.oracle.identity_bytes)
            if expected_identity is not None and identity != validate_identity(expected_identity, max_bytes=expected_scope.oracle.identity_bytes):
                raise SerializationError("receiver identity differs from expected owner")
            basis = _load_basis(r.blob(MAX_WIRE), expected_scope.oracle.parent_rows(identity),
                                expected_scope.oracle.q)
            seeds = FixedSeedState.from_bytes(r.blob(MAX_WIRE), expected_scope=expected_scope.seed_scope(identity))
            r.finish()
            result = cls(expected_scope, identity, basis, seed_state=seeds)
        except (ValueError, EncodingError, InvalidParameterError) as exc:
            raise SerializationError(str(exc)) from exc
        if result.to_bytes() != r.data:
            raise SerializationError("noncanonical receiver private state")
        return result


class MasterTreeState:
    security_claim = "none"
    backend_admitted = False

    def __init__(self, scope, root_basis):
        if not isinstance(scope, DelegationScope):
            raise InvalidParameterError("validated delegation scope required")
        self._scope = scope
        self._root = validate_basis(root_basis, scope.oracle.root_rows, scope.oracle.q, scope.root_gs_squared_bound)
        self._entries, self._lock = {}, RLock()

    @property
    def scope(self): return self._scope

    def __repr__(self): return "MasterTreeState(RESEARCH, all secret bases/state hidden)"

    def _reserve(self, growth):
        if len(self.to_bytes()) + growth > MAX_WIRE:
            raise InvalidParameterError("whole master tree future private wire exceeds budget")

    def _bind(self, receiver):
        # One lock order for all owned parent/leaf mutations and master snapshots.
        # Callbacks/locks are runtime-only and are reattached on master restore.
        receiver._lock, receiver._owner_reserve = self._lock, self._reserve
        return receiver

    def lookup(self, receiver):
        identity = validate_identity(receiver, max_bytes=self.scope.oracle.identity_bytes)
        with self._lock:
            if identity not in self._entries:
                raise KeyError("receiver not yet issued")
            entry = self._entries[identity]
            if entry is None:
                raise ParentAddressBlocked("receiver blocked after failed delegation")
            return entry

    def issue(self, receiver, generate):
        if not callable(generate):
            raise TypeError("trusted parent basis generator required")
        identity = validate_identity(receiver, max_bytes=self.scope.oracle.identity_bytes)
        with self._lock:
            if identity in self._entries:
                return self.lookup(identity)
            if len(self._entries) >= self.scope.max_receivers:
                raise InvalidParameterError("receiver capacity exhausted; no eviction")
            dimension = 2 * self.scope.oracle.m
            _basis_size_gate(dimension)
            # Basis maximum plus exact repeated scopes and a conservative fixed
            # header budget. All size admission precedes basis generation/entropy.
            growth = dimension**2 * (5 + VECTOR_BITS // 8) + 2 * len(self.scope.to_bytes()) + 65536
            self._reserve(growth)
            self._entries[identity] = None
            basis = generate(ParentDelegationPlan(self.scope, identity, self._root))
            result = ReceiverState(self.scope, identity, basis)
            self._entries[identity] = self._bind(result)
            return result

    def to_bytes(self):
        with self._lock:
            chunks = [MASTER_MAGIC, encode_bytes(self.scope.to_bytes()), encode_bytes(_dump_basis(self._root)),
                      len(self._entries).to_bytes(4, "big")]
            for identity, receiver in sorted(self._entries.items()):
                chunks += [encode_bytes(identity), bytes([int(receiver is not None)])]
                if receiver is not None:
                    chunks.append(encode_bytes(receiver.to_bytes()))
            raw = b"".join(chunks)
            if len(raw) > MAX_WIRE:
                raise SerializationError("master tree private wire exceeds budget")
            return raw

    @classmethod
    def from_bytes(cls, data, *, expected_scope):
        if not isinstance(expected_scope, DelegationScope):
            raise TypeError("trusted delegation scope required")
        r = Reader(data, maximum=MAX_WIRE)
        if r.take(len(MASTER_MAGIC)) != MASTER_MAGIC or r.blob(MAX_WIRE) != expected_scope.to_bytes():
            raise SerializationError("master tree version or scope mismatch")
        try:
            root = _load_basis(r.blob(MAX_WIRE), expected_scope.oracle.root_rows, expected_scope.oracle.q)
            result, count = cls(expected_scope, root), r.number()
            if count > expected_scope.max_receivers:
                raise SerializationError("master receiver count exceeds capacity")
            previous = None
            for _ in range(count):
                identity = validate_identity(r.blob(expected_scope.oracle.identity_bytes), max_bytes=expected_scope.oracle.identity_bytes)
                if previous is not None and identity <= previous:
                    raise SerializationError("duplicate or unordered receiver")
                status, receiver = r.number(1), None
                if status not in (0, 1):
                    raise SerializationError("invalid master receiver status")
                if status:
                    receiver = ReceiverState.from_bytes(r.blob(MAX_WIRE), expected_scope=expected_scope,
                                                       expected_identity=identity)
                    result._bind(receiver)
                result._entries[identity], previous = receiver, identity
            r.finish()
        except (ValueError, EncodingError, InvalidParameterError) as exc:
            raise SerializationError(str(exc)) from exc
        if result.to_bytes() != r.data:
            raise SerializationError("noncanonical master tree state")
        return result
