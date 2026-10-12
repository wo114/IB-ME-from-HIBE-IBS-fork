"""Identity-bound, 256-position private leaf state for the first CHKP suite.

Only short preimages survive delegation; no root/parent/leaf basis or RNG is
retained by this store. All H/G/public matrices are reconstructed from the
canonical root and ordered identities. A failed attempt stays FAILED through
serialization; callers must publish snapshots on success AND failure. Existing
CLI receiver transactions provide the eventual disk boundary. This module is
not itself a HIBE backend, disk transaction, authenticated storage or sampler.
"""

from dataclasses import dataclass, field
from fractions import Fraction
from threading import RLock

from ibme.core.encoding import encode_bytes
from ibme.core.errors import EncodingError, InvalidParameterError, SerializationError
from ibme.core.types import validate_identity

from .identity import Reader, ROHIBEContext, SEED_BITS, checked_bytes, checked_int

MAGIC = b"IBME:CHKP:FIXED-SEED-STATE:v1"
MAX_WIRE = 16 * 2**20
MAX_CHILDREN = 8
VECTOR_BITS = 256
MAX_PROFILE_BYTES = 4096


def _uint(value):
    if type(value) is not int or not 0 <= value < 2**VECTOR_BITS:
        raise SerializationError("integer exceeds private wire budget")
    return encode_bytes(value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big"))


def _read_uint(reader):
    raw = reader.blob(VECTOR_BITS // 8)
    if len(raw) > 1 and raw[0] == 0:
        raise SerializationError("noncanonical integer leading zero")
    return int.from_bytes(raw, "big")


def _signed(value):
    return bytes([int(value < 0)]) + _uint(abs(value))


def _read_signed(reader):
    sign, value = reader.number(1), _read_uint(reader)
    if sign not in (0, 1) or (sign == 1 and value == 0):
        raise SerializationError("noncanonical private integer sign")
    return -value if sign else value


def _width(value):
    if isinstance(value, bool) or not isinstance(value, (int, str, Fraction)):
        raise InvalidParameterError("width squared requires an exact rational")
    if isinstance(value, str) and len(value) > 200:
        raise InvalidParameterError("width text exceeds its public budget")
    try:
        width = Fraction(value)
    except (ValueError, ZeroDivisionError) as exc:
        raise InvalidParameterError("invalid squared width") from exc
    if width <= 0 or max(width.numerator.bit_length(), width.denominator.bit_length()) > VECTOR_BITS:
        raise InvalidParameterError("squared width exceeds the public budget")
    return width


@dataclass(frozen=True, repr=False)
class SeedScope:
    oracle: ROHIBEContext
    receiver: bytes
    width_squared: Fraction
    sampler_profile: bytes
    max_children: int = MAX_CHILDREN

    def __post_init__(self):
        if not isinstance(self.oracle, ROHIBEContext):
            raise InvalidParameterError("canonical CHKP oracle context required")
        object.__setattr__(self, "receiver", validate_identity(self.receiver, max_bytes=self.oracle.identity_bytes))
        object.__setattr__(self, "width_squared", _width(self.width_squared))
        object.__setattr__(self, "sampler_profile", checked_bytes(self.sampler_profile, "sampler profile", MAX_PROFILE_BYTES))
        checked_int(self.max_children, "child entries", 1, MAX_CHILDREN)

    def to_bytes(self):
        return (encode_bytes(self.oracle.to_bytes()) + encode_bytes(self.receiver)
                + _uint(self.width_squared.numerator) + _uint(self.width_squared.denominator)
                + encode_bytes(self.sampler_profile) + self.max_children.to_bytes(4, "big"))


@dataclass(frozen=True, repr=False)
class SeedPlan:
    scope: SeedScope
    sender: bytes
    public_rows: tuple = field(init=False, repr=False)
    targets: tuple = field(init=False, repr=False)

    def __post_init__(self):
        if not isinstance(self.scope, SeedScope):
            raise InvalidParameterError("validated seed scope required")
        sender = validate_identity(self.sender, max_bytes=self.scope.oracle.identity_bytes)
        object.__setattr__(self, "sender", sender)
        object.__setattr__(self, "public_rows", self.scope.oracle.leaf_rows(self.scope.receiver, sender))
        object.__setattr__(self, "targets", self.scope.oracle.targets(self.scope.receiver, sender))

    @property
    def dimension(self):
        return self.scope.oracle.leaf_dimension


@dataclass(frozen=True, repr=False)
class FixedSeedKey:
    plan: SeedPlan
    preimages: tuple = field(repr=False)
    security_claim: str = field(default="none", init=False)
    backend_admitted: bool = field(default=False, init=False)

    def __post_init__(self):
        if not isinstance(self.plan, SeedPlan):
            raise InvalidParameterError("validated 256-position plan required")
        if not isinstance(self.preimages, (tuple, list)) or len(self.preimages) != SEED_BITS:
            raise InvalidParameterError("exactly 256 fixed preimages required")
        rows, q, dimension = self.plan.public_rows, self.plan.scope.oracle.q, self.plan.dimension
        norm_limit = self.plan.scope.width_squared * dimension
        canonical = []
        for sample, target in zip(self.preimages, self.plan.targets):
            if not isinstance(sample, (tuple, list)) or len(sample) != dimension:
                raise InvalidParameterError("wrong fixed preimage dimension")
            values = tuple(checked_int(x, "private vector", -(2**VECTOR_BITS - 1), 2**VECTOR_BITS - 1) for x in sample)
            if sum(x * x for x in values) > norm_limit:
                raise InvalidParameterError("fixed preimage norm exceeds the declared budget")
            if tuple(sum(a * x for a, x in zip(row, values)) % q for row in rows) != target:
                raise InvalidParameterError("fixed preimage does not solve its real identity/position target")
            canonical.append(values)
        object.__setattr__(self, "preimages", tuple(canonical))


class SeedAddressBlocked(InvalidParameterError):
    """A previous attempt failed; creating a new plan cannot unblock it."""


class FixedSeedState:
    security_claim = "none"
    backend_admitted = False

    def __init__(self, scope):
        if not isinstance(scope, SeedScope):
            raise InvalidParameterError("validated seed scope required")
        self._scope, self._entries, self._lock = scope, {}, RLock()

    @property
    def scope(self):
        return self._scope

    def __repr__(self):
        return "FixedSeedState(RESEARCH, private state hidden)"

    def _sender(self, sender):
        return validate_identity(sender, max_bytes=self.scope.oracle.identity_bytes)

    def lookup(self, sender):
        sender = self._sender(sender)
        with self._lock:
            if sender not in self._entries:
                raise KeyError("fixed sender address not yet issued")
            entry = self._entries[sender]
            if entry is None:
                raise SeedAddressBlocked("sender address blocked after failed sampling")
            return entry

    def resolve(self, sender, generate):
        """Generate one full key or reuse it; execution never retries a failure.

        generate(plan) is a trusted sampler adapter. Its entropy/distribution
        admission must be checked separately. This store checks actual equations
        and norms, which cannot establish Gaussian sampling or secrecy.
        """
        sender = self._sender(sender)
        if not callable(generate):
            raise TypeError("trusted fixed-target generator must be callable")
        with self._lock:
            if sender in self._entries:
                return self.lookup(sender)
            if len(self._entries) >= self.scope.max_children:
                raise InvalidParameterError("fixed sender capacity exhausted; no eviction")
            # Admission uses the maximum encoded vector length BEFORE hashing,
            # reserving an address, or asking the sampler for randomness.
            reservation = 4 + len(sender) + 1 + SEED_BITS * self.scope.oracle.leaf_dimension * (5 + VECTOR_BITS // 8)
            if len(self.to_bytes()) + reservation > MAX_WIRE:
                raise InvalidParameterError("worst-case fixed private snapshot exceeds wire budget")
            plan = SeedPlan(self.scope, sender)
            self._entries[sender] = None
            samples = generate(plan)
            entry = FixedSeedKey(plan, samples)
            self._entries[sender] = entry
            return entry

    def to_bytes(self):
        with self._lock:
            out = [MAGIC, encode_bytes(self.scope.to_bytes()), len(self._entries).to_bytes(4, "big")]
            for sender, entry in sorted(self._entries.items()):
                out += [encode_bytes(sender), bytes([int(entry is not None)])]
                if entry is not None:
                    out.extend(_signed(x) for row in entry.preimages for x in row)
            raw = b"".join(out)
            if len(raw) > MAX_WIRE:
                raise SerializationError("private fixed seed snapshot exceeds wire budget")
            return raw

    @classmethod
    def from_bytes(cls, data, *, expected_scope):
        if not isinstance(expected_scope, SeedScope):
            raise TypeError("trusted expected scope required for private state loading")
        r = Reader(data, maximum=MAX_WIRE)
        if r.take(len(MAGIC)) != MAGIC:
            raise SerializationError("unknown fixed seed state version")
        if r.blob(MAX_WIRE) != expected_scope.to_bytes():
            raise SerializationError("fixed seed state differs from trusted public/identity/width/profile scope")
        count = r.number()
        if count > expected_scope.max_children:
            raise SerializationError("private sender entry count exceeds its fixed capacity")
        result, previous = cls(expected_scope), None
        try:
            for _ in range(count):
                sender = validate_identity(r.blob(expected_scope.oracle.identity_bytes), max_bytes=expected_scope.oracle.identity_bytes)
                if previous is not None and sender <= previous:
                    raise SerializationError("duplicate or unordered sender entry")
                status = r.number(1)
                if status not in (0, 1):
                    raise SerializationError("unknown private seed state status")
                entry = None
                if status:
                    dimension = expected_scope.oracle.leaf_dimension
                    if len(r.data) - r.pos < SEED_BITS * dimension * 6:
                        raise SerializationError("truncated private vector batch")
                    samples = tuple(tuple(_read_signed(r) for _ in range(dimension)) for _ in range(SEED_BITS))
                    entry = FixedSeedKey(SeedPlan(expected_scope, sender), samples)
                result._entries[sender], previous = entry, sender
            r.finish()
        except (EncodingError, InvalidParameterError) as exc:
            raise SerializationError(str(exc)) from exc
        if result.to_bytes() != r.data:
            raise SerializationError("noncanonical private seed state")
        return result
