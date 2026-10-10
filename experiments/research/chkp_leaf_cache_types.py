"""Validated public bindings for the research-only fixed leaf cache.

H/G and a canonical production public-key format are NOT defined here.
The caller supplies the full canonical public context and trusted leaf plans.
"""

from dataclasses import dataclass, fields

from sage.all import GF, QQ, ZZ, matrix, vector

from .chkp_basis import ModMatrixReference
from .chkp_gpv import CHKPGPVSampler
from .online_gaussian_reference import OnlineOptions, exact_integer, exact_rational


MAX_WIRE = 16 * 1024 * 1024
MAX_CONTEXT = 65536
MAX_ID = 256
MAX_ENTRIES = 8
MAX_CAPACITY = 32
MAX_ROWS, MAX_DIMENSION = 16, 192
PUBLIC_BITS, WIDTH_BITS, VECTOR_BITS = 64, 1024, 8192
PROFILE_MAGIC = b"CHKP-GPV-ONLINE/1\x00"
OPTION_NAMES = tuple(f.name for f in fields(OnlineOptions))


def bounded_bytes(value, name, limit, *, nonempty=True):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ValueError(f"{name} must be bytes-like")
    size = value.nbytes if isinstance(value, memoryview) else len(value)
    if size > limit or (nonempty and not size):
        raise ValueError(f"{name} exceeds its length bounds")
    return bytes(value)


def sampler_profile(sampler):
    if not isinstance(sampler, CHKPGPVSampler):
        raise ValueError("Need an admitted research GPV sampler")
    options = sampler.scalars[0].options
    values = [sampler.epsilon_bits] + [getattr(options, name) for name in OPTION_NAMES]
    return PROFILE_MAGIC + b"".join(int(x).to_bytes(4, "big") for x in values)


def validate_profile(value):
    data = bounded_bytes(value, "sampling profile", 4096)
    if not data.startswith(PROFILE_MAGIC) or len(data) != len(PROFILE_MAGIC)+4*(1+len(OPTION_NAMES)):
        raise ValueError("Unknown sampling profile")
    vals = [int.from_bytes(data[i:i+4], "big") for i in range(len(PROFILE_MAGIC), len(data), 4)]
    exact_integer(vals[0], "epsilon bits", minimum=2, maximum=4096)
    OnlineOptions(**dict(zip(OPTION_NAMES, vals[1:])))
    return data


@dataclass(frozen=True, repr=False)
class CacheScope:
    public_context: bytes
    parent_identity: bytes
    capacity: int
    max_entries: int = MAX_ENTRIES

    def __post_init__(self):
        object.__setattr__(self, "public_context", bounded_bytes(self.public_context, "public context", MAX_CONTEXT))
        object.__setattr__(self, "parent_identity", bounded_bytes(self.parent_identity, "receiver identity", MAX_ID))
        object.__setattr__(self, "capacity", exact_integer(self.capacity, "capacity", minimum=1, maximum=MAX_CAPACITY))
        object.__setattr__(self, "max_entries", exact_integer(self.max_entries, "entries", minimum=1, maximum=MAX_ENTRIES))


@dataclass(frozen=True, repr=False)
class LeafPlan:
    public: ModMatrixReference
    width_squared: object
    profile: bytes
    targets: tuple

    def __post_init__(self):
        a = self.public
        if not isinstance(a, ModMatrixReference) or not 1 <= a.nrows <= MAX_ROWS or not a.nrows <= a.ncols <= MAX_DIMENSION:
            raise ValueError("Leaf public dimensions exceed research bounds")
        if a.q.bit_length() > PUBLIC_BITS:
            raise ValueError("Leaf modulus exceeds cache research bound")
        if matrix(GF(a.q), a.rows).rank() != a.nrows:
            raise ValueError("Leaf public matrix must have full row rank")
        width = exact_rational(self.width_squared, "width squared", max_bits=WIDTH_BITS)
        if width <= 0:
            raise ValueError("Leaf width must be positive")
        if not isinstance(self.targets, (tuple, list)) or not 1 <= len(self.targets) <= MAX_CAPACITY:
            raise ValueError("Invalid fixed leaf target count")
        targets = []
        for target in self.targets:
            if not isinstance(target, (tuple, list)) or len(target) != a.nrows:
                raise ValueError("Invalid leaf target dimension")
            targets.append(tuple(exact_integer(x, "target", maximum=a.q-1) for x in target))
        object.__setattr__(self, "width_squared", width)
        object.__setattr__(self, "targets", tuple(targets))
        object.__setattr__(self, "profile", validate_profile(self.profile))

    @classmethod
    def from_sampler(cls, sampler, targets):
        return cls(sampler.basis.public, sampler.width_squared, sampler_profile(sampler), targets)

    def matches(self, sampler):
        return (isinstance(sampler, CHKPGPVSampler) and self.public == sampler.basis.public
                and self.width_squared == sampler.width_squared and self.profile == sampler_profile(sampler))


@dataclass(frozen=True, repr=False)
class CacheEntry:
    plan: LeafPlan
    preimages: tuple | None  # None is a persistent FAILED/BLOCKED tombstone

    def __post_init__(self):
        if not isinstance(self.plan, LeafPlan):
            raise ValueError("Need a validated leaf plan")
        if self.preimages is None:
            return
        if not isinstance(self.preimages, (tuple, list)) or len(self.preimages) != len(self.plan.targets):
            raise ValueError("Wrong cached preimage count")
        limit, canonical = 2**VECTOR_BITS-1, []
        a = self.plan.public
        for sample, target in zip(self.preimages, self.plan.targets):
            if not isinstance(sample, (tuple, list)) or len(sample) != a.ncols:
                raise ValueError("Wrong cached vector dimension")
            x = tuple(exact_integer(v, "preimage integer", minimum=-limit, maximum=limit) for v in sample)
            if tuple(int(v) % a.q for v in matrix(ZZ, a.rows)*vector(ZZ, x)) != target:
                raise ValueError("Cached preimage equation mismatch")
            canonical.append(x)
        object.__setattr__(self, "preimages", tuple(canonical))
