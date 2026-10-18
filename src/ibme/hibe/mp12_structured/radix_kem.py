"""Wide-q seed KEM for the MP12-radix 3m engineering prototype.

This module does not establish correspondence to a CHKP security theorem.
The raw CPA capsule has no byte integrity; callers need outer authentication.
The finite rounded-continuous noise sampler is variable-time research code.
"""

from dataclasses import dataclass, field
from functools import lru_cache
from fractions import Fraction
from hmac import compare_digest
from math import isqrt

from ibme.core.errors import InvalidParameterError, RandomnessError, SerializationError
from ibme.core.randomness import SecureRandom
from ibme.lattice.chkp.identity import Reader, SEED_BITS, checked_bytes, checked_int
from ibme.lattice.chkp.joint_parameters import integer, rational
from ibme.lattice.chkp.noise_budget import MAX_RADIUS, RoundedNoiseParams
from ibme.lattice.chkp.rounded_noise import RoundedNoiseTable, build_rounded_noise
from ibme.lattice.chkp.seed_kem import decode_phase, uniform_residue

from .blocked_prototype import RadixPrototypeContext, load_leaf

MAGIC = b"IBME:MP12-RADIX-3M:SEED-KEM:v1\0"
MAX_WIRE = 512 * 1024
MAX_Q = 2**256 - 1
NOISE_OPTIONS = dict(tail_bits=192, mass_bits=320, precision_bits=384, max_radius=8192)


@dataclass(frozen=True)
class WideRoundedNoiseParams(RoundedNoiseParams):
    """The existing finite CDF profile with an independently checked wide q."""

    def __post_init__(self):
        try:
            integer(self.q, "q", low=2**61, high=MAX_Q)
            if self.q % 2 == 0:
                raise ValueError("wide rounded noise requires odd q")
            rate = rational(self.alpha, "alpha")
            if not 0 < rate < 1 or not Fraction(1, 256) <= self.q * rate <= 16384:
                raise ValueError("need 0<alpha<1 and 1/256<=q*alpha<=16384")
            for name, low, high in (("tail_bits", 8, 256), ("mass_bits", 8, 512),
                                    ("precision_bits", 128, 1024), ("max_radius", 1, MAX_RADIUS)):
                integer(getattr(self, name), name, low=low, high=high)
            if self.precision_bits < self.mass_bits + 32:
                raise ValueError("CDF precision must be at least mass_bits+32")
            object.__setattr__(self, "alpha", rate)
            square = (self.q * rate)**2 * (self.tail_bits + 1)
            radius = isqrt(square.numerator // square.denominator)
            radius += int(radius * radius < square)
            if radius > self.max_radius:
                raise ValueError("rounded-noise support exceeds public radius budget")
        except ValueError as exc:
            raise InvalidParameterError(str(exc)) from exc


def build_radix_noise(context):
    """Build the actual finite CDF for this radix profile, never a zero error."""
    if type(context) is not RadixPrototypeContext:
        raise TypeError("radix prototype context required")
    p = context.params
    return _canonical_noise(WideRoundedNoiseParams(
        p.q, Fraction(p.q_alpha, p.q), **NOISE_OPTIONS))


@lru_cache(maxsize=8)
def _canonical_noise(params):
    return build_rounded_noise(params)


@dataclass(frozen=True, repr=False)
class RadixSeedCapsule:
    context: bytes
    q: int
    preamble: tuple
    terminals: tuple
    security_claim: str = field(default="none", init=False)
    backend_admitted: bool = field(default=False, init=False)
    parameters_are_formal: bool = field(default=False, init=False)

    def __post_init__(self):
        context = checked_bytes(self.context, "radix KEM context", 64)
        if len(context) != 64:
            raise InvalidParameterError("radix KEM context must have 64 bytes")
        checked_int(self.q, "radix KEM modulus", 2**61, MAX_Q)
        if self.q % 2 == 0:
            raise InvalidParameterError("radix KEM modulus must be odd")
        if (not isinstance(self.preamble, (tuple, list)) or
                not 3 <= len(self.preamble) <= 8192 or len(self.preamble) % 3):
            raise InvalidParameterError("radix KEM needs a bounded 3m preamble")
        if not isinstance(self.terminals, (tuple, list)) or len(self.terminals) != SEED_BITS:
            raise InvalidParameterError("radix KEM needs 256 terminals")
        for name in ("preamble", "terminals"):
            values = tuple(checked_int(x, "radix KEM residue", 0, self.q - 1)
                           for x in getattr(self, name))
            object.__setattr__(self, name, values)
        object.__setattr__(self, "context", context)

    @property
    def residue_bytes(self):
        return ((self.q - 1).bit_length() + 7) // 8

    def to_bytes(self):
        return (MAGIC + self.context + self.q.to_bytes(32, "big")
                + len(self.preamble).to_bytes(4, "big")
                + b"".join(x.to_bytes(self.residue_bytes, "big")
                           for x in self.preamble + self.terminals))

    @classmethod
    def from_bytes(cls, raw):
        reader = Reader(raw, maximum=MAX_WIRE)
        if reader.take(len(MAGIC)) != MAGIC:
            raise SerializationError("unknown radix seed KEM wire version")
        context, q, dimension = reader.take(64), reader.number(32), reader.number()
        try:
            checked_int(q, "radix KEM modulus", 2**61, MAX_Q)
            checked_int(dimension, "radix KEM dimension", 3, 8192)
            if q % 2 == 0 or dimension % 3:
                raise InvalidParameterError("invalid radix KEM modulus/dimension")
            width = ((q - 1).bit_length() + 7) // 8
            if len(reader.data) - reader.pos != (dimension + SEED_BITS) * width:
                raise SerializationError("truncated or appended radix KEM coefficients")
            preamble = tuple(reader.number(width) for _ in range(dimension))
            terminals = tuple(reader.number(width) for _ in range(SEED_BITS))
            reader.finish()
            return cls(context, q, preamble, terminals)
        except InvalidParameterError as exc:
            raise SerializationError(str(exc)) from exc


def encapsulate_seed(context, receiver, sender, seed, *, noise=None, rng=None):
    """Encrypt exactly 32 seed bytes using all 3m LWE coefficients."""
    if type(context) is not RadixPrototypeContext:
        raise TypeError("radix prototype context required")
    payload = checked_bytes(seed, "radix KEM seed", 32)
    if len(payload) != 32:
        raise InvalidParameterError("radix KEM seed must have exactly 32 bytes")
    expected = WideRoundedNoiseParams(
        context.q, Fraction(context.params.q_alpha, context.q), **NOISE_OPTIONS)
    canonical = _canonical_noise(expected)
    table = canonical if noise is None else noise
    if type(table) is not RoundedNoiseTable or table != canonical:
        raise InvalidParameterError("radix KEM needs its matching actual rounded Gaussian")
    source = SecureRandom() if rng is None else rng
    if not callable(getattr(source, "read", None)):
        raise RandomnessError("radix KEM RNG must implement read(n)")
    public, targets = context.leaf_rows(receiver, sender), context.targets(receiver, sender)
    secret = tuple(uniform_residue(source, context.q) for _ in range(context.n))
    errors = table.sample_vector(context.leaf_dimension + SEED_BITS, rng=source)
    preamble = tuple((sum(row[j] * s for row, s in zip(public, secret)) + errors[j]) % context.q
                     for j in range(context.leaf_dimension))
    bits = tuple((byte >> shift) & 1 for byte in payload for shift in range(7, -1, -1))
    terminals = tuple((sum(y * s for y, s in zip(target, secret))
                       + bit * (context.q // 2) + errors[context.leaf_dimension + position]) % context.q
                      for position, (target, bit) in enumerate(zip(targets, bits)))
    return RadixSeedCapsule(context.context, context.q, preamble, terminals)


def decapsulate_seed(context, receiver, sender, leaf_wire, capsule):
    """Decode with a fully checked, identity-bound serialized 256-column leaf."""
    if type(context) is not RadixPrototypeContext or not isinstance(capsule, RadixSeedCapsule):
        raise TypeError("radix context and capsule required")
    if (not compare_digest(context.context, capsule.context) or
            capsule.q != context.q or len(capsule.preamble) != context.leaf_dimension):
        return None
    leaf = load_leaf(leaf_wire, context, receiver, sender)
    bits = tuple(decode_phase(value - sum(x * b for x, b in zip(leaf.column(position), capsule.preamble)),
                              context.q)
                 for position, value in enumerate(capsule.terminals))
    return bytes(sum(bits[8 * i + j] << (7 - j) for j in range(8)) for i in range(32))
