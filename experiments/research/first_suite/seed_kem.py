"""CHKP shared-preamble 256-bit seed encapsulation with actual rounded noise.

Sections 5.1--5.3 of the fixed CHKP author version. This is the KEM boundary,
not yet the seven-method byte HIBE or an admitted IBME suite. Wrong identities
can decode arbitrary seed bytes; the existing HYBRID-HIBE AEAD layer must
reject them. The raw KEM does not claim all-byte integrity or CCA security.
"""

from dataclasses import dataclass, field
from hmac import compare_digest

from ibme.core.errors import InvalidParameterError, RandomnessError, SerializationError
from ibme.core.randomness import SecureRandom

from .identity import (MAX_DIMENSION, MAX_RESIDUE_TRIALS, Reader, ROHIBEContext,
                       SEED_BITS, checked_bytes, checked_int)
from .leaf_state import FixedSeedKey

MAGIC = b"IBME:CHKP:SEED-KEM:v1"
MAX_WIRE = 2 * 2**20


def uniform_residue(source, q):
    bits = (q - 1).bit_length()
    size, mask = (bits + 7) // 8, (1 << bits) - 1
    for _ in range(MAX_RESIDUE_TRIALS):
        data = source.read(size)
        if not isinstance(data, bytes) or len(data) != size:
            raise RandomnessError("KEM uniform source returned a wrong type/length")
        value = int.from_bytes(data, "big") & mask
        if value < q:
            return value
    raise RandomnessError("KEM uniform residue budget exhausted; no fallback")


def decode_phase(phase, q):
    value = phase % q
    zero_distance = min(value, q - value)
    offset = (value - q // 2) % q
    one_distance = min(offset, q - offset)
    return int(zero_distance >= one_distance)


@dataclass(frozen=True, repr=False)
class SeedCapsule:
    context: bytes
    q: int
    preamble: tuple
    terminals: tuple
    security_claim: str = field(default="none", init=False)
    backend_admitted: bool = field(default=False, init=False)

    def __post_init__(self):
        context = checked_bytes(self.context, "KEM public context", 64)
        if len(context) != 64:
            raise InvalidParameterError("KEM public context must have exactly 64 bytes")
        checked_int(self.q, "KEM modulus", 2, 2**61 - 1)
        if not isinstance(self.preamble, (tuple, list)) or not 1 <= len(self.preamble) <= MAX_DIMENSION:
            raise InvalidParameterError("KEM preamble dimension exceeds its budget")
        if not isinstance(self.terminals, (tuple, list)) or len(self.terminals) != SEED_BITS:
            raise InvalidParameterError("KEM needs exactly 256 terminal coefficients")
        for name in ("preamble", "terminals"):
            object.__setattr__(self, name, tuple(checked_int(x, "KEM residue", 0, self.q - 1) for x in getattr(self, name)))
        object.__setattr__(self, "context", context)

    @property
    def residue_bytes(self):
        return ((self.q - 1).bit_length() + 7) // 8

    def to_bytes(self):
        header = MAGIC + self.context + self.q.to_bytes(8, "big") + len(self.preamble).to_bytes(4, "big")
        return header + b"".join(x.to_bytes(self.residue_bytes, "big") for x in self.preamble + self.terminals)

    @classmethod
    def from_bytes(cls, data):
        r = Reader(data, maximum=MAX_WIRE)
        if r.take(len(MAGIC)) != MAGIC:
            raise SerializationError("unknown CHKP KEM wire version")
        context, q, dimension = r.take(64), r.number(8), r.number()
        try:
            checked_int(q, "KEM modulus", 2, 2**61 - 1)
            checked_int(dimension, "KEM dimension", 1, MAX_DIMENSION)
            width = ((q - 1).bit_length() + 7) // 8
            if len(r.data) - r.pos != (dimension + SEED_BITS) * width:
                raise SerializationError("truncated/appended KEM coefficients")
            preamble = tuple(r.number(width) for _ in range(dimension))
            terminals = tuple(r.number(width) for _ in range(SEED_BITS))
            r.finish()
            return cls(context, q, preamble, terminals)
        except InvalidParameterError as exc:
            raise SerializationError(str(exc)) from exc


def encapsulate_seed(oracle, receiver, sender, seed, noise, *, rng=None):
    """Encrypt exactly 32 bytes with fresh s and D+256 independent errors.

    The rounded-noise component is mandatory and must have the same q. It
    samples round(q * continuous Gaussian width alpha); a discrete Gaussian
    noise substitute, zero-error driver or generic mock is not accepted here.
    """
    from experiments.research.ibme_rounded_noise import RoundedNoiseTable

    if not isinstance(oracle, ROHIBEContext):
        raise TypeError("canonical ROHIBE context required")
    payload = checked_bytes(seed, "KEM seed", 32)
    if len(payload) != 32:
        raise InvalidParameterError("KEM seed must have exactly 32 bytes")
    if not isinstance(noise, RoundedNoiseTable) or noise.params.q != oracle.q:
        raise InvalidParameterError("actual rounded Gaussian must match the KEM modulus")
    public, targets = oracle.leaf_rows(receiver, sender), oracle.targets(receiver, sender)
    source = SecureRandom() if rng is None else rng
    if not callable(getattr(source, "read", None)):
        raise RandomnessError("KEM RNG must provide read(n)")
    secret = tuple(uniform_residue(source, oracle.q) for _ in range(oracle.n))
    errors = noise.sample_vector(oracle.leaf_dimension + SEED_BITS, rng=source, mod_q=False)
    preamble = tuple((sum(row[j] * s for row, s in zip(public, secret)) + errors[j]) % oracle.q
                     for j in range(oracle.leaf_dimension))
    bits = tuple((byte >> shift) & 1 for byte in payload for shift in range(7, -1, -1))
    terminals = tuple((sum(y * s for y, s in zip(target, secret)) + bit * (oracle.q // 2)
                       + errors[oracle.leaf_dimension + position]) % oracle.q
                      for position, (target, bit) in enumerate(zip(targets, bits)))
    return SeedCapsule(oracle.context, oracle.q, preamble, terminals)


def decapsulate_seed(key, capsule):
    """Raw KEM result; wrong identity and tampering need the outer AEAD/IBS."""
    if not isinstance(key, FixedSeedKey) or not isinstance(capsule, SeedCapsule):
        raise TypeError("validated fixed seed key and capsule required")
    oracle = key.plan.scope.oracle
    if (not compare_digest(oracle.context, capsule.context) or capsule.q != oracle.q
            or len(capsule.preamble) != oracle.leaf_dimension):
        return None
    bits = tuple(decode_phase(value - sum(x * b for x, b in zip(sample, capsule.preamble)), oracle.q)
                 for value, sample in zip(capsule.terminals, key.preimages))
    return bytes(sum(bits[8 * i + j] << (7 - j) for j in range(8)) for i in range(32))
