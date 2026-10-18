"""2011 CHKP author-manuscript KEM for a depth-one identity.

At depth one the real KEM matrix is A0 || H(receiver), with 2m columns.
The manuscript's variable-depth anonymity extension pads its preamble to
3m columns with independent uniform residues.  The 256 indexed G targets
are the same amortization used by the existing depth-two seed KEM.

This module supplies a mathematical primitive, not a persistent level-one
HIBE secret key, an anonymity reduction, or security-parameter admission.
"""

from dataclasses import dataclass, field
from fractions import Fraction
from hmac import compare_digest

from ibme.core.errors import InvalidParameterError, RandomnessError
from ibme.core.randomness import SecureRandom
from ibme.core.types import validate_identity

from .identity import ROHIBEContext, SEED_BITS, checked_bytes
from .seed_kem import SeedCapsule, decode_phase, uniform_residue


def _inputs(oracle, receiver):
    if type(oracle) is not ROHIBEContext:
        raise TypeError("canonical CHKP public oracle required")
    receiver = validate_identity(receiver, max_bytes=oracle.identity_bytes)
    return receiver, oracle.parent_rows(receiver), tuple(
        oracle.g((receiver,), position) for position in range(SEED_BITS))


def _width(value):
    if isinstance(value, bool) or not isinstance(value, (int, str, Fraction)):
        raise InvalidParameterError("level-one width squared must be exact")
    if isinstance(value, str) and len(value) > 200:
        raise InvalidParameterError("level-one width text exceeds its budget")
    try:
        result = Fraction(value)
    except (ValueError, ZeroDivisionError) as exc:
        raise InvalidParameterError("invalid level-one width squared") from exc
    if result <= 0 or max(result.numerator.bit_length(), result.denominator.bit_length()) > 256:
        raise InvalidParameterError("level-one width squared exceeds its exact budget")
    return result


@dataclass(frozen=True, repr=False)
class Level1Preimages:
    """A fixed, validated receiver key; raw tuples cannot bypass key checks."""

    oracle: ROHIBEContext = field(repr=False)
    receiver: bytes
    preimages: tuple = field(repr=False)
    width_squared: Fraction

    security_claim = "none"
    backend_admitted = False

    def __post_init__(self):
        receiver, rows, targets = _inputs(self.oracle, self.receiver)
        width = _width(self.width_squared)
        dimension = 2 * self.oracle.m
        if not isinstance(self.preimages, (tuple, list)) or len(self.preimages) != SEED_BITS:
            raise InvalidParameterError("exactly 256 level-one preimages required")
        samples = []
        for sample, target in zip(self.preimages, targets):
            if not isinstance(sample, (tuple, list)) or len(sample) != dimension:
                raise InvalidParameterError("wrong level-one preimage dimension")
            if any(type(x) is not int or abs(x) >= 2**256 for x in sample):
                raise InvalidParameterError("level-one preimage exceeds signed wire domain")
            vector = tuple(sample)
            if sum(x * x for x in vector) > width * dimension:
                raise InvalidParameterError("level-one preimage exceeds its width bound")
            if tuple(sum(a * x for a, x in zip(row, vector)) % self.oracle.q
                     for row in rows) != target:
                raise InvalidParameterError("level-one preimage differs from receiver G target")
            samples.append(vector)
        object.__setattr__(self, "receiver", receiver)
        object.__setattr__(self, "width_squared", width)
        object.__setattr__(self, "preimages", tuple(samples))


def validate_level1_preimages(oracle, receiver, preimages, width_squared):
    """Bind 256 sampled vectors to A_receiver, G(receiver,j), and a norm bound."""
    return Level1Preimages(oracle, receiver, preimages, width_squared)


def sample_level1_preimages(root_basis, oracle, receiver, width_squared, *,
                            epsilon_bits, options, entropy_budget, rng=None):
    """Sample 256 targets via CHKP's implicit ExtBasis GPV sampler.

    The full entropy upper bound is checked before drawing any private byte.
    A failed sampling attempt is propagated; persistence and no-retry policy
    belong to the owning HIBE state object, not this stateless primitive.
    """
    from .basis import KernelBasis, ModMatrixReference
    from .extended_gpv import ExtendedGPV

    receiver, _, targets = _inputs(oracle, receiver)
    if (not isinstance(root_basis, KernelBasis) or root_basis.public.q != oracle.q
            or root_basis.public.rows != oracle.root_rows):
        raise InvalidParameterError("level-one sampler root differs from public A0")
    if type(entropy_budget) is not int or not 1 <= entropy_budget <= 2**40:
        raise InvalidParameterError("explicit bounded level-one entropy budget required")
    source = SecureRandom() if rng is None else rng
    if not callable(getattr(source, "read", None)):
        raise RandomnessError("level-one RNG must provide read(n)")
    extension = ModMatrixReference(oracle.h((receiver,)), oracle.q)
    sampler = ExtendedGPV(root_basis, extension, width_squared,
                          epsilon_bits=epsilon_bits, options=options)
    if SEED_BITS * sampler.random_tape_bytes > entropy_budget:
        raise InvalidParameterError("256 level-one GPV tapes exceed the entropy budget")
    samples = tuple(sampler.sample(target, rng=source) for target in targets)
    validate_level1_preimages(oracle, receiver, samples, width_squared)
    return samples


def encapsulate_level1(oracle, receiver, seed32, noise, *, rng=None):
    """Encrypt a 32-byte seed using 2m LWE columns plus m uniform padding."""
    from .rounded_noise import RoundedNoiseTable

    receiver, rows, targets = _inputs(oracle, receiver)
    seed = checked_bytes(seed32, "level-one seed", 32)
    if len(seed) != 32:
        raise InvalidParameterError("level-one seed must have exactly 32 bytes")
    if not isinstance(noise, RoundedNoiseTable) or noise.params.q != oracle.q:
        raise InvalidParameterError("matching rounded continuous Gaussian noise required")
    source = SecureRandom() if rng is None else rng
    if not callable(getattr(source, "read", None)):
        raise RandomnessError("level-one RNG must provide read(n)")
    secret = tuple(uniform_residue(source, oracle.q) for _ in range(oracle.n))
    errors = noise.sample_vector(2 * oracle.m + SEED_BITS, rng=source, mod_q=False)
    real_preamble = tuple((sum(row[j] * s for row, s in zip(rows, secret)) + errors[j]) % oracle.q
                          for j in range(2 * oracle.m))
    padding = tuple(uniform_residue(source, oracle.q) for _ in range(oracle.m))
    bits = tuple((byte >> shift) & 1 for byte in seed for shift in range(7, -1, -1))
    terminals = tuple((sum(y * s for y, s in zip(target, secret))
                       + bit * (oracle.q // 2) + errors[2 * oracle.m + position]) % oracle.q
                      for position, (target, bit) in enumerate(zip(targets, bits)))
    return SeedCapsule(oracle.context, oracle.q, real_preamble + padding, terminals)


def decapsulate_level1(oracle, receiver, preimages, capsule):
    """Decode with only the first 2m entries; CPA KEM has no tamper rejection."""
    receiver, _, _ = _inputs(oracle, receiver)
    if not isinstance(preimages, Level1Preimages) or not isinstance(capsule, SeedCapsule):
        raise TypeError("validated level-one key and CHKP seed capsule required")
    if (receiver != preimages.receiver or preimages.oracle.to_bytes() != oracle.to_bytes()
            or not compare_digest(capsule.context, oracle.context) or capsule.q != oracle.q
            or len(capsule.preamble) != oracle.leaf_dimension):
        return None
    preamble = capsule.preamble[:2 * oracle.m]
    bits = tuple(decode_phase(value - sum(x * b for x, b in zip(sample, preamble)), oracle.q)
                 for value, sample in zip(capsule.terminals, preimages.preimages))
    return bytes(sum(bits[8 * i + j] << (7 - j) for j in range(8)) for i in range(32))
