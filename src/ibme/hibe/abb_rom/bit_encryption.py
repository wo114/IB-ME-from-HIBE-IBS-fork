"""ABB10 section 4.1's bit Encrypt/Decrypt, not a byte HIBE backend.

Every bit has a fresh s and m+1 rounded continuous Gaussian draws. The
SamplePre call is made separately on each Decrypt, as the original specifies.
The integer threshold differs from CHKP's nearest-phase rule; do not reuse it.
This module has no identity hash, key persistence, authentication or ROM claim.
"""

from dataclasses import dataclass
from fractions import Fraction
from itertools import islice

from sage.all import GF, matrix

from ibme.core.errors import InvalidParameterError
from ibme.core.randomness import SecureRandom
from ibme.lattice.research import FirstFiniteGPV, KernelBasis, ModMatrixReference
from experiments.research.first_suite.entropy import CheckedEntropy
from experiments.research.gaussian_reference import draw_uniform_integer
from experiments.research.ibme_noise_budget import RoundedNoiseParams
from experiments.research.ibme_rounded_noise import build_rounded_noise
from .trapgen import MAX_DIMENSION, MAX_MODULUS_BITS, bounded_integer


def _vector(values, length, q, name):
    if isinstance(values, (str, bytes, bytearray, memoryview)):
        raise InvalidParameterError(f"{name} requires an exact vector")
    try:
        values = tuple(islice(iter(values), length + 1))
    except TypeError:
        raise InvalidParameterError(f"{name} requires an exact vector") from None
    if len(values) != length:
        raise InvalidParameterError(f"{name} dimension mismatch")
    return tuple(bounded_integer(v, name, 0, q - 1) for v in values)


@dataclass(frozen=True)
class ABBBitPublic:
    matrix: ModMatrixReference
    u0: tuple

    def __post_init__(self):
        if not isinstance(self.matrix, ModMatrixReference):
            raise InvalidParameterError("ABB requires an exact modular matrix")
        a = self.matrix
        if (not 1 <= a.nrows < a.ncols <= MAX_DIMENSION or not 3 <= a.q < 2**MAX_MODULUS_BITS
                or a.q % 2 == 0):
            raise InvalidParameterError("ABB bit matrix exceeds the profile")
        if matrix(GF(a.q), a.rows).rank() != a.nrows:
            raise InvalidParameterError("ABB bit public matrix requires full row rank")
        object.__setattr__(self, "u0", _vector(self.u0, a.nrows, a.q, "u0"))


@dataclass(frozen=True)
class ABBBitCiphertext:
    q: int
    c0: int
    c1: tuple

    def __post_init__(self):
        q = bounded_integer(self.q, "q", 3, 2**MAX_MODULUS_BITS - 1)
        if q % 2 == 0:
            raise InvalidParameterError("ABB bit ciphertext requires odd q")
        if not isinstance(self.c1, (tuple, list)) or not 2 <= len(self.c1) <= MAX_DIMENSION:
            raise InvalidParameterError("ABB bit ciphertext dimension")
        object.__setattr__(self, "c0", bounded_integer(self.c0, "c0", 0, q - 1))
        object.__setattr__(self, "c1", _vector(self.c1, len(self.c1), q, "c1"))


class ABBBitEncryptor:
    def __init__(self, public, alpha, *, uniform_trials=192, tail_bits=128,
                 mass_bits=192, precision_bits=256, max_radius=8192):
        if not isinstance(public, ABBBitPublic):
            raise InvalidParameterError("ABBBitPublic required")
        if isinstance(alpha, bool) or not isinstance(alpha, (int, Fraction)):
            raise InvalidParameterError("alpha requires an exact Fraction")
        alpha = Fraction(alpha)
        if (max(abs(alpha.numerator).bit_length(), alpha.denominator.bit_length()) > 512
                or not 0 < alpha < 1):
            raise InvalidParameterError("alpha outside the exact input profile")
        self.public, self.alpha = public, alpha
        self.uniform_trials = bounded_integer(uniform_trials, "uniform_trials", 1, 4096)
        # Signed round(Y) depends solely on width q*alpha, never q separately.
        # Reuse the existing certified scalar at that exact width, under an
        # explicit anchor modulus. Never call its anchor-modulus projection.
        self.noise = build_rounded_noise(RoundedNoiseParams(
            65537, public.matrix.q * alpha / 65537, tail_bits=tail_bits,
            mass_bits=mass_bits, precision_bits=precision_bits, max_radius=max_radius))
        a = public.matrix
        self.random_tape_bytes = (a.nrows * self.uniform_trials * (((a.q - 1).bit_length() + 7) // 8)
                                  + (a.ncols + 1) * self.noise.draw_bytes)

    def encrypt(self, bit, *, rng=None):
        bit = bounded_integer(bit, "message bit", 0, 1)
        a = self.public.matrix
        source = CheckedEntropy(SecureRandom() if rng is None else rng, self.random_tape_bytes)
        s = tuple(draw_uniform_integer(source, a.q, max_trials=self.uniform_trials)
                  for _ in range(a.nrows))
        noise = self.noise.sample_vector(a.ncols + 1, rng=source)
        c0 = (sum(u * v for u, v in zip(self.public.u0, s)) + noise[0] + bit * (a.q // 2)) % a.q
        c1 = tuple((sum(a.rows[i][j] * s[i] for i in range(a.nrows)) + noise[j + 1]) % a.q
                   for j in range(a.ncols))
        return ABBBitCiphertext(a.q, c0, c1)

    def certificate(self):
        scalar = self.noise.certificate()
        error = Fraction(scalar["tv_upper_including_abort"])
        a = self.public.matrix
        return {
            "profile": "ABB-ROM-BIT-ENCRYPT/1", "source": "ABB10 PDF12 section4.1",
            "q": str(a.q), "alpha": str(self.alpha), "scaled_width": str(a.q * self.alpha),
            "n": a.nrows, "dimension": a.ncols, "message_bits_per_call": 1,
            "fresh_uniform_s_per_bit": True, "noise_draws_per_bit": a.ncols + 1,
            "signed_scalar_anchor_config": scalar["config"],
            "anchor_modulus_used_for_ciphertext": False,
            "noise_tv_upper_per_bit": str(min(1, (a.ncols + 1) * error)),
            "uniform_abort_upper_per_bit": str(min(Fraction(1), Fraction(a.nrows, 2**self.uniform_trials))),
            "scalar_certificate": scalar, "random_tape_bytes": self.random_tape_bytes,
            "security_claim": "none", "backend_admitted": False, "full_ABB_HIBE": False,
        }


def abb_decode_phase(phase, q):
    q = bounded_integer(q, "q", 3, 2**MAX_MODULUS_BITS - 1)
    if q % 2 == 0:
        raise InvalidParameterError("odd q required")
    phase = bounded_integer(phase, "phase", 0, q - 1)
    return int(abs(phase - q // 2) < q // 4)


class ABBBitDecryptor:
    """Prepare exact public/private arithmetic; sample a fresh d on every call.

    Preparing GPV geometry consumes no entropy and does not cache a sampled
    preimage. This is a consumer of the existing public finite GPV profile.
    """
    def __init__(self, public, basis, width_squared, *, epsilon_bits=128, options=None):
        if not isinstance(public, ABBBitPublic) or not isinstance(basis, KernelBasis):
            raise InvalidParameterError("ABB public input and complete basis required")
        if basis.public != public.matrix:
            raise InvalidParameterError("ABB decryption basis belongs to another public matrix")
        self.public = public
        self.sampler = FirstFiniteGPV(basis, width_squared, epsilon_bits=epsilon_bits, options=options)

    def decrypt(self, ciphertext, *, rng=None):
        if not isinstance(ciphertext, ABBBitCiphertext):
            raise InvalidParameterError("ABBBitCiphertext required")
        if ciphertext.q != self.public.matrix.q or len(ciphertext.c1) != self.public.matrix.ncols:
            raise InvalidParameterError("ABB ciphertext q/dimension mismatch")
        d = self.sampler.sample(self.public.u0, rng=rng)
        # Failure is an implementation defect, never substituted by a public lift.
        if any(sum(row[j] * d[j] for j in range(len(d))) % ciphertext.q != target
               for row, target in zip(self.public.matrix.rows, self.public.u0)):
            raise ArithmeticError("ABB SamplePre equation failed")
        phase = (ciphertext.c0 - sum(x * y for x, y in zip(d, ciphertext.c1))) % ciphertext.q
        return abb_decode_phase(phase, ciphertext.q)


def abb_decrypt_bit(public, basis, ciphertext, width_squared, *, rng=None,
                    epsilon_bits=128, options=None):
    # The cheap q/shape checks precede preparation and entropy consumption.
    if not isinstance(public, ABBBitPublic) or not isinstance(ciphertext, ABBBitCiphertext):
        raise InvalidParameterError("ABB public input and ciphertext required")
    if ciphertext.q != public.matrix.q or len(ciphertext.c1) != public.matrix.ncols:
        raise InvalidParameterError("ABB ciphertext q/dimension mismatch")
    return ABBBitDecryptor(public, basis, width_squared,
        epsilon_bits=epsilon_bits, options=options).decrypt(ciphertext, rng=rng)
