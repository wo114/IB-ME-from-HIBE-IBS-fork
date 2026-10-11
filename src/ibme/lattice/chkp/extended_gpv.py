"""CHKP section 3.3.1 implicit SampleD for a right-extended lattice.

Sample the appended coordinates first from D_Z,s independently, then the
parent coset with syndrome y-Abar*vbar. This is the original ExtBasis
sampling optimization, not MP12 DelTrap. Its ideal comparison needs smoothing
for the parent lattice; bounds conservatively use the full extended dimension.
Finite oracle TV/abort terms are added by adaptive composition.
"""

from itertools import islice
from sage.all import QQ
from ibme.core.randomness import SecureRandom
from .basis import KernelBasis, ModMatrixReference, ext_basis, _integer
from .finite_gaussian import FirstFiniteGaussian, FirstFiniteOptions, exact_integer
from .finite_gpv import FirstFiniteGPV
from .entropy import CheckedEntropy


class ExtendedGPV:
    def __init__(self, basis, extension, width_squared, *, epsilon_bits=128,
                 options=None, max_dimension=512):
        limit = exact_integer(max_dimension, "max_dimension", minimum=1, maximum=512)
        if not isinstance(basis, KernelBasis) or not isinstance(extension, ModMatrixReference):
            raise ValueError("validated parent basis and extension required")
        if basis.public.q != extension.q or basis.public.nrows != extension.nrows:
            raise ValueError("extension has a different public field or row count")
        self.dimension = basis.public.ncols + extension.ncols
        if self.dimension > limit:
            raise ValueError("extended lattice dimension exceeds the explicit profile")
        opts = FirstFiniteOptions() if options is None else options
        self.parent = FirstFiniteGPV(basis, width_squared, epsilon_bits=epsilon_bits,
                                     options=opts, max_dimension=limit)
        self.width_squared = self.parent.width_squared
        self.epsilon_bits = self.parent.epsilon_bits
        self.extension = extension
        # ExtBasis contains the root and must never be returned as a delegated
        # key. RandBasis consumes it only for the canonical complete lattice.
        self.basis = ext_basis(basis, extension)
        self.scalar = FirstFiniteGaussian(self.width_squared, self.width_squared, options=opts)
        # Use the full dimension's C1-exec threshold; parent-only admission
        # would be a weaker promise than the declared extended SampleD profile.
        scale = 1 << self.epsilon_bits
        factor = (2 * self.dimension * (1 + scale) - 1).bit_length()
        if self.width_squared < 4 * max(QQ(1), self.parent._max_gs_squared) * factor:
            raise ValueError("extended width fails the full-dimension smoothing condition")
        self.random_tape_bytes = (self.parent.random_tape_bytes
                                 + extension.ncols * self.scalar.random_tape_bytes)
        if self.random_tape_bytes > opts.max_tape_bytes:
            raise ValueError("extended SampleD tape exceeds the explicit budget")
        # Include geometry for the parent partition functions and every scalar;
        # conservative extended dimension also covers the marginal discrepancy.
        denominator = scale - 2 * self.dimension - 1
        geometry = min(QQ(1), QQ(self.dimension) / denominator) if denominator > 0 else QQ(1)
        self.tv_upper = min(QQ(1), geometry + self.parent.tv_upper
                            + extension.ncols * self.scalar.tv_upper)

    def sample(self, syndrome, *, rng=None):
        if isinstance(syndrome, (str, bytes, bytearray, memoryview)):
            raise ValueError("syndrome must be an exact finite residue vector")
        try:
            y = tuple(islice(iter(syndrome), self.basis.public.nrows + 1))
        except TypeError as exc:
            raise ValueError("syndrome must be an exact finite residue vector") from exc
        q = self.basis.public.q
        if len(y) != self.basis.public.nrows:
            raise ValueError("wrong syndrome dimension")
        y = tuple(_integer(v, modulus=q) for v in y)
        if any(not 0 <= v < q for v in y):
            raise ValueError("syndrome must contain canonical residues")
        source = CheckedEntropy(SecureRandom() if rng is None else rng, self.random_tape_bytes)
        appended = tuple(int(self.scalar.sample(self.width_squared, 0, rng=source))
                         for _ in range(self.extension.ncols))
        adjusted = tuple((target - sum(a * v for a, v in zip(row, appended))) % q
                         for target, row in zip(y, self.extension.rows))
        return self.parent.sample(adjusted, rng=source) + appended
