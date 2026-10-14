"""Compatibility entry for FIRST-SUITE-FINITE-GPV/1.

One implementation lives in ibme.lattice.matrix_sampling.gpv. Original
limits, error/coset semantics, entropy injection and certificate remain.
"""

from ibme.core.randomness import SecureRandom
from ibme.lattice.matrix_sampling.gpv import (
    MatrixFiniteGPV, _bit_length, _bounded_rational, _bounded_basis,
    _gs_geometry, _admit_paths,
)
from .finite_gaussian import FirstFiniteOptions, FirstFiniteGaussian

MAX_DIMENSION = 256
MAX_INPUT_BITS = 1024


class FirstFiniteGPV(MatrixFiniteGPV):
    MAX_DIMENSION = 256
    MAX_INPUT_BITS = 1024
    OPTIONS_TYPE = FirstFiniteOptions
    SCALAR_CLASS = FirstFiniteGaussian
    PROFILE_ID = "FIRST-SUITE-FINITE-GPV/1"

    def __init__(self, basis, width_squared, *, epsilon_bits=32,
                 options=None, max_dimension=256):
        super().__init__(basis, width_squared, epsilon_bits=epsilon_bits,
                         options=options, max_dimension=max_dimension)

    def sample(self, syndrome, *, rng=None):
        self._syndrome(syndrome)
        return super().sample(syndrome, rng=SecureRandom() if rng is None else rng)
