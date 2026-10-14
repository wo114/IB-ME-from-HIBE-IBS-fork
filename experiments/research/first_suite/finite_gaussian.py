"""Compatibility entry for the original FIRST-SUITE-FINITE-DGS/1 profile.

Mathematics lives once in ibme.lattice.matrix_sampling.scalar. Original option
bounds, per-call RNG injection, profile ID and resource guards are retained.
The new matrix profile must be selected through its own public class.
"""

from ibme.core.randomness import SecureRandom
from ibme.lattice.matrix_sampling.scalar import (
    FirstFiniteOptions, MatrixFiniteGaussian, exact_integer, exact_rational,
    interval_upper, capped_exp_minus_pi, FiniteByteTape, SamplingAbort,
)
from .entropy import CheckedEntropy


class FirstFiniteGaussian(MatrixFiniteGaussian):
    MAX_SQUARED_WIDTH = 2**80
    OPTIONS_TYPE = FirstFiniteOptions
    PROFILE_ID = "FIRST-SUITE-FINITE-DGS/1"

    def sample(self, width_squared, center=0, *, rng=None):
        # Keep this module's old injectable system-entropy seam. Validation
        # still precedes the first byte read, and errors are never retried.
        self.checked_inputs(width_squared, center)
        source = SecureRandom() if rng is None else rng
        return super().sample(width_squared, center, rng=source)
