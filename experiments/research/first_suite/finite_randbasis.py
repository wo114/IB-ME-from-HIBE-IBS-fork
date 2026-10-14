"""Original first-suite RandBasis profile, now a single-engine consumer."""

from dataclasses import dataclass
from ibme.core.randomness import SecureRandom
from ibme.lattice.matrix_sampling.randbasis import MatrixFiniteRandBasis, MatrixFiniteRandResult
from ibme.lattice.matrix_sampling.basis import LEGACY_BASIS_LIMITS
from .finite_gpv import FirstFiniteGPV


@dataclass(frozen=True)
class FirstFiniteRandResult(MatrixFiniteRandResult):
    pass


class FirstFiniteRandBasis(MatrixFiniteRandBasis):
    SAMPLER_TYPE = FirstFiniteGPV
    RESULT_TYPE = FirstFiniteRandResult
    BASIS_LIMITS = LEGACY_BASIS_LIMITS
    MAX_TAPE_BYTES = 2**40
    PROFILE_ID = "FIRST-SUITE-FINITE-RANDBASIS/1"

    def __init__(self, sampler, *, max_vectors, max_tape_bytes=2**40):
        super().__init__(sampler, max_vectors=max_vectors, max_tape_bytes=max_tape_bytes)

    def sample(self, *, rng=None):
        return super().sample(rng=SecureRandom() if rng is None else rng)
