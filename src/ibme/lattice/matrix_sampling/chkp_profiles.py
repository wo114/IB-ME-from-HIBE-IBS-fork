"""Explicit CHKP profiles over the existing matrix sampling engines.

PR14 uses squared scalar widths through 2**88 and an explicit GPV dimension
through 512, unlike the original first-suite 2**80 / 256 profile. Keep those
domains separate without copying scalar, GPV, RandBasis or ToBasis arithmetic.
This is an integration proposal; it does not register or replace a backend.
CHKP's ExtendedGPV is supplied by that implementation after its source handoff.
"""

from dataclasses import asdict, dataclass
from sage.all import ZZ, vector

from .scalar import FirstFiniteOptions as LegacyOptions, MatrixFiniteGaussian, exact_integer
from .gpv import MatrixFiniteGPV
from .basis import MatrixBasisLimits, canonical_basis, to_basis
from .randbasis import MatrixFiniteRandBasis, MatrixFiniteRandResult


MAX_SQUARED_WIDTH = 2**88
MAX_DIMENSION = 512
MAX_INPUT_BITS = 2048
MAX_ENTRY_BITS = 8192
MAX_CONTENT_BYTES = 2**30


@dataclass(frozen=True)
class CHKPFiniteOptions(LegacyOptions):
    """Same parameter fields/defaults as PR14; not the legacy width profile."""


def _options(options):
    # Legacy byte-budget templates have exactly the same fields. Revalidate
    # their values in the target profile; do not mutate or widen that caller's
    # scalar/GPV implementation. Arbitrary wide MatrixFiniteOptions stay out.
    if isinstance(options, LegacyOptions) and not isinstance(options, CHKPFiniteOptions):
        return CHKPFiniteOptions(**asdict(options))
    return options


class CHKPFiniteGaussian(MatrixFiniteGaussian):
    MAX_SQUARED_WIDTH = MAX_SQUARED_WIDTH
    OPTIONS_TYPE = CHKPFiniteOptions
    PROFILE_ID = "FIRST-SUITE-FINITE-DGS/1"
    WIDTH_DOMAIN_ERROR = "Public squared widths require 1 <= min <= max <= 2^88"

    def __init__(self, width_min_squared, width_max_squared, *, options=None):
        super().__init__(width_min_squared, width_max_squared, options=_options(options))


class CHKPFiniteGPV(MatrixFiniteGPV):
    MAX_DIMENSION = MAX_DIMENSION
    MAX_INPUT_BITS = MAX_INPUT_BITS
    MAX_CONTENT_BYTES = MAX_CONTENT_BYTES
    OPTIONS_TYPE = CHKPFiniteOptions
    SCALAR_CLASS = CHKPFiniteGaussian
    PROFILE_ID = "FIRST-SUITE-FINITE-GPV/1"
    WIDTH_DOMAIN_ERROR = "Scalar squared width outside independent finite profile 1..2^88"

    def __init__(self, basis, width_squared, *, epsilon_bits=32,
                 options=None, max_dimension=256):
        super().__init__(basis, width_squared, epsilon_bits=epsilon_bits,
                         options=_options(options), max_dimension=max_dimension)
        # Retain the peer's exact diagnostic view. The shared sampler keeps
        # using its admitted rational projections; both views are identical.
        weights = []
        for row, resource in zip(self._weights, self._path_resources):
            denominator = ZZ(resource[0])
            numerators = vector(ZZ, [denominator*x for x in row])
            numerators.set_immutable()
            weights.append((numerators, denominator))
        self._integer_weights = tuple(weights)


@dataclass(frozen=True)
class CHKPFiniteRandResult(MatrixFiniteRandResult):
    pass


class CHKPFiniteRandBasis(MatrixFiniteRandBasis):
    SAMPLER_TYPE = CHKPFiniteGPV
    RESULT_TYPE = CHKPFiniteRandResult
    MAX_TAPE_BYTES = 2**40
    PROFILE_ID = "FIRST-SUITE-FINITE-RANDBASIS/1"

    def __init__(self, sampler, *, max_vectors, max_tape_bytes=2**40,
                 max_dimension=192):
        limit = exact_integer(max_dimension, "max_dimension", minimum=1,
                              maximum=MAX_DIMENSION)
        if not isinstance(sampler, CHKPFiniteGPV):
            # Only the known, backend-owned extension is eligible. No duck
            # typing, fixture sampler or fallback can enter RandBasis here.
            try:
                from ibme.lattice.chkp.extended_gpv import ExtendedGPV
            except ModuleNotFoundError as exc:
                if exc.name not in ("ibme.lattice.chkp", "ibme.lattice.chkp.extended_gpv"):
                    raise
                raise ValueError("CHKP ExtendedGPV source handoff is required") from exc
            if not isinstance(sampler, ExtendedGPV) or not isinstance(sampler.parent, CHKPFiniteGPV):
                raise ValueError("RandBasis needs the shared CHKP GPV or actual ExtendedGPV consumer")
            self.SAMPLER_TYPE = (CHKPFiniteGPV, ExtendedGPV)
        self.max_dimension = limit
        super().__init__(sampler, max_vectors=max_vectors, max_tape_bytes=max_tape_bytes,
                         basis_limits=_basis_limits(limit))


def _basis_limits(max_dimension):
    limit = exact_integer(max_dimension, "max_dimension", minimum=1,
                          maximum=MAX_DIMENSION)
    # Exact-content admission is an additional engineering abort, not an RSS
    # guarantee or a Gaussian error term. All other CHKP input limits remain.
    return MatrixBasisLimits(limit, MAX_ENTRY_BITS, MAX_CONTENT_BYTES)


def chkp_canonical_basis(basis, *, max_dimension=192):
    return canonical_basis(basis, limits=_basis_limits(max_dimension))


def chkp_to_basis(vectors_rows, basis, *, max_dimension=192):
    return to_basis(vectors_rows, basis, limits=_basis_limits(max_dimension))
