"""One finite RandBasis engine for matrix and preserved first-suite profiles.

Same exact Z independence and complete canonical-lattice postprocessor.
A modular hint accelerates only proven independence; exact fallback keeps
identical candidate acceptance and fixed random-tape behavior. Output TV
compares bounded processes including deterministic resource abort. Workspace
availability remains separate from the published ideal rank/norm bounds.
"""

from dataclasses import dataclass, field

from sage.all import GF, QQ, ZZ, matrix, vector

from ibme.core.randomness import SecureRandom
from .gpv import MatrixFiniteGPV
from .basis import MatrixBasisLimits, MATRIX_BASIS_LIMITS, canonical_basis, to_basis, admit_transform_content
from experiments.research.gaussian_reference import SamplingAbort
from experiments.research.mp12_sampled_reference import FiniteByteTape
from experiments.research.online_gaussian_reference import exact_integer
from experiments.research.first_suite.entropy import CheckedEntropy


@dataclass(frozen=True)
class MatrixFiniteRandResult:
    # The nested KernelBasis certifies algebra only. Its historical T1
    # is_randomized=False flag is not repurposed as a cryptographic claim.
    basis: object = field(repr=False)
    draws_used: int
    independent_vectors: int
    security_claim: str = field(default="none", init=False)
    backend_admitted: bool = field(default=False, init=False)


class MatrixFiniteRandBasis:
    """Select independent zero-syndrome samples, with K TOTAL attempts.

The reference ideal process uses the same finite K, norm-ABORT rule and
canonical lattice basis. K*delta_D bounds actual-vs-ideal output TV (including
ABORT); rank/norm terms additionally bound failure of that ideal process.
"""

    SAMPLER_TYPE = MatrixFiniteGPV
    RESULT_TYPE = MatrixFiniteRandResult
    BASIS_LIMITS = MATRIX_BASIS_LIMITS
    MAX_TAPE_BYTES = 2**44
    PROFILE_ID = "MATRIX-FINITE-RANDBASIS/1"

    def __init__(self, sampler, *, max_vectors, max_tape_bytes=2**44, basis_limits=None):
        if not isinstance(sampler, self.SAMPLER_TYPE):
            raise ValueError("RandBasis needs an admitted research GPV sampler")
        self.sampler = sampler
        self.dimension = sampler.dimension
        self.max_vectors = exact_integer(max_vectors, "max_vectors",
                                          minimum=self.dimension, maximum=4096)
        self.max_tape_bytes = exact_integer(max_tape_bytes, "max_tape_bytes",
                                           minimum=1, maximum=self.MAX_TAPE_BYTES)
        self.random_tape_bytes = self.max_vectors*sampler.random_tape_bytes
        if self.random_tape_bytes > self.max_tape_bytes:
            raise ValueError("Whole RandBasis tape exceeds the resource budget")
        self.basis_limits = self.BASIS_LIMITS if basis_limits is None else basis_limits
        if not isinstance(self.basis_limits, MatrixBasisLimits):
            raise ValueError("explicit MatrixBasisLimits required")
        self.canonical = canonical_basis(sampler.basis, limits=self.basis_limits)
        self.norm_squared_limit = sampler.width_squared * self.dimension
        # Pre-admit the full bounded set of candidate coordinates to ToBasis.
        ceiling = ZZ(self.norm_squared_limit.ceil()).isqrt() + 1
        inverse = matrix(QQ, self.canonical.basis_rows).inverse()
        coordinate_limit = max(sum(abs(x) for x in row) * ceiling
                               for row in inverse.rows())
        if (int(ceiling).bit_length() > self.basis_limits.max_entry_bits
                or int(coordinate_limit.ceil()).bit_length() > self.basis_limits.max_entry_bits):
            raise ValueError("all-candidate ToBasis coordinates exceed resource budget")
        self.transform_content_estimate = admit_transform_content(self.dimension,
            int(coordinate_limit.ceil()).bit_length(), limits=self.basis_limits)
        bits = sampler.epsilon_bits
        eps = QQ(1) / 2**bits
        self.rank_upper = min(QQ(1), QQ(2)**(self.dimension-self.max_vectors)
                              + 2*self.max_vectors*eps)
        self.tail_upper = min(QQ(1), (1+eps)/(1-eps)*QQ(2)**(-self.dimension))
        self.output_tv_upper = min(QQ(1), self.max_vectors*sampler.tv_upper)
        self.failure_upper = min(QQ(1), self.rank_upper
                                 + self.max_vectors*self.tail_upper
                                 + self.output_tv_upper)

    def sample(self, *, rng=None):
        rng = CheckedEntropy(SecureRandom() if rng is None else rng, self.random_tape_bytes)
        chosen = []
        hint = _ExactIndependenceHint(self.dimension, self.sampler.basis.public.q)
        zero = (0,) * self.sampler.basis.public.nrows
        for count in range(1, self.max_vectors + 1):
            candidate = vector(ZZ, self.sampler.sample(zero, rng=rng))
            if candidate.dot_product(candidate) > self.norm_squared_limit:
                raise SamplingAbort("RandBasis norm budget exceeded; entire call aborted")
            # A modular pivot proves independence over Z. A failed hint is
            # never rejection: fall back to the original exact Z rank test.
            if hint.accept(candidate, chosen):
                chosen.append(candidate)
            if len(chosen) == self.dimension:
                result = to_basis(matrix(ZZ, chosen).transpose(), self.canonical, limits=self.basis_limits)
                return self.RESULT_TYPE(result, count, len(chosen))
        raise SamplingAbort("RandBasis rank budget exhausted; no retry or fallback")

    def sample_from_tape(self, tape):
        if not isinstance(tape, (bytes, bytearray, memoryview)):
            raise ValueError("RandBasis tape must have the configured fixed length")
        size = tape.nbytes if isinstance(tape, memoryview) else len(tape)
        if size != self.random_tape_bytes:
            raise ValueError("RandBasis tape must have the configured fixed length")
        return self.sample(rng=FiniteByteTape(tape))

    def certificate(self):
        result = {
            "profile": self.PROFILE_ID, "algorithm": "CHKP RandBasis, independent finite K/norm-abort adaptation",
            "dimension": self.dimension, "max_vectors": self.max_vectors,
            "width_squared": str(self.sampler.width_squared),
            "candidate_norm_squared_limit": str(self.norm_squared_limit),
            "ideal_rank_exhaustion_upper": str(self.rank_upper),
            "one_ideal_norm_tail_upper": str(self.tail_upper),
            "actual_vs_bounded_ideal_output_tv_upper": str(self.output_tv_upper),
            "rank_or_norm_or_sampling_failure_upper": str(self.failure_upper),
            "failure_bound_nonvacuous": self.failure_upper < 1,
            "output_gs_squared_upper_on_success": str(self.norm_squared_limit),
            "public_random_tape_bytes": self.random_tape_bytes,
            "whole_call_random_tape_cap": self.max_tape_bytes,
            "public_test_evidence_only": True,
            "disclosure": "basis-dependent tape/profile diagnostics are excluded from the parent-basis output-TV comparison",
            "canonical_complete_lattice_basis": True,
            "all_candidate_tobasis_coordinate_resources_checked": True,
            "parent_basis_comparison": "at common s,K,norm cutoff and canonical postprocessor, TV <= K*(delta_D0+delta_D1); NOT exact basis independence",
            "ordinary_column_norm_preservation": False,
            "spectral_norm_preservation": False,
            "randomness_assumption": "independent uniform bytes; deterministic seeds only test executions",
            "production_random_api": True, "native_Sage_rng_used": False, "constant_time": False, "security_claim": "none", "backend_admitted": False,
        }

        if self.PROFILE_ID == "MATRIX-FINITE-RANDBASIS/1":
            result.update(completion_resource_gate_is_part_of_bounded_ideal_process=True,
                arithmetic_workspace_failure_upper=None,
                full_failure_upper_including_workspace=None,
                transform_content_estimate=self.transform_content_estimate,
                transform_content_estimate_is_not_measured_RSS=True,
                integer_rank_hint_rejection=False)
        return result


class _ExactIndependenceHint:
    """A sufficient modular hint plus exact fallback, never a new filter.

    Full modular row rank implies full integer row rank. Dependence modulo a
    fixed auxiliary prime does not imply dependence over Z, so use the exact
    original rank in that branch. If a Z-independent/mod-dependent row enters,
    disable the hint for later candidates. No entropy or change in acceptance.
    """
    def __init__(self, dimension, lattice_q):
        self.dimension = dimension
        self.field = GF(65521 if lattice_q != 65521 else 65519)
        self.pivots = []
        self.enabled = True

    def accept(self, candidate, chosen):
        if self.enabled:
            row = vector(self.field, candidate)
            for pivot, previous in self.pivots:
                coefficient = row[pivot]
                if coefficient:
                    row -= coefficient * previous
            pivot = next((j for j, value in enumerate(row) if value), None)
            if pivot is not None:
                row /= row[pivot]
                self.pivots.append((pivot, row))
                return True
        independent = matrix(ZZ, chosen + [candidate]).rank() > len(chosen)
        if independent:
            self.enabled = False
        return independent
