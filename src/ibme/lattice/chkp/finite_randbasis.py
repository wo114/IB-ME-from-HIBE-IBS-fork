"""Independent first-suite finite/CSPRNG RandBasis; existing ToBasis domain.

CHKP author 2011-06-14, section 3.4; project T2 finite contract C4--C6.
No retry after ABORT, no conditioning the report on a successful invocation.
No security level or production backend; not constant time.
"""

from dataclasses import dataclass, field

from sage.all import GF, QQ, ZZ, matrix, vector

from ibme.core.randomness import SecureRandom
from .finite_gpv import FirstFiniteGPV
from .extended_gpv import ExtendedGPV
from ibme.lattice.chkp.tobasis import MAX_ENTRY_BITS, canonical_basis, to_basis
from ibme.lattice.chkp.gaussian import SamplingAbort
from ibme.lattice.chkp.tape import FiniteByteTape
from ibme.lattice.chkp.finite_gaussian import exact_integer
from .entropy import CheckedEntropy


class _ExactIncrementalRank:
    """One-sided modular independence witness with exact rational fallback.

    A full-rank modular image of the retained rows plus the candidate proves
    independence over Q. If the retained rows already lost rank modulo the
    prime, a modular rank INCREASE alone proves nothing; that case and every
    modular dependence trigger the original exact check. Retained vectors and
    order are identical for every input sequence. No random bytes are used.
    """

    def __init__(self, dimension, *, witness_prime=2147483647):
        self.dimension = exact_integer(dimension, "rank dimension", minimum=1, maximum=512)
        prime = exact_integer(witness_prime, "rank witness prime", minimum=2, maximum=2**61-1)
        if not ZZ(prime).is_prime(proof=True):
            raise ValueError("rank witness requires a prime field")
        self.field = GF(prime)
        self.echelon = []
        self.chosen = []
        self.exact_fallbacks = 0

    def add(self, candidate):
        candidate = vector(ZZ, candidate)
        if len(candidate) != self.dimension:
            raise ValueError("rank candidate dimension mismatch")
        residual = vector(self.field, candidate)
        for pivot, row in self.echelon:
            if residual[pivot]:
                residual -= residual[pivot] * row
        pivot = next((i for i, value in enumerate(residual) if value), None)
        def retain():
            if pivot is not None:
                normalized = residual / residual[pivot]
                normalized.set_immutable()
                self.echelon.append((pivot, normalized))
                self.echelon.sort(key=lambda pair: pair[0])
            self.chosen.append(candidate)
            return True

        if pivot is not None and len(self.echelon) == len(self.chosen):
            return retain()
        self.exact_fallbacks += 1
        if matrix(ZZ, self.chosen + [candidate]).rank() > len(self.chosen):
            # An accepted but modularly dependent row leaves a rank deficit.
            # Keep using exact checks whenever that deficit is present.
            return retain()
        return False


@dataclass(frozen=True)
class FirstFiniteRandResult:
    # The nested KernelBasis certifies algebra only. Its historical T1
    # is_randomized=False flag is not repurposed as a cryptographic claim.
    basis: object = field(repr=False)
    draws_used: int
    independent_vectors: int
    security_claim: str = field(default="none", init=False)
    backend_admitted: bool = field(default=False, init=False)


class FirstFiniteRandBasis:
    """Select independent zero-syndrome samples, with K TOTAL attempts.

The reference ideal process uses the same finite K, norm-ABORT rule and
canonical lattice basis. K*delta_D bounds actual-vs-ideal output TV (including
ABORT); rank/norm terms additionally bound failure of that ideal process.
"""

    def __init__(self, sampler, *, max_vectors, max_tape_bytes=2**40, max_dimension=192):
        if not isinstance(sampler, (FirstFiniteGPV, ExtendedGPV)):
            raise ValueError("RandBasis needs an admitted research GPV sampler")
        self.sampler = sampler
        self.dimension = sampler.dimension
        self.max_vectors = exact_integer(max_vectors, "max_vectors",
                                          minimum=self.dimension, maximum=4096)
        self.max_tape_bytes = exact_integer(max_tape_bytes, "max_tape_bytes",
                                           minimum=1, maximum=2**40)
        self.random_tape_bytes = self.max_vectors*sampler.random_tape_bytes
        if self.random_tape_bytes > self.max_tape_bytes:
            raise ValueError("Whole RandBasis tape exceeds the resource budget")
        self.max_dimension = exact_integer(max_dimension, "max_dimension", minimum=1, maximum=512)
        self.canonical = canonical_basis(sampler.basis, max_dimension=self.max_dimension)
        self.norm_squared_limit = sampler.width_squared * self.dimension
        # Pre-admit the full bounded set of candidate coordinates to ToBasis.
        ceiling = ZZ(self.norm_squared_limit.ceil()).isqrt() + 1
        inverse = matrix(QQ, self.canonical.basis_rows).inverse()
        coordinate_limit = max(sum(abs(x) for x in row) * ceiling
                               for row in inverse.rows())
        if (int(ceiling).bit_length() > MAX_ENTRY_BITS
                or int(coordinate_limit.ceil()).bit_length() > MAX_ENTRY_BITS):
            raise ValueError("all-candidate ToBasis coordinates exceed resource budget")
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
        rank = _ExactIncrementalRank(self.dimension)
        zero = (0,) * self.sampler.basis.public.nrows
        for count in range(1, self.max_vectors + 1):
            candidate = vector(ZZ, self.sampler.sample(zero, rng=rng))
            if candidate.dot_product(candidate) > self.norm_squared_limit:
                raise SamplingAbort("RandBasis norm budget exceeded; entire call aborted")
            # The modular fast path is only a proof of Q-independence. Every
            # modular dependency is checked exactly; no candidate is dropped
            # because of its rank over a finite field.
            if rank.add(candidate):
                chosen.append(candidate)
            if len(chosen) == self.dimension:
                result = to_basis(matrix(ZZ, chosen).transpose(), self.canonical,
                                  max_dimension=self.max_dimension)
                return FirstFiniteRandResult(result, count, len(chosen))
        raise SamplingAbort("RandBasis rank budget exhausted; no retry or fallback")

    def sample_from_tape(self, tape):
        if not isinstance(tape, (bytes, bytearray, memoryview)):
            raise ValueError("RandBasis tape must have the configured fixed length")
        size = tape.nbytes if isinstance(tape, memoryview) else len(tape)
        if size != self.random_tape_bytes:
            raise ValueError("RandBasis tape must have the configured fixed length")
        return self.sample(rng=FiniteByteTape(tape))

    def certificate(self):
        return {
            "profile": "FIRST-SUITE-FINITE-RANDBASIS/1", "algorithm": "CHKP RandBasis, independent finite K/norm-abort adaptation",
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
