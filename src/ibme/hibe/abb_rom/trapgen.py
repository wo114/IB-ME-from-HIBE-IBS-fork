"""AP09 Algorithm 1 / section 3.3 for ABB's actual Setup family.

This bounded profile extends the executable matrix domain, not the old AP09
experiment's guards. The Hadamard quality test is deterministic and public.
Uniformity, rank abort and entropy abort are separate from LWE hardness.
Basis vectors are columns; the private R is ternary, as AP09 specifies.
"""

from dataclasses import dataclass, field
from math import isqrt

from sage.all import GF, QQ, ZZ, block_matrix, identity_matrix, matrix, zero_matrix

from ibme.core.errors import InvalidParameterError
from ibme.core.randomness import SecureRandom
from ibme.lattice.research import KernelBasis, ModMatrixReference, SamplingAbort
from experiments.research.chkp_basis import complete_kernel_basis
from experiments.research.gaussian_reference import draw_uniform_integer
from experiments.research.first_suite.entropy import CheckedEntropy

MAX_DIMENSION = 1536
MAX_MODULUS_BITS = 256


def bounded_integer(value, name, low, high):
    if isinstance(value, bool) or not isinstance(value, (int, type(ZZ(0)))):
        raise InvalidParameterError(f"{name} requires an exact integer")
    value = int(value)
    if not low <= value <= high:
        raise InvalidParameterError(f"{name} exceeds the AP09 resource domain")
    return value


def ceil_sqrt(value):
    value = int(value)
    root = isqrt(value)
    return root + int(root * root < value)


@dataclass(frozen=True)
class ABBTrapGenParams:
    n: int
    q: int
    random_rows: int
    m1: int
    m2: int
    hadamard_scale: int = 32
    uniform_trials: int = 192
    max_entropy_bytes: int = 2**30
    security_claim: str = field(default="none", init=False)
    backend_admitted: bool = field(default=False, init=False)
    parameters_are_formal: bool = field(default=False, init=False)

    def __post_init__(self):
        limits = {
            "n": (1, 64), "q": (3, 2**MAX_MODULUS_BITS - 1),
            "random_rows": (1, MAX_DIMENSION), "m1": (1, MAX_DIMENSION),
            "m2": (1, MAX_DIMENSION), "hadamard_scale": (1, 4096),
            "uniform_trials": (1, 4096), "max_entropy_bytes": (1, 2**40),
        }
        for name, (low, high) in limits.items():
            object.__setattr__(self, name, bounded_integer(getattr(self, name), name, low, high))
        if self.q % 2 != 1 or not ZZ(self.q).is_prime(proof=True):
            raise InvalidParameterError("ABB AP09 requires a proven odd prime")
        if self.dimension > MAX_DIMENSION:
            raise InvalidParameterError("AP09 complete-basis dimension exceeds 1536")
        if not self.m1 >= self.random_rows > self.n * self.log_q_ceiling:
            raise InvalidParameterError("AP09 requires m1 >= d > n*ceil(log2(q))")
        if self.m2 < 2 * self.n * self.log_q_ceiling + 2 * self.random_rows:
            raise InvalidParameterError("AP09 Hadamard/digit blocks exceed m2")
        if 4 * self.random_rows * self.m2 > self.hadamard_scale**2 * self.hadamard_width:
            raise InvalidParameterError("AP09 deterministic quality test failed")
        if self.random_tape_bytes > self.max_entropy_bytes:
            raise InvalidParameterError("AP09 whole-generation entropy budget exceeded")

    @property
    def dimension(self):
        return self.m1 + self.m2

    @property
    def log_q_ceiling(self):
        return (self.q - 1).bit_length()

    @property
    def hadamard_width(self):
        remaining = self.m2 - 2 * self.n * self.log_q_ceiling
        return 1 << (remaining.bit_length() - 1)

    @property
    def gs_squared_bound(self):
        return max((self.hadamard_scale + 3)**2 * self.random_rows + 5,
                   8 * self.n * self.log_q_ceiling + 2)

    @property
    def random_tape_bytes(self):
        return (self.n * self.m1 * self.uniform_trials * ((self.log_q_ceiling + 7) // 8)
                + self.random_rows * self.m2)

    def certificate(self):
        """Public, unconditional one-attempt certificate; no private geometry."""
        rank_ok = QQ(1)
        for i in range(self.n):
            rank_ok *= 1 - QQ(self.q)**(i - self.m1)
        # Upward rounding must support the declared high precision: a fixed
        # 80-bit grid would give vacuous results for a 128-bit regularity target.
        rounding_bits = 256
        radicand = QQ(self.q**self.n) / 2**self.random_rows
        scaled = int((radicand * 2**(2 * rounding_bits)).ceil())
        matrix_tv = min(QQ(1), QQ(self.m2 * ceil_sqrt(scaled)) / 2**rounding_bits)
        rank_abort = 1 - rank_ok
        entropy_abort = min(QQ(1), QQ(self.n * self.m1) / 2**self.uniform_trials)
        return {
            "profile": "ABB-AP09-SECOND-FINITE/1",
            "algorithm": "AP09 Algorithm 1 / section 3.3, ABB10 Theorem 1 Setup family",
            "n": self.n, "q": str(self.q), "dimension": self.dimension,
            "random_rows": self.random_rows, "m1": self.m1, "m2": self.m2,
            "hadamard_scale": self.hadamard_scale, "hadamard_width": self.hadamard_width,
            "public_gs_squared_bound": self.gs_squared_bound,
            "paper_setup_dimension_sufficient": self.dimension > 6 * self.n * self.log_q_ceiling,
            "paper_matrix_tv_upper_before_rank_abort": str(matrix_tv),
            "matrix_uniformity_comparison": "uniform A1; AP09 LHL bound before the rank ABORT coupling",
            "rank_abort_upper": str(rank_abort), "uniform_integer_abort_upper": str(entropy_abort),
            "output_vs_uniform_tv_upper_including_abort": str(min(1, matrix_tv + rank_abort + entropy_abort)),
            "uniformity_rounding_bits": rounding_bits,
            "quality_failure_inside_deterministic_domain": "0",
            "random_tape_bytes": self.random_tape_bytes,
            "randomness": "independent uniform bytes; default SecureRandom; fixed seeds only tests",
            "rank_retry": False, "constant_time": False,
            "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False,
            "LWE_hardness_verified": False, "full_ABB_HIBE": False,
        }


def _hadamard(width):
    result = matrix(ZZ, [[1]])
    while result.nrows() < width:
        result = block_matrix([[result, result], [result, -result]])
    return result


def _components(params, h):
    g = zero_matrix(ZZ, params.m1, params.m2)
    p = zero_matrix(ZZ, params.m2, params.m1)
    u = identity_matrix(ZZ, params.m2)
    offset = 0
    for i in range(params.m1):
        width = (int(h[i, i]) - 1).bit_length()
        for j in range(params.m1):
            value = int(h[i, j]) - int(i == j)
            if not 0 <= value < h[i, i]:
                raise ArithmeticError("AP09 canonical column-HNF digit convention failed")
            for k in range(width):
                p[offset + k, j] = (value >> k) & 1
        for k in range(width):
            g[i, offset + k] = 2**k
            if k + 1 < width:
                u[offset + k, offset + k + 1] = -2
        offset += width
    width = params.hadamard_width
    if offset + width > params.m2 or params.random_rows > width:
        raise ArithmeticError("AP09 public block-size guarantee failed")
    hadamard = _hadamard(width)
    for i in range(params.random_rows):
        for j in range(width):
            g[i, offset + j] = params.hadamard_scale * hadamard[i, j]
    # U is unit upper triangular by construction. GP+I=H and the Hadamard
    # rows give the exact block identity and deterministic quality argument.
    if g * p != h - identity_matrix(ZZ, params.m1):
        raise ArithmeticError("AP09 GP+I=H failed")
    return g, p, u


@dataclass(frozen=True, repr=False)
class ABBTrapGenResult:
    basis: KernelBasis = field(repr=False)
    params: ABBTrapGenParams
    entropy_bytes: int
    security_claim: str = field(default="none", init=False)
    backend_admitted: bool = field(default=False, init=False)


def abb_trapgen(params, *, rng=None):
    """One real AP09 generation; no MP12 root or public-basis fallback."""
    if not isinstance(params, ABBTrapGenParams):
        raise InvalidParameterError("explicit ABBTrapGenParams required")
    source = CheckedEntropy(SecureRandom() if rng is None else rng, params.random_tape_bytes)
    a1 = matrix(ZZ, params.n, params.m1, [
        draw_uniform_integer(source, params.q, max_trials=params.uniform_trials)
        for _ in range(params.n * params.m1)])
    if matrix(GF(params.q), a1).rank() != params.n:
        raise SamplingAbort("AP09 A1 rank failure; no regeneration")
    # HNF acts on rows; transpose on both sides for a column-lattice basis.
    anchor = complete_kernel_basis(ModMatrixReference(a1, params.q))
    h = matrix(ZZ, anchor.basis_rows).transpose().hermite_form().transpose()
    g, p, u = _components(params, h)
    r = zero_matrix(ZZ, params.m1, params.m2)
    for i in range(params.random_rows):
        for j in range(params.m2):
            bits = draw_uniform_integer(source, 4, max_trials=params.uniform_trials)
            r[i, j] = (bits & 1) - ((bits >> 1) & 1)
    public = ModMatrixReference(a1.augment(-a1 * (g + r)), params.q)
    s = block_matrix([[(g + r) * u, r * p - identity_matrix(ZZ, params.m1)], [u, p]])
    # KernelBasis independently verifies full rank, AS=0 and |det S|=q^n.
    basis = KernelBasis(public, s)
    return ABBTrapGenResult(basis, params, source.bytes_used)
