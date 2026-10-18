"""AP09 Algorithm 1, section 3.3, as CHKP's 2011 GenBasis option.

The public matrix is ``A1 || -A1(G+R)``.  A1 is sampled uniformly, the
nonzero part of R is ternary, and the returned *complete* integer kernel
basis is the AP09 second-construction basis.  Unlike the MP12 root, no public
identity block is fixed.  This module supplies a bounded research domain and
an unconditional finite-abort/near-uniformity ledger; neither is a security
parameter admission or a proof for the HIBE built on top of this root.

Sources: Alwen--Peikert, Generating Shorter Bases for Hard Random Lattices,
Algorithm 1 and Lemma 3.5 (author full version, section 3.3); Cash et al.,
Bonsai Trees, 2011-06-14 author version, Proposition 3.1 (PDF page 13).
Basis vectors are columns.  All exact algebra uses Sage in the project's WSL
conda environment; random bytes come from the injected read(n)->bytes source.
"""

from dataclasses import asdict, dataclass, field
from math import isqrt

from sage.all import GF, QQ, ZZ, block_matrix, identity_matrix, matrix, zero_matrix

from ibme.core.errors import InvalidParameterError
from ibme.core.randomness import SecureRandom, DeterministicRandom
from ibme.lattice.chkp.basis import KernelBasis, ModMatrixReference, complete_kernel_basis
from ibme.lattice.chkp.entropy import CheckedEntropy
from ibme.lattice.chkp.gaussian import SamplingAbort, draw_uniform_integer
from ibme.lattice.matrix_sampling.basis import canonical_basis


MAX_DIMENSION = 1536
MAX_MODULUS_BITS = 256
_CERTIFICATE_PRECISION_BITS = 256


def _bounded_integer(value, name, low, high):
    if isinstance(value, bool) or not isinstance(value, (int, type(ZZ(0)))):
        raise InvalidParameterError(f"{name} requires an exact integer")
    value = int(value)
    if not low <= value <= high:
        raise InvalidParameterError(f"{name} exceeds the AP09 research domain")
    return value


def _ceil_sqrt(value):
    root = isqrt(int(value))
    return root + int(root * root < value)


@dataclass(frozen=True)
class AP09RootParams:
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
            object.__setattr__(self, name, _bounded_integer(getattr(self, name), name, low, high))
        if self.q % 2 == 0 or not ZZ(self.q).is_prime(proof=True):
            raise InvalidParameterError("AP09 root requires a proven odd prime q")
        if self.dimension > MAX_DIMENSION:
            raise InvalidParameterError("AP09 complete-basis dimension exceeds 1536")
        if not self.m1 >= self.random_rows > self.n * self.log_q_ceiling:
            raise InvalidParameterError("AP09 requires m1 >= d > n*ceil(log2 q)")
        if self.m2 < 2 * self.n * self.log_q_ceiling + 2 * self.random_rows:
            raise InvalidParameterError("AP09 digit/Hadamard blocks exceed m2")
        # Each R entry has magnitude <=1, so ||R||_2 <= ||R||_F <= sqrt(d*m2).
        # The Hadamard block has minimum singular value C'*sqrt(w).  This gate
        # enforces the AP09 section 3.3 proof's <=1/2 perturbation condition
        # for *every* accepted R, without conditioning on a quality event.
        if 4 * self.random_rows * self.m2 > self.hadamard_scale**2 * self.hadamard_width:
            raise InvalidParameterError("deterministic AP09 quality gate failed")
        if self.random_tape_bytes > self.max_entropy_bytes:
            raise InvalidParameterError("AP09 root entropy budget exceeded")

    @property
    def log_q_ceiling(self):
        return (self.q - 1).bit_length()

    @property
    def dimension(self):
        return self.m1 + self.m2

    @property
    def hadamard_width(self):
        remainder = self.m2 - 2 * self.n * self.log_q_ceiling
        return 1 << (remainder.bit_length() - 1)

    @property
    def gs_squared_bound(self):
        # AP09 section 3.3's two column groups, with its finite sufficient
        # quality gate above; this is a public bound, not a measured width.
        # The paper gives ||projection(S2)||² <= 8*n*log(q), followed by an
        # added unit vector.  Squaring that final +1 matters: the rational
        # upper bound 16*n*ceil(log2(q))+2 safely covers it.
        return max((self.hadamard_scale + 3)**2 * self.random_rows + 5,
                   16 * self.n * self.log_q_ceiling + 2)

    @property
    def random_tape_bytes(self):
        # Worst case for bounded uniform rejection, plus one byte per R entry.
        return (self.n * self.m1 * self.uniform_trials * ((self.log_q_ceiling + 7) // 8)
                + self.random_rows * self.m2)

    def certificate(self):
        """Public one-attempt bound, including rank and finite RNG aborts.

        The AP09 LHL comparison precedes the rank ABORT.  All terms are
        deliberately conservative and must be read as *statistical* bounds.
        A nonvacuous bound does not certify LWE hardness or CHKP security.
        """
        rank_ok = QQ(1)
        for i in range(self.n):
            rank_ok *= 1 - QQ(self.q)**(i - self.m1)
        radicand = QQ(self.q)**self.n / 2**self.random_rows
        scaled = int((radicand * 2**(2 * _CERTIFICATE_PRECISION_BITS)).ceil())
        matrix_tv = min(QQ(1), QQ(self.m2 * _ceil_sqrt(scaled))
                        / 2**_CERTIFICATE_PRECISION_BITS)
        rank_abort = 1 - rank_ok
        entropy_abort = min(QQ(1), QQ(self.n * self.m1) / 2**self.uniform_trials)
        total = min(QQ(1), matrix_tv + rank_abort + entropy_abort)
        return {
            "schema": "IBME/CHKP/AP09-ROOT/1",
            "algorithm": "AP09 Algorithm 1, section 3.3 second construction",
            "parameters": asdict(self), "dimension": self.dimension,
            "hadamard_width": self.hadamard_width,
            "public_gs_squared_bound": self.gs_squared_bound,
            "quality_gate": "4*d*m2 <= Cprime^2*w; Frobenius sufficient condition",
            "quality_bad_probability_inside_domain": "0",
            "paper_matrix_tv_upper_before_rank_abort": str(matrix_tv),
            "ideal_A1_rank_abort": str(rank_abort),
            "finite_uniform_integer_abort_upper": str(entropy_abort),
            "output_vs_uniform_tv_upper_including_abort": str(total),
            "near_uniform_bound_nonvacuous": total < 1,
            "upward_rounding_bits": _CERTIFICATE_PRECISION_BITS,
            "random_tape_bytes_upper": self.random_tape_bytes,
            "rank_retry": False, "randomness_assumption": "independent uniform bytes",
            "constant_time": False, "security_claim": "none",
            "backend_admitted": False, "parameters_are_formal": False,
            "LWE_hardness_verified": False, "CHKP_HIBE_verified": False,
        }


def _sylvester(width):
    result = matrix(ZZ, [[1]])
    while result.nrows() < width:
        result = block_matrix([[result, result], [result, -result]])
    return result


def _ap09_blocks(params, h):
    """Construct G, P, U with G*P+I=H and det(U)=1."""
    g = zero_matrix(ZZ, params.m1, params.m2)
    p = zero_matrix(ZZ, params.m2, params.m1)
    u = identity_matrix(ZZ, params.m2)
    offset = 0
    for i in range(params.m1):
        width = (int(h[i, i]) - 1).bit_length()
        for j in range(params.m1):
            value = int(h[i, j]) - int(i == j)
            if not 0 <= value < h[i, i]:
                raise ArithmeticError("AP09 HNF digit convention failed")
            for k in range(width):
                p[offset + k, j] = (value >> k) & 1
        for k in range(width):
            g[i, offset + k] = 1 << k
            if k + 1 < width:
                u[offset + k, offset + k + 1] = -2
        offset += width
    width = params.hadamard_width
    if offset + width > params.m2 or params.random_rows > width:
        raise ArithmeticError("AP09 block dimension contract failed")
    hadamard = _sylvester(width)
    for i in range(params.random_rows):
        for j in range(width):
            g[i, offset + j] = params.hadamard_scale * hadamard[i, j]
    if g * p != h - identity_matrix(ZZ, params.m1):
        raise ArithmeticError("AP09 GP+I=H failed")
    return g, p, u


@dataclass(frozen=True, repr=False)
class AP09RootResult:
    params: AP09RootParams
    basis: KernelBasis = field(repr=False)
    public_gs_squared_bound: int
    public_generation_certificate: dict = field(repr=False)
    entropy_bytes: int
    security_claim: str = field(default="none", init=False)
    backend_admitted: bool = field(default=False, init=False)


class AP09RootGenerator:
    """One AP09 attempt.  Any rank or finite-byte failure propagates."""

    def __init__(self, params):
        if not isinstance(params, AP09RootParams):
            raise InvalidParameterError("explicit AP09RootParams required")
        self.params = params

    def generate(self, *, rng=None):
        p = self.params
        source = CheckedEntropy(SecureRandom() if rng is None else rng,
                                p.random_tape_bytes)
        a1 = matrix(ZZ, p.n, p.m1, [
            draw_uniform_integer(source, p.q, max_trials=p.uniform_trials)
            for _ in range(p.n * p.m1)])
        if matrix(GF(p.q), a1).rank() != p.n:
            raise SamplingAbort("AP09 A1 rank failure; no automatic retry")
        anchor = complete_kernel_basis(ModMatrixReference(a1, p.q))
        h = matrix(ZZ, canonical_basis(anchor).basis_rows)
        g, projections, u = _ap09_blocks(p, h)
        r = zero_matrix(ZZ, p.m1, p.m2)
        for i in range(p.random_rows):
            for j in range(p.m2):
                bits = draw_uniform_integer(source, 4, max_trials=p.uniform_trials)
                r[i, j] = (bits & 1) - ((bits >> 1) & 1)
        public = ModMatrixReference(a1.augment(-a1 * (g + r)), p.q)
        s = block_matrix([[(g + r) * u, r * projections - identity_matrix(ZZ, p.m1)],
                          [u, projections]])
        # Checks rank, A*S=0 mod q, and |det(S)|=q^n: no public-basis fallback.
        basis = KernelBasis(public, s)
        cert = p.certificate()
        cert["entropy_source"] = ("system" if rng is None else
                                  "deterministic-test" if isinstance(rng, DeterministicRandom)
                                  else "external-byte-source")
        cert["actual_entropy_bytes"] = source.bytes_used
        cert["complete_kernel_checked"] = True
        return AP09RootResult(p, basis, p.gs_squared_bound, cert,
                              source.bytes_used)
