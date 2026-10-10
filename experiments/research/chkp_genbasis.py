"""AP09 Algorithm 1 / section 3.3, finite-domain second construction.

Author version 2010-07-10, PDF 9 and 13--17. A deterministic sufficient
quality gate replaces unspecified asymptotic constants ONLY on this admitted
finite domain. No rank retry, no claim of optimized parameters or security.
"""

from dataclasses import dataclass, field

from sage.all import GF, QQ, ZZ, block_matrix, identity_matrix, matrix, zero_matrix

from ibme.core.randomness import SecureRandom
from .chkp_basis import (
    KernelBasis, ModMatrixReference, complete_kernel_basis,
    gram_schmidt_squared_lengths,
)
from .chkp_tobasis import canonical_basis
from .gaussian_reference import SamplingAbort, draw_uniform_integer
from .online_gaussian_reference import exact_integer


@dataclass(frozen=True)
class AP09Parameters:
    n: int
    q: int
    random_rows: int
    m1: int
    m2: int
    hadamard_scale: int = 8
    max_uniform_trials: int = 192
    security_claim: str = field(default="none", init=False)

    def __post_init__(self):
        for name, low, high in (("n", 1, 16), ("q", 2, 2**61-1),
                               ("random_rows", 1, 192), ("m1", 1, 192),
                               ("m2", 1, 192), ("hadamard_scale", 1, 1024),
                               ("max_uniform_trials", 1, 4096)):
            object.__setattr__(self, name, exact_integer(getattr(self, name), name,
                                                        minimum=low, maximum=high))
        if not ZZ(self.q).is_prime(proof=True):
            raise ValueError("AP09 research reference requires prime q")
        ell = (self.q-1).bit_length()
        d = self.random_rows
        if self.m1 < d or d <= self.n*ell or self.m1+self.m2 > 192:
            raise ValueError("need m1 >= d > n*ceil(log2 q), dimension <= 192")
        if self.m2 < 2*self.n*ell + 2*d:
            raise ValueError("m2 must cover the rounded AP09 second-construction blocks")
        if 4*d*self.m2 > self.hadamard_scale**2*self.hadamard_width:
            raise ValueError("deterministic finite-domain AP09 quality gate not met")

    @property
    def hadamard_width(self):
        remaining = self.m2-2*self.n*(self.q-1).bit_length()
        return 1 << (remaining.bit_length()-1)

    @property
    def gs_squared_bound(self):
        # ||S1||² <= (C'+3)²*d+5. For S2: (2*sqrt(sum w_i)+1)²
        # <= 8*sum w_i+2 <= 8*n*ceil(log2 q)+2 (prime q).
        return max((self.hadamard_scale+3)**2*self.random_rows+5,
                   8*self.n*(self.q-1).bit_length()+2)


@dataclass(frozen=True)
class GenBasisResult:
    basis: KernelBasis = field(repr=False)
    parameters: AP09Parameters
    security_claim: str = field(default="none", init=False)
    backend_admitted: bool = field(default=False, init=False)


def _sylvester(size):
    h = matrix(ZZ, [[1]])
    while h.nrows() < size:
        h = block_matrix([[h, h], [h, -h]])
    return h


def _components(params, h):
    """Exact paper blocks: G P = H-I, U unimodular; no random R here."""
    m1, m2 = params.m1, params.m2
    g, p, u = zero_matrix(ZZ, m1, m2), zero_matrix(ZZ, m2, m1), identity_matrix(ZZ, m2)
    offset = 0
    for i in range(m1):
        width = (int(h[i, i])-1).bit_length()
        for j in range(m1):
            value = int(h[i, j]) - int(i == j)
            if not 0 <= value < h[i, i]:
                raise ArithmeticError("column HNF does not satisfy AP09 digit convention")
            for k in range(width):
                p[offset+k, j] = (value >> k) & 1
        for k in range(width):
            g[i, offset+k] = 2**k
            if k+1 < width:
                u[offset+k, offset+k+1] = -2
        offset += width
    w = params.hadamard_width
    if offset+w > m2 or params.random_rows > w:
        raise ArithmeticError("AP09 blocks exceeded admitted dimensions")
    hadamard = _sylvester(w)
    for i in range(params.random_rows):
        for j in range(w):
            g[i, offset+j] = params.hadamard_scale*hadamard[i, j]
    if g*p != h-identity_matrix(ZZ, m1) or u.det() != 1:
        raise ArithmeticError("AP09 component identities failed")
    return g, p, u


def gen_basis(params, *, rng=None):
    """One attempt. Rank-deficient A1 => ABORT, never hidden resampling."""
    if not isinstance(params, AP09Parameters):
        raise ValueError("need AP09Parameters")
    rng = SecureRandom() if rng is None else rng
    a1 = matrix(ZZ, params.n, params.m1, [
        draw_uniform_integer(rng, params.q, max_trials=params.max_uniform_trials)
        for _ in range(params.n*params.m1)])
    if matrix(GF(params.q), a1).rank() != params.n:
        raise SamplingAbort("AP09 A1 rank failure; no automatic retry")
    public1 = ModMatrixReference(a1, params.q)
    h = matrix(ZZ, canonical_basis(complete_kernel_basis(public1)).basis_rows)
    g, p, u = _components(params, h)
    r = zero_matrix(ZZ, params.m1, params.m2)
    for i in range(params.random_rows):
        for j in range(params.m2):
            bits = draw_uniform_integer(rng, 4, max_trials=params.max_uniform_trials)
            r[i, j] = (bits & 1)-((bits >> 1) & 1)
    a2 = -a1*(g+r)
    public = ModMatrixReference(a1.augment(a2), params.q)
    s = block_matrix([[(g+r)*u, r*p-identity_matrix(ZZ, params.m1)], [u, p]])
    basis = KernelBasis(public, s)
    if max(gram_schmidt_squared_lengths(s)) > params.gs_squared_bound:
        raise ArithmeticError("AP09 deterministic GS bound failed; implementation defect")
    return GenBasisResult(basis, params)


def genbasis_certificate(params):
    """Unconditional one-attempt budget; failure is not conditioned away."""
    if not isinstance(params, AP09Parameters):
        raise ValueError("need AP09Parameters")
    rank_ok = QQ(1)
    for i in range(params.n):
        rank_ok *= 1-QQ(params.q)**(i-params.m1)
    rank_abort = 1-rank_ok
    # Conservative LHL upper bound m2*sqrt(q^n/2^d), rounded UP dyadically.
    radicand = QQ(params.q**params.n)/2**params.random_rows
    scaled = ZZ((radicand*2**160).ceil())
    upper = scaled.isqrt()
    if upper*upper < scaled:
        upper += 1
    matrix_tv = min(QQ(1), params.m2*QQ(upper)/2**80)
    entropy_abort = min(QQ(1), QQ(params.n*params.m1)/2**params.max_uniform_trials)
    return {
        "algorithm": "AP09 second construction, Algorithm 1 / section 3.3",
        "parameters": {k: getattr(params, k) for k in (
            "n", "q", "random_rows", "m1", "m2", "hadamard_scale", "max_uniform_trials")},
        "hadamard_width": params.hadamard_width,
        "gs_squared_bound": params.gs_squared_bound,
        "quality_gate": "4*d*m2 <= Cprime^2*w; deterministic Frobenius sufficient condition",
        "quality_bad_probability_inside_admitted_domain": "0",
        "unconditioned_paper_matrix_tv_upper": str(matrix_tv),
        "ideal_A1_rank_abort_upper": str(rank_abort),
        "uniform_integer_abort_upper": str(entropy_abort),
        "actual_output_vs_uniform_including_abort_tv_upper": str(min(1, matrix_tv+rank_abort+entropy_abort)),
        "public_random_tape_bytes_upper": params.n*params.m1*params.max_uniform_trials*(((params.q-1).bit_length()+7)//8)+params.random_rows*params.m2,
        "rounding": "sqrt rounded upward to 2^-80; not a security level",
        "randomness_assumption": "independent uniform bytes; fixed seed tests are not proof",
        "near_uniform_bound_nonvacuous": matrix_tv+rank_abort+entropy_abort < 1,
        "dimension_optimality_claim": False, "security_claim": "none", "backend_admitted": False,
    }
