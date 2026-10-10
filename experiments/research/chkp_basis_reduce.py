"""Deterministic exact LLL postprocessing, not a Gaussian sampler.

LLL82 section 1, (1.4)--(1.5), (1.22)--(1.26); delta=99/100.
Project proof: T2-width-basis-audit-2026-10-10.md. Research-only, variable
time, bounded work; an ABORT must NOT be retried or hidden from the ledger.
No parent basis, randomness or secret-dependent choice of delta is used.
"""

from dataclasses import dataclass, field
from copy import copy

from sage.all import QQ, ZZ, identity_matrix, matrix, vector

from .chkp_basis import KernelBasis
from .chkp_gpv import _bounded_basis
from .gaussian_reference import SamplingAbort
from .online_gaussian_reference import exact_integer


DELTA = QQ(99)/100
GAMMA = DELTA-QQ(1)/4
MAX_DIMENSION = 64
MAX_STEPS = 100000
MAX_BITS = 8192


def _geometry(b):
    d = b.ncols()
    stars, g = [], []
    mu = matrix(QQ, d, d)
    for i, col in enumerate(b.columns()):
        cur = vector(QQ, col)
        for j, star in enumerate(stars):
            mu[i, j] = vector(QQ, col).dot_product(star)/g[j]
            cur -= mu[i, j]*star
        norm = cur.dot_product(cur)
        if norm <= 0:
            raise ArithmeticError("LLL input lost full rank")
        stars.append(cur)
        g.append(norm)
    return mu, g


def _check_bits(b, u, mu, g):
    for value in (*b.list(), *u.list(), *mu.list(), *g):
        value = QQ(value)
        if max(abs(int(value.numerator())).bit_length(),
               int(value.denominator()).bit_length()) > MAX_BITS:
            raise SamplingAbort("LLL exact-arithmetic budget exhausted; no fallback")


@dataclass(frozen=True)
class ReducedBasis:
    basis: KernelBasis = field(repr=False)
    transform_rows: tuple = field(repr=False)
    steps: int
    swaps: int
    gs_squared_lower: object
    gs_squared_upper: object
    security_claim: str = field(default="none", init=False)
    backend_admitted: bool = field(default=False, init=False)


def reduce_basis(basis, *, max_steps=MAX_STEPS):
    """Return exact column B'=B*U with det(U)=+-1, or explicit failure.

Input <=64 dimensions/1024-bit entries; checked state limited to 8192 bits.
This is NOT a bound on all temporaries or peak memory: geometry and products
are computed before state checkpoints. Caps are NOT a uniform success theorem. The deterministic
map including ABORT preserves TV contraction, but success probabilities
need an additional resource-failure bound. Diagnostics are not public keys.
"""
    max_steps = exact_integer(max_steps, "max_steps", minimum=1, maximum=MAX_STEPS)
    basis = _bounded_basis(basis, MAX_DIMENSION, 1024)
    original = matrix(ZZ, basis.basis_rows)
    b = copy(original)
    d = b.ncols()
    u = identity_matrix(ZZ, d)
    mu, g = _geometry(b)
    original_max = max(g)
    _check_bits(b, u, mu, g)
    k, steps, swaps = 1, 0, 0
    while k < d:
        if steps == max_steps:
            raise SamplingAbort("LLL step budget exhausted; no fallback")
        steps += 1
        # Fixed descending order and exact floor(x+1/2), also for negative ties.
        for j in reversed(range(k)):
            r = ZZ((mu[k, j]+QQ(1)/2).floor())
            if r:
                b.add_multiple_of_column(k, j, -r)
                u.add_multiple_of_column(k, j, -r)
                for l in range(j):
                    mu[k, l] -= r*mu[j, l]
                mu[k, j] -= r
                _check_bits(b, u, mu, g)
        nu, a, c = mu[k, k-1], g[k-1], g[k]
        t = c+nu**2*a
        if t < DELTA*a:
            b.swap_columns(k-1, k)
            u.swap_columns(k-1, k)
            g[k-1], g[k] = t, a*c/t
            mu[k, k-1] = nu*a/t
            for j in range(k-1):
                mu[k-1, j], mu[k, j] = mu[k, j], mu[k-1, j]
            for i in range(k+1, d):
                old = mu[i, k]
                mu[i, k] = mu[i, k-1]-nu*old
                mu[i, k-1] = old+mu[k, k-1]*mu[i, k]
            swaps += 1
            k = max(1, k-1)
        else:
            k += 1
        _check_bits(b, u, mu, g)
    # Independently recompute geometry; incremental recurrences are not trusted.
    checked_mu, checked_g = _geometry(b)
    if checked_mu != mu or checked_g != g:
        raise ArithmeticError("LLL incremental geometry check failed")
    if (original*u != b or abs(u.det()) != 1
            or any(abs(mu[i, j]) > QQ(1)/2 for i in range(d) for j in range(i))
            or any(g[i]+mu[i, i-1]**2*g[i-1] < DELTA*g[i-1] for i in range(1, d))
            or max(g) > original_max or min(g) < GAMMA**(d-1)):
        raise ArithmeticError("LLL exact postcondition failed")
    return ReducedBasis(KernelBasis(basis.public, b),
                        tuple(tuple(int(x) for x in row) for row in u.rows()),
                        steps, swaps, min(g), max(g))
