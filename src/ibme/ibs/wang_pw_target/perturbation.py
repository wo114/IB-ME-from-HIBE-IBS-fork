"""MP12 SampleD with perturbation for the Wang–PW target profile.

The user trapdoor T = [X; I] satisfies F_id·T = G (mod q) with F_id = [A|H1].
We sample z with the ideal coset Gaussian D_{Λ^⊥_{h2}(F_id), s_p} by

    p ~ N(0, Sigma),  Sigma = s_p² I − sigma_g² T T^T   (MP12 Lemma 5.3)
    z_g ~ D_{Λ^⊥_{h2 - F_id p}(G), sigma_g}             (gadget blocks)
    z = p + T z_g

so Cov(z) = Sigma + sigma_g² T T^T = s_p² I.  The perturbation width is
derived from the spectral norm ||T||_2 (power iteration), never from the
Frobenius norm, which would inflate s_p by two orders of magnitude.

All randomness comes from the backend's source (SecureRandom in production,
DeterministicRandom under test_only).  The final vector is checked with exact
mod-q arithmetic and the public squared-norm gate before it is returned.
"""

from __future__ import annotations

import math

import numpy as np
from scipy.linalg import cholesky

from .math import gadget, gram_schmidt
from .native import draw_gaussian, sample_gpv, SamplingError

# Gadget coset width: ker(G) bidiagonal GS norms are ~sqrt(5) <= 2.24, so 4
# leaves a two-sigma smoothing margin for the Klein/GPV block sampler.
GADGET_SIGMA = 4.0
# Power iteration is deterministic and deliberately conservative.
POWER_ITERATIONS = 48
POWER_MARGIN = 1.10


def gadget_kernel_basis(k: int, q: int) -> np.ndarray:
    """Columns of a complete Z-basis of {x in Z^k : g^T x = 0 mod q}."""
    basis = np.zeros((k, k), dtype=np.int64)
    qdigits = np.array([(q >> j) & 1 for j in range(k)], dtype=np.int64)
    for index in range(k - 1):
        basis[index, index] = 2
        basis[index + 1, index] = -1
    basis[:, k - 1] = qdigits
    return basis


def trapdoor_spectral_norm(trapdoor: np.ndarray, iterations: int = POWER_ITERATIONS) -> float:
    """Power iteration for ||[X; I]||_2 without forming T T^T.

    T = [X; I] is (m+w) x w, so T v = [X v; v] and T^T u = X^T u[:m] + u[m:].
    The Rayleigh quotient u·u converges to the largest eigenvalue of T T^T.
    """
    x = np.asarray(trapdoor, dtype=np.float64)
    if x.ndim != 2 or x.size == 0:
        raise ValueError("non-empty matrix trapdoor required")
    m, w = x.shape
    gen = np.random.default_rng(0x57504157)
    v = gen.standard_normal(w)
    v /= np.linalg.norm(v)
    eigenvalue = 0.0
    for _ in range(int(iterations)):
        u = np.concatenate((x @ v, v))
        eigenvalue = float(u @ u)
        wv = x.T @ u[:m] + u[m:]
        norm = float(np.linalg.norm(wv))
        if not math.isfinite(norm) or norm <= 0.0:
            break
        v = wv / norm
    if not math.isfinite(eigenvalue) or eigenvalue <= 0.0:
        raise SamplingError("spectral-norm estimate failed", public_reason="native-return-code")
    return math.sqrt(eigenvalue)


def _covariance(trapdoor: np.ndarray, s: float, sigma_g: float) -> np.ndarray:
    """Sigma = s² I − sigma_g² T T^T as a dense (dim, dim) float64 array."""
    x = np.asarray(trapdoor, dtype=np.float64)
    m, w = x.shape
    dim = m + w
    covariance = np.empty((dim, dim), dtype=np.float64)
    with np.errstate(all="ignore"):
        covariance[:m, :m] = x @ x.T
        covariance[:m, m:] = x
        covariance[m:, :m] = x.T
        covariance[m:, m:] = 0.0
        np.fill_diagonal(covariance[m:, m:], 1.0)
        covariance *= -(sigma_g * sigma_g)
        diagonal = np.diag(covariance).copy()
        diagonal += s * s
        np.fill_diagonal(covariance, diagonal)
    return covariance


def perturbation_factor(trapdoor: np.ndarray, sigma_g: float = GADGET_SIGMA,
                        *, max_doublings: int = 8):
    """Return (s_p, L) with L the lower Cholesky factor of Sigma (LL^T = Sigma).

    s_p starts at POWER_MARGIN·1.05·sigma_g·||T||_2 and doubles until the
    covariance is numerically positive definite.
    """
    lam = trapdoor_spectral_norm(trapdoor)
    s = sigma_g * lam * POWER_MARGIN * 1.05
    for _ in range(int(max_doublings)):
        covariance = _covariance(trapdoor, s, sigma_g)
        try:
            lower = cholesky(covariance, lower=True, overwrite_a=True, check_finite=False)
        except np.linalg.LinAlgError:
            lower = None
        if lower is not None:
            return s, lower
        s *= 2.0
    raise SamplingError("perturbation covariance never became positive definite",
                        public_reason="native-return-code")


def sample_perturbation(lower: np.ndarray, options: dict) -> np.ndarray:
    """p = round(L g) with g an integer standard Gaussian of matching size."""
    dim = lower.shape[0]
    g = draw_gaussian(dim, sigma=1.0, **options)
    if g.shape != (dim,):
        raise SamplingError("native perturbation draw returned the wrong shape",
                            public_reason="native-return-code")
    product = lower @ g.astype(np.float64)
    return np.rint(product).astype(np.int64)


def sample_gadget_solution(p, residue: np.ndarray, sigma_g: float, options: dict) -> np.ndarray:
    """z_g with G z_g = residue (mod q), block-wise D_{Lambda^perp, sigma_g}."""
    n, k, q = p.n, p.k, p.q
    residue = np.asarray(residue, dtype=np.int64)
    if residue.shape != (n,):
        raise ValueError("gadget residue must have one entry per row")
    basis = gadget_kernel_basis(k, q)
    star, norms, _width = gram_schmidt(basis)
    out = np.empty(n * k, dtype=np.int64)
    for row in range(n):
        particular = np.zeros(k, dtype=np.int64)
        particular[0] = int(residue[row]) % q
        block = sample_gpv(basis, star, norms, particular, sigma_g, **options)
        out[row * k:(row + 1) * k] = block
    return out


def sign_with_perturbation(backend, sk, message) -> "Signature":
    """Backend.sign for the perturbation route; mirrors the existing stages."""
    from .backend import checked_message, checked_identity  # local to avoid a cycle
    from .hashing import identity_matrix, inner_identity, inner_message, message_vector
    from .math import matmul_mod
    from .objects import Signature

    pk, p = sk.public_key, sk.public_key.params
    message = checked_message(p, message)
    backend._sign_stage("public-matrix")
    expected = identity_matrix(pk, inner_identity(p, sk.identity, sk.identity_salt))
    derived = (gadget(p.n, p.q) - matmul_mod(pk.a, sk.trapdoor, p.q)) % p.q
    if not np.array_equal(derived, expected):
        raise SamplingError("delegated public matrix mismatch",
                            public_reason="delegated-public-matrix")
    backend._sign_stage("random-salt")
    salt = backend._read(p.salt_bytes)
    backend._sign_stage("message-hash")
    x = inner_identity(p, sk.identity, sk.identity_salt)
    y = inner_message(p, message, salt)
    target = message_vector(pk, x, y)
    backend._sign_stage("perturbation")
    s_p, lower = perturbation_factor(sk.trapdoor, GADGET_SIGMA)
    perturbation = sample_perturbation(lower, backend._options(p))
    del lower
    backend._sign_stage("particular")
    f_id = np.hstack((pk.a, expected))
    residual = (target - matmul_mod(f_id, perturbation.reshape(-1, 1), p.q)[:, 0]) % p.q
    backend._sign_stage("native-gpv")
    gadget_part = sample_gadget_solution(p, residual, GADGET_SIGMA, backend._options(p))
    z = perturbation.copy()
    z[:p.m] += sk.trapdoor @ gadget_part
    z[p.m:] += gadget_part
    backend._sign_stage("signature-object")
    signature = Signature(pk.context, sk.identity_salt, salt, z)
    backend._sign_stage("final-verify")
    if not backend.verify(pk, sk.identity, message, signature):
        raise SamplingError("signature equation/norm gate failed; no hidden reroll",
                            public_reason="signature-equation-or-norm")
    backend.last_metrics["signature_norm_sq"] = sum(int(v) * int(v) for v in z)
    backend.last_metrics["perturbation_width"] = s_p
    backend._sign_stage("complete")
    return signature


