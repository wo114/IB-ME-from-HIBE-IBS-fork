"""Numeric batched GPV sampler for the Wang--PW block delegation.

Master basis: MP12 private_root_basis (deterministic full-basis conversion).
Sampler: float QR Gram--Schmidt + batched rank-1 updates (research numeric;
not the exact finite reference law).
"""
import math
import sys
import time

import numpy as np

import ibme.ibs.wang_pw as W
from .fast_root_basis import fast_root_basis


class FastParams(W.WangPWParams):
    def __post_init__(self):
        if type(self.n) is not int or self.n < 1:
            raise ValueError("n")
        if type(self.q) is not int or self.q < 3 or not W.is_probable_prime(self.q):
            raise ValueError("q")
        if type(self.m_bar) is not int or self.m_bar < self.w:
            raise ValueError("m_bar")


def as_np(matrix):
    return np.array([[int(x) for x in row] for row in matrix], dtype=np.int64)


def numeric_gs(B):
    Q, R = np.linalg.qr(B.astype(np.float64))
    norms = np.diag(R).astype(np.float64) ** 2
    star = Q * np.diag(R)
    return star, norms


def sample_batch(B, particulars, sigma, rng, star=None, norms=None):
    m, w = particulars.shape
    if star is None or norms is None:
        star, norms = numeric_gs(B)
    center = -particulars.astype(np.float64)
    out = particulars.astype(np.int64).copy()
    for i in range(m - 1, -1, -1):
        ci = (star[:, i] @ center) / norms[i]
        sigma_i = sigma / math.sqrt(float(norms[i]))
        zi = np.rint(rng.normal(ci, sigma_i)).astype(np.int64)
        col = B[:, i]
        center -= np.outer(col, zi)
        out += np.outer(col, zi)
    return out


def mod_vec(A, x, q):
    return [sum(int(a) * int(v) for a, v in zip(row, x)) % q for row in A]


def main(n=4, q=65521, m_bar=None):
    if m_bar is None:
        m_bar = n * ((q - 1).bit_length())
    p = FastParams(n=n, q=q, m_bar=m_bar)
    rng = np.random.default_rng(0)
    t0 = time.perf_counter()
    pk, msk = W.setup(p)
    A_sage, basis_sage = fast_root_basis(msk.a_bar(), msk.r_a(), p.q)
    A = [[int(x) for x in row] for row in A_sage]
    B = as_np(basis_sage)
    m = B.shape[0]
    print("setup+root", round(time.perf_counter() - t0, 2), "m", m, flush=True)

    t0 = time.perf_counter()
    star, norms = numeric_gs(B)
    width = math.sqrt(float(np.max(norms)))
    print("numeric_gs", round(time.perf_counter() - t0, 2), "width", round(width, 3), flush=True)

    identity = b"alice"
    H1 = W.hash_identity_matrix(pk, identity)
    w = p.w
    particulars = np.empty((m, w), dtype=np.int64)
    for j in range(w):
        target = [(-H1[i][j]) % p.q for i in range(p.n)]
        part = W._gf_solve(A, target, p.q)
        particulars[:, j] = part
    sigma = p.s_del * width * math.sqrt(m)
    t0 = time.perf_counter()
    X = sample_batch(B, particulars, sigma, rng, star, norms)
    print("X_batch", round(time.perf_counter() - t0, 2), flush=True)
    for j in range(0, w, max(1, w // 8)):
        target = [(-H1[i][j]) % p.q for i in range(p.n)]
        if mod_vec(A, X[:, j], p.q) != target:
            raise RuntimeError("X equation failed")

    T_id = np.zeros((m + w, m + w), dtype=np.int64)
    T_id[:m, :m] = B
    T_id[:m, m:] = X
    T_id[m:, m:] = np.eye(w, dtype=np.int64)
    F = [A[i] + H1[i] for i in range(p.n)]
    t0 = time.perf_counter()
    star2, norms2 = numeric_gs(T_id)
    width2 = math.sqrt(float(np.max(norms2)))
    print("block_gs", round(time.perf_counter() - t0, 2), "width", round(width2, 3), flush=True)

    message = b"hello"
    h2 = W.hash_message_vector(pk, identity, message)
    particular = W._gf_solve(F, h2, p.q)
    sigma_sign = p.verify_width / math.sqrt(2 * math.pi)
    t0 = time.perf_counter()
    z = sample_batch(T_id, np.array(particular, dtype=np.int64).reshape(-1, 1), sigma_sign, rng, star2, norms2).reshape(-1)
    norm = float(np.linalg.norm(z))
    print("sign", round(time.perf_counter() - t0, 2), "norm", round(norm, 2),
          "bound", round(p.verify_bound, 2), "eq", mod_vec(F, z, p.q) == h2, flush=True)


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 4
    q = int(sys.argv[2]) if len(sys.argv) > 2 else 65521
    main(n, q)
