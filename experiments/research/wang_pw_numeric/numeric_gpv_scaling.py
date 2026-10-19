"""Scaling run: fast setup + MP12 root basis + numeric batched GPV."""
import math
import sys
import time

import numpy as np

from .fast_root_basis import fast_root_basis
from .numeric_gpv_ibs import as_np, numeric_gs, sample_batch


def fast_setup(n, q, m_bar, s0, rng):
    k = (q - 1).bit_length()
    w = n * k
    a_bar = rng.integers(0, q, size=(n, m_bar), dtype=np.int64)
    R = np.rint(rng.normal(0, s0, size=(m_bar, w))).astype(np.int64)
    return a_bar, R


def mod_vec(A, x, q):
    return [sum(int(a) * int(v) for a, v in zip(row, x)) % q for row in A]


def run(n, q=4294967291, s0=4, seed=0):
    rng = np.random.default_rng(seed)
    k = (q - 1).bit_length()
    w = n * k
    m_bar = w
    m = m_bar + w
    M = m + w
    t0 = time.perf_counter()
    a_bar, R = fast_setup(n, q, m_bar, s0, rng)
    public, basis = fast_root_basis(a_bar.tolist(), R.tolist(), q)
    A = [[int(x) for x in row] for row in public]
    B = as_np(basis)
    print(dict(n=n, m=m, M=M, setup_root_s=round(time.perf_counter() - t0, 2)), flush=True)

    t0 = time.perf_counter()
    star, norms = numeric_gs(B)
    width = math.sqrt(float(np.max(norms)))
    print(dict(phase="gs", s=round(time.perf_counter() - t0, 2), width=round(width, 3)), flush=True)

    H1 = rng.integers(0, q, size=(n, w), dtype=np.int64)
    particulars = np.empty((m, w), dtype=np.int64)
    from ibme.ibs.wang_pw import _gf_solve
    for j in range(w):
        target = [(-int(H1[i, j])) % q for i in range(n)]
        particulars[:, j] = _gf_solve(A, target, q)
    sigma = width * math.sqrt(m)
    t0 = time.perf_counter()
    X = sample_batch(B, particulars, sigma, rng, star, norms)
    print(dict(phase="X", s=round(time.perf_counter() - t0, 2)), flush=True)
    for j in range(0, w, max(1, w // 8)):
        target = [(-int(H1[i, j])) % q for i in range(n)]
        if mod_vec(A, X[:, j], q) != target:
            raise RuntimeError("X equation failed")

    T_id = np.zeros((M, M), dtype=np.int64)
    T_id[:m, :m] = B
    T_id[:m, m:] = X
    T_id[m:, m:] = np.eye(w, dtype=np.int64)
    F = [A[i] + [int(x) for x in H1[i]] for i in range(n)]
    t0 = time.perf_counter()
    star2, norms2 = numeric_gs(T_id)
    width2 = math.sqrt(float(np.max(norms2)))
    print(dict(phase="block_gs", s=round(time.perf_counter() - t0, 2), width=round(width2, 3)), flush=True)

    H2 = rng.integers(0, q, size=n, dtype=np.int64)
    particular = _gf_solve(F, [int(x) for x in H2], q)
    sigma_sign = 200.0 / math.sqrt(2 * math.pi)
    t0 = time.perf_counter()
    z = sample_batch(T_id, np.array(particular, dtype=np.int64).reshape(-1, 1),
                     sigma_sign, rng, star2, norms2).reshape(-1)
    print(dict(phase="sign", s=round(time.perf_counter() - t0, 2),
               norm=round(float(np.linalg.norm(z)), 2),
               eq=mod_vec(F, z, q) == [int(x) for x in H2]), flush=True)


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 16
    run(n)
