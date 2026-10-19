"""Multiprocess batched GPV for n=64+: 16 columns workers, one QR."""
import math
import multiprocessing as mp
import sys
import time

import numpy as np

from .fast_root_basis import fast_root_basis
from .numeric_gpv_ibs import as_np, numeric_gs, sample_batch

G = {}


def _worker(args):
    cols, seed = args
    rng = np.random.default_rng(seed)
    return sample_batch(G["B"], G["P"][:, cols], G["sigma"], rng, G["star"], G["norms"])


def _pivot_particulars(A, targets, q):
    from sage.all import GF, matrix, vector
    n, m = len(A), len(A[0])
    sub = matrix(GF(q), [[A[i][j] for j in range(n)] for i in range(n)])
    inv = sub.inverse()
    out = np.zeros((m, targets.shape[1]), dtype=np.int64)
    for c in range(targets.shape[1]):
        vec = inv * vector(GF(q), [int(targets[i, c]) for i in range(n)])
        for i in range(n):
            out[i, c] = int(vec[i])
    return out


def mod_vec(A, x, q):
    return [sum(int(a) * int(v) for a, v in zip(row, x)) % q for row in A]


def run(n, q=4294967291, workers=16, seed=0):
    rng = np.random.default_rng(seed)
    k = (q - 1).bit_length()
    w = n * k
    m_bar = w
    m = m_bar + w
    M = m + w
    t0 = time.perf_counter()
    a_bar = rng.integers(0, q, size=(n, m_bar), dtype=np.int64)
    R = np.rint(rng.normal(0, 4, size=(m_bar, w))).astype(np.int64)
    public, basis = fast_root_basis(a_bar.tolist(), R.tolist(), q)
    A = [[int(x) for x in row] for row in public]
    B = as_np(basis)
    print(dict(n=n, m=m, M=M, setup_root_s=round(time.perf_counter() - t0, 2)), flush=True)

    t0 = time.perf_counter()
    star, norms = numeric_gs(B)
    width = math.sqrt(float(np.max(norms)))
    print(dict(phase="gs", s=round(time.perf_counter() - t0, 2), width=round(width, 3)), flush=True)

    H1 = rng.integers(0, q, size=(n, w), dtype=np.int64)
    targets = np.array([[-int(H1[i, j]) % q for j in range(w)] for i in range(n)], dtype=np.int64)
    t0 = time.perf_counter()
    P = _pivot_particulars(A, targets, q)
    print(dict(phase="particulars", s=round(time.perf_counter() - t0, 2)), flush=True)

    G.update(B=B, star=star, norms=norms, P=P, sigma=width * math.sqrt(m))
    chunks = np.array_split(np.arange(w), workers)
    t0 = time.perf_counter()
    with mp.Pool(workers) as pool:
        parts = pool.map(_worker, [(c, seed + i) for i, c in enumerate(chunks)])
    X = np.concatenate(parts, axis=1)
    print(dict(phase="X_mp", s=round(time.perf_counter() - t0, 2)), flush=True)

    for j in range(0, w, max(1, w // 8)):
        if mod_vec(A, X[:, j], q) != [int(x) for x in targets[:, j]]:
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
    part = np.zeros(M, dtype=np.int64)
    from sage.all import GF, matrix, vector
    sub = matrix(GF(q), [[F[i][j] for j in range(n)] for i in range(n)])
    inv = sub.inverse()
    vec = inv * vector(GF(q), [int(x) for x in H2])
    for i in range(n):
        part[i] = int(vec[i])
    sigma_sign = 200.0 / math.sqrt(2 * math.pi)
    t0 = time.perf_counter()
    z = sample_batch(T_id, part.reshape(-1, 1), sigma_sign, rng, star2, norms2).reshape(-1)
    print(dict(phase="sign", s=round(time.perf_counter() - t0, 2),
               norm=round(float(np.linalg.norm(z)), 2),
               eq=mod_vec(F, z, q) == [int(x) for x in H2]), flush=True)


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 64
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 16
    run(n, workers=workers)
