"""n=512/q32 algebraic probe: numpy root + block delegation + numeric GPV.

sigma_sign is set to the measured block GS width, so the sampler width is at
the basis-quality scale; beta = sigma_sign * sqrt(M). H1/H2 are random test
targets, not identity/message hashes. Only the response equation is tested;
there is no full IBS verify or public norm acceptance here. Research only.
"""
import math
import sys
import time

import numpy as np

from .gpv_kernel import sample_x_c
from .numeric_gpv_ibs import numeric_gs, sample_batch
from .numeric_gpv_mp import mod_vec
from .root_basis_numpy import root_basis_numpy


def gadget_particulars(R, targets, q):
    """A [R;I] = G, so P=[R D;D] solves A P = G D = targets."""
    n, w = targets.shape
    m_bar = R.shape[0]
    k = w // n
    D = np.zeros((w, w), dtype=np.int8)
    for i in range(n):
        for j in range(k):
            D[i * k + j, :] = ((targets[i, :] >> j) & 1).astype(np.int8)
    RD = np.rint(R.astype(np.float64) @ D.astype(np.float64)).astype(np.int64)
    return np.vstack([RD, D.astype(np.int64)])


def run(n, q=4294967291, workers=16, sigma_factor=1.0, s0=4.0, seed=0):
    rng = np.random.default_rng(seed)
    k = (q - 1).bit_length()
    w = n * k
    m = 2 * w
    M = 3 * w
    t0 = time.perf_counter()
    a_bar = rng.integers(0, q, size=(n, w), dtype=np.int64)
    R = np.rint(rng.normal(0, s0, size=(w, w))).astype(np.int64)
    A, B = root_basis_numpy(a_bar, R, q)
    print(dict(n=n, m=m, M=M, setup_root_s=round(time.perf_counter() - t0, 2)), flush=True)
    del a_bar

    t0 = time.perf_counter()
    star, norms = numeric_gs(B)
    width = math.sqrt(float(np.max(norms)))
    print(dict(phase="gs", s=round(time.perf_counter() - t0, 2), width=round(width, 3)), flush=True)

    H1 = rng.integers(0, q, size=(n, w), dtype=np.int64)
    targets = np.array([[-int(H1[i, j]) % q for j in range(w)] for i in range(n)], dtype=np.int64)
    t0 = time.perf_counter()
    P = gadget_particulars(R, targets, q)
    print(dict(phase="particulars", s=round(time.perf_counter() - t0, 2)), flush=True)

    t0 = time.perf_counter()
    X = sample_x_c(B, star, norms, P, width * math.sqrt(m), threads=workers)
    print(dict(phase="X_c", s=round(time.perf_counter() - t0, 2)), flush=True)
    del P, star, norms
    for j in range(0, w, max(1, w // 8)):
        if mod_vec(A.tolist(), X[:, j].tolist(), q) != [int(x) for x in targets[:, j]]:
            raise RuntimeError("X equation failed")

    T_id = np.zeros((M, M), dtype=np.int64)
    T_id[:m, :m] = B
    T_id[:m, m:] = X
    T_id[m:, m:] = np.eye(w, dtype=np.int64)
    del B, X
    F = [A[i].tolist() + [int(x) for x in H1[i]] for i in range(n)]
    t0 = time.perf_counter()
    star2, norms2 = numeric_gs(T_id)
    width2 = math.sqrt(float(np.max(norms2)))
    print(dict(phase="block_gs", s=round(time.perf_counter() - t0, 2), width=round(width2, 3)), flush=True)

    H2 = rng.integers(0, q, size=n, dtype=np.int64)
    # Short particular: F=[A|H1] and A[R;I]=G, so [R d; d; 0] maps to G d = H2.
    d = np.zeros(w, dtype=np.int64)
    for i in range(n):
        for j in range(k):
            d[i * k + j] = (int(H2[i]) >> j) & 1
    part = np.zeros(M, dtype=np.int64)
    part[:m] = np.concatenate([R @ d, d])
    if mod_vec(F, part.tolist(), q) != [int(x) for x in H2]:
        raise RuntimeError("short particular equation failed")
    sigma_sign = sigma_factor * width2
    beta = sigma_sign * math.sqrt(M)
    t0 = time.perf_counter()
    z = sample_batch(T_id, part.reshape(-1, 1), sigma_sign, rng, star2, norms2).reshape(-1)
    print(dict(phase="sign", s=round(time.perf_counter() - t0, 2),
               sigma_sign=round(sigma_sign, 3), beta_log2=round(math.log2(beta), 3),
               norm=round(float(np.linalg.norm(z)), 2),
               eq=mod_vec(F, z.tolist(), q) == [int(x) for x in H2]), flush=True)


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 16
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 16
    s0 = float(sys.argv[3]) if len(sys.argv) > 3 else 4.0
    run(n, workers=workers, s0=s0)
