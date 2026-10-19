"""Width-only scaling using numpy root basis and QR mode='r'."""
import sys
import time

import numpy as np

from experiments.research.wang_pw_numeric.root_basis_numpy import root_basis_numpy


def main(n, q=4294967291, s0=4):
    k = (q - 1).bit_length()
    w = n * k
    rng = np.random.default_rng(0)
    a_bar = rng.integers(0, q, size=(n, w), dtype=np.int64)
    R = np.rint(rng.normal(0, s0, size=(w, w))).astype(np.int64)
    t = time.perf_counter()
    A, T = root_basis_numpy(a_bar, R, q)
    print("build", round(time.perf_counter() - t, 2), "dim", T.shape, flush=True)
    del a_bar, R
    t = time.perf_counter()
    Rq = np.linalg.qr(T.astype(np.float64), mode="r")
    norms = np.diag(Rq) ** 2
    print("qr", round(time.perf_counter() - t, 2), "width", round(float(np.sqrt(norms.max())), 3), flush=True)
    obj = A.astype(object)
    for j in range(0, T.shape[1], max(1, T.shape[1] // 8)):
        assert all(int(x) % q == 0 for x in (obj @ T[:, j].astype(object)))
    print("kernel ok", flush=True)


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 256,
         s0=float(sys.argv[2]) if len(sys.argv) > 2 else 4)
