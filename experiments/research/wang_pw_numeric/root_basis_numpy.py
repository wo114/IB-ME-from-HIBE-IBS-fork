"""NumPy MP12 root-basis builder for q<2^53 (q32 target).

Same formula as ibme.lattice.chkp.root_basis.private_root_basis, but dense
float64 BLAS products are exact for the q=2^32 instance because every integer
intermediate is below 2^53.  Research prototype; no security claim.
"""
import numpy as np


def gadget_basis(w, q):
    k = (q - 1).bit_length()
    gb = np.zeros((w, w), dtype=np.int64)
    for row in range(w // k):
        for j in range(k):
            idx = row * k + j
            if j < k - 1:
                gb[idx, idx] = 2
                gb[idx + 1, idx] = -1
            gb[idx, row * k + k - 1] = (int(q) >> j) if j == k - 1 else ((int(q) >> j) & 1)
    return gb


def digits_matrix(a_bar, w, q):
    n, m_bar = a_bar.shape
    k = (q - 1).bit_length()
    digits = np.zeros((w, m_bar), dtype=np.int64)
    for row in range(n):
        for j in range(k):
            digits[row * k + j, :] = (a_bar[row, :] >> j) & 1
    return digits


def root_basis_numpy(a_bar, R, q):
    a_bar = np.asarray(a_bar, dtype=np.int64)
    R = np.asarray(R, dtype=np.int64)
    n, m_bar = a_bar.shape
    w = R.shape[1]
    k = (q - 1).bit_length()
    assert w == n * k
    gb = gadget_basis(w, q).astype(np.float64)
    digits = digits_matrix(a_bar, w, q).astype(np.float64)
    trap = R.astype(np.float64)
    top_left = np.rint(trap @ gb).astype(np.int64)
    top_right = np.eye(m_bar, dtype=np.int64) - np.rint(trap @ digits).astype(np.int64)
    T = np.zeros((m_bar + w, m_bar + w), dtype=np.int64)
    T[:m_bar, :m_bar] = top_left
    T[:m_bar, m_bar:] = top_right
    T[m_bar:, :m_bar] = gb.astype(np.int64)
    T[m_bar:, m_bar:] = -digits.astype(np.int64)
    gadget = np.zeros((n, w), dtype=np.int64)
    for row in range(n):
        for j in range(k):
            gadget[row, row * k + j] = (1 << j) % q
    public = np.rint(a_bar.astype(np.float64) @ trap).astype(np.int64)
    A = np.hstack([a_bar, (gadget - public) % q])
    return A, T


if __name__ == "__main__":
    import time

    from tmp.numeric_gpv_ibs import numeric_gs

    for n in (64, 128):
        q = 4294967291
        k = (q - 1).bit_length()
        w = n * k
        rng = np.random.default_rng(0)
        a_bar = rng.integers(0, q, size=(n, w), dtype=np.int64)
        R = np.rint(rng.normal(0, 4, size=(w, w))).astype(np.int64)
        t = time.perf_counter()
        A, T = root_basis_numpy(a_bar, R, q)
        print("n", n, "build", round(time.perf_counter() - t, 2), "dim", T.shape, flush=True)
        t = time.perf_counter()
        star, norms = numeric_gs(T)
        print("n", n, "gs", round(time.perf_counter() - t, 2),
              "width", round(float(np.sqrt(norms.max())), 3), flush=True)
        # spot-check kernel membership with object arithmetic
        obj = A.astype(object)
        for j in range(0, T.shape[1], max(1, T.shape[1] // 8)):
            assert all(int(x) % q == 0 for x in (obj @ T[:, j].astype(object)))
        print("n", n, "kernel ok", flush=True)
