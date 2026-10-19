"""Fast MP12 root-basis formula without the exact determinant validator."""
import time

from sage.all import ZZ, block_matrix, identity_matrix, matrix


def fast_root_basis(a_bar, r, q):
    ab, trap = matrix(ZZ, a_bar), matrix(ZZ, r)
    n, mbar = ab.nrows(), ab.ncols()
    k = (int(q) - 1).bit_length()
    w = n * k
    g = matrix(ZZ, n, w)
    gadget_basis = matrix(ZZ, w, w)
    for row in range(n):
        for j in range(k):
            g[row, row * k + j] = 2**j
            if j < k - 1:
                gadget_basis[row * k + j, row * k + j] = 2
                gadget_basis[row * k + j + 1, row * k + j] = -1
            gadget_basis[row * k + j, row * k + k - 1] = (int(q) >> j) if j == k - 1 else ((int(q) >> j) & 1)
    digits = matrix(ZZ, w, mbar)
    for row in range(n):
        for column in range(mbar):
            for j in range(k):
                digits[row * k + j, column] = (int(ab[row, column]) >> j) & 1
    basis = block_matrix(ZZ, [[trap * gadget_basis, identity_matrix(ZZ, mbar) - trap * digits],
                              [gadget_basis, -digits]])
    public = ab.augment(g - ab * trap)
    return public, basis


def main():
    import ibme.ibs.wang_pw as W

    class FastParams(W.WangPWParams):
        def __post_init__(self):
            pass

    for n, q in ((8, 4294967291),):
        m_bar = n * ((q - 1).bit_length())
        p = FastParams(n=n, q=q, m_bar=m_bar)
        pk, msk = W.setup(p)
        t0 = time.perf_counter()
        public, basis = fast_root_basis(msk.a_bar(), msk.r_a(), p.q)
        build = time.perf_counter() - t0
        t0 = time.perf_counter()
        width = W.basis_width([list(map(int, col)) for col in basis.columns()])
        width_t = time.perf_counter() - t0
        print(dict(n=n, m=len(public[0]), build_s=round(build, 2),
                   width=round(width, 3), width_s=round(width_t, 2)), flush=True)


if __name__ == "__main__":
    main()
