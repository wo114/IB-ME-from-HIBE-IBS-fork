"""Deterministic MP12 binary-gadget full-basis conversion in Sage.

For A=[Abar | G-Abar R], T=[[I,R],[0,I]] gives A*T=[Abar,G].
Start with the block gadget kernel columns, followed by [I;-bits(Abar)].
Their determinant is q^n, and their ordered GS lengths are at most sqrt(5).
Multiplication by T gives the MP12 Lemma 5.3 bound used by root_generation.
No native RNG, public fixture, resampling, or secret diagnostics are used.
"""

from sage.all import ZZ, matrix, identity_matrix, block_matrix
from .basis import KernelBasis, ModMatrixReference


def private_root_basis(a_bar, r, q):
    ab, trap = matrix(ZZ, a_bar), matrix(ZZ, r)
    n, mbar = ab.nrows(), ab.ncols()
    k = (int(q) - 1).bit_length()
    w = n * k
    if trap.nrows() != mbar or trap.ncols() != w:
        raise ValueError("private root trapdoor shape mismatch")
    g = matrix(ZZ, n, w)
    gadget_basis = matrix(ZZ, w, w)
    for row in range(n):
        for j in range(k):
            g[row, row * k + j] = 2**j
            if j < k - 1:
                gadget_basis[row*k+j, row*k+j] = 2
                gadget_basis[row*k+j+1, row*k+j] = -1
            gadget_basis[row*k+j, row*k+k-1] = int(q) >> j if j == k-1 else (int(q) >> j) & 1
    digits = matrix(ZZ, w, mbar)
    for row in range(n):
        for column in range(mbar):
            for j in range(k):
                digits[row*k+j, column] = (int(ab[row, column]) >> j) & 1
    # Gadget columns first is essential for the public GS bound.
    basis = block_matrix(ZZ, [[trap * gadget_basis, identity_matrix(ZZ, mbar) - trap * digits],
                              [gadget_basis, -digits]])
    public = ab.augment(g - ab * trap)
    return KernelBasis(ModMatrixReference(tuple(tuple(int(x % q) for x in row)
                      for row in public.rows()), int(q)), basis)
