"""Exact, deterministic ToBasis: full lattice and ordered GS bounds ONLY.

Peikert, pargauss author version 2011-04-13, Lemma 5.4 (PDF 16).
The proof's claim about singular values of triangular integer matrices is
false; this implementation does NOT promise spectral/ordinary norm bounds.
Input and output vectors are COLUMNS. WSL ~/miniconda3/envs/sage required.
"""

from itertools import islice

from sage.all import QQ, ZZ, matrix

from .chkp_basis import KernelBasis, gram_schmidt_squared_lengths


MAX_DIMENSION = 192
MAX_ENTRY_BITS = 8192


def _checked_square(rows, dimension):
    if hasattr(rows, "rows") and callable(rows.rows):
        if rows.nrows() != dimension or rows.ncols() != dimension:
            raise ValueError("vector matrix must have the full lattice dimension")
        rows = rows.rows()
    try:
        outer = tuple(islice(iter(rows), dimension+1))
        if len(outer) != dimension:
            raise ValueError("vector matrix must have the full lattice dimension")
        rows = tuple(tuple(islice(iter(row), dimension+1)) for row in outer)
    except TypeError as exc:
        raise ValueError("expected a square integer column-vector matrix") from exc
    if len(rows) != dimension or any(len(row) != dimension for row in rows):
        raise ValueError("vector matrix must have the full lattice dimension")
    checked = []
    for row in rows:
        out = []
        for value in row:
            if isinstance(value, bool) or not isinstance(value, (int, type(ZZ(0)))):
                raise ValueError("vector matrix entries must be exact integers")
            value = int(value)
            if abs(value).bit_length() > MAX_ENTRY_BITS:
                raise ValueError("integer matrix exceeds the entry bit budget")
            out.append(value)
        checked.append(out)
    return matrix(ZZ, checked)


def canonical_basis(basis):
    """Canonical COLUMN HNF of the complete lattice, never of sampled S.

Sage HNF acts on rows. Transposing both before and after is essential.
The result depends on the lattice, not on the secret basis used to sample.
"""
    if not isinstance(basis, KernelBasis):
        raise ValueError("need a validated complete KernelBasis")
    d = basis.public.ncols
    if not 1 <= d <= MAX_DIMENSION:
        raise ValueError("basis exceeds the research dimension resource limit")
    b = _checked_square(basis.basis_rows, d)
    h = b.transpose().hermite_form().transpose()
    return KernelBasis(basis.public, h)


def to_basis(vectors_rows, basis):
    """Complete a full-rank set S in Lambda using canonical B for Lambda.

Compute Z=B^-1 S over QQ and REQUIRE integral coordinates. Row HNF gives
R=V Z with V unimodular and R upper triangular, so U=V^-1 and T=B U.
Then S=T R, L(T)=L(B), and tilde(s_i)=r_ii tilde(t_i).
As each r_ii is a nonzero integer, ordered GS lengths cannot increase.
No randomness, LLL approximation, mod-q basis reduction, or retry occurs.
"""
    canonical = canonical_basis(basis)
    d = canonical.public.ncols
    s = _checked_square(vectors_rows, d)
    if s.det() == 0:
        raise ValueError("sampled vectors must have full integer rank")
    b = matrix(ZZ, canonical.basis_rows)
    coordinates = matrix(QQ, b).solve_right(matrix(QQ, s))
    if any(x.denominator() != 1 for x in coordinates.list()):
        raise ValueError("sampled vectors are not in the complete input lattice")
    z = matrix(ZZ, coordinates)
    if any(abs(int(x)).bit_length() > MAX_ENTRY_BITS for x in z.list()):
        raise ValueError("integer coordinates exceed the entry bit budget")
    r, v = z.hermite_form(transformation=True)
    if (v * z != r or abs(v.det()) != 1
            or any(r[i, j] != 0 for i in range(d) for j in range(i))):
        raise ArithmeticError("HNF transformation failed its exact contract")
    if any(r[i, i] == 0 for i in range(d)):
        raise ArithmeticError("HNF unexpectedly lost full rank")
    u = matrix(ZZ, v.inverse())
    t = b * u
    if t * r != s:
        raise ArithmeticError("ToBasis factorization check failed")
    # Runtime verification is an implementation safeguard, not the proof.
    old = gram_schmidt_squared_lengths(s)
    new = gram_schmidt_squared_lengths(t)
    if any(new[i] * r[i, i] ** 2 != old[i] or new[i] > old[i]
           for i in range(d)):
        raise ArithmeticError("ordered Gram-Schmidt postcondition failed")
    return KernelBasis(canonical.public, t)
