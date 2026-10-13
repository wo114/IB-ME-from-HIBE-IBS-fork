"""Exact, deterministic ToBasis: full lattice and ordered GS bounds ONLY.

Peikert, pargauss author version 2011-04-13, Lemma 5.4 (PDF 16).
The proof's claim about singular values of triangular integer matrices is
false; this implementation does NOT promise spectral/ordinary norm bounds.
Input and output vectors are COLUMNS. WSL ~/miniconda3/envs/sage required.
"""

from itertools import islice

from sage.all import QQ, ZZ, matrix

from .basis import KernelBasis


MAX_DIMENSION = 192
EXTENDED_MAX_DIMENSION = 512
MAX_ENTRY_BITS = 8192


def _dimension_limit(value):
    if type(value) is not int or not 1 <= value <= EXTENDED_MAX_DIMENSION:
        raise ValueError("explicit ToBasis dimension budget must be in 1..512")
    return value


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


def canonical_basis(basis, *, max_dimension=MAX_DIMENSION):
    """Canonical COLUMN HNF of the complete lattice, never of sampled S.

Sage HNF acts on rows. Transposing both before and after is essential.
The result depends on the lattice, not on the secret basis used to sample.
"""
    if not isinstance(basis, KernelBasis):
        raise ValueError("need a validated complete KernelBasis")
    d = basis.public.ncols
    if not 1 <= d <= _dimension_limit(max_dimension):
        raise ValueError("basis exceeds the research dimension resource limit")
    b = _checked_square(basis.basis_rows, d)
    h = b.transpose().hermite_form().transpose()
    return KernelBasis(basis.public, h)


def to_basis(vectors_rows, basis, *, max_dimension=MAX_DIMENSION):
    """Complete a full-rank set S in Lambda using canonical B for Lambda.

Compute Z=B^-1 S over QQ and REQUIRE integral coordinates. Row HNF gives
R=V Z with V unimodular and R upper triangular, so U=V^-1 and T=B U.
Then S=T R, L(T)=L(B), and tilde(s_i)=r_ii tilde(t_i).
As each r_ii is a nonzero integer, ordered GS lengths cannot increase.
No randomness, LLL approximation, mod-q basis reduction, or retry occurs.
"""
    canonical = canonical_basis(basis, max_dimension=max_dimension)
    d = canonical.public.ncols
    s = _checked_square(vectors_rows, d)
    b = matrix(ZZ, canonical.basis_rows)
    coordinates = matrix(QQ, b).solve_right(matrix(QQ, s))
    if any(x.denominator() != 1 for x in coordinates.list()):
        raise ValueError("sampled vectors are not in the complete input lattice")
    z = matrix(ZZ, coordinates)
    if any(abs(int(x)).bit_length() > MAX_ENTRY_BITS for x in z.list()):
        raise ValueError("integer coordinates exceed the entry bit budget")
    r, v = z.hermite_form(transformation=True)
    if (v * z != r
            or any(r[i, j] != 0 for i in range(d) for j in range(i))):
        raise ArithmeticError("HNF transformation failed its exact contract")
    if any(r[i, i] == 0 for i in range(d)):
        raise ValueError("sampled vectors must have full integer rank")
    # T R = S determines T uniquely. Solve one column at a time using the
    # exact upper-triangular R instead of inverting the generally large V.
    # This gives precisely B*V^-1, not an alternative short basis.
    t = matrix(ZZ, d, d)
    for j in range(d):
        numerator = s.column(j)
        for i in range(j):
            if r[i, j]:
                numerator -= r[i, j] * t.column(i)
        diagonal = r[j, j]
        if any(entry % diagonal for entry in numerator):
            raise ArithmeticError("ToBasis triangular solution is not integral")
        t.set_column(j, [entry // diagonal for entry in numerator])
    if t * r != s:
        raise ArithmeticError("ToBasis factorization check failed")
    # Exact factorization certificate for the ordered GS postcondition:
    # S=T*R, upper-triangular R, and nonzero integer r_ii imply
    # GS(S)_i=r_ii*GS(T)_i and |r_ii|>=1. Therefore no GS length increases.
    # Computing both rational GS decompositions repeats this exact consequence
    # and is especially expensive for the large integer HNF transformations.
    # Small-matrix tests independently verify both GS decompositions and the
    # old B*V^-1 output. Complete-lattice validation is retained below.
    # The final exact product certificate also verifies HNF unimodularity:
    # S=B*Z, V*Z=R, and |det(B)|=q^n give
    # |det(V)|=|prod diag(R)|*q^n/|det(S)|=1. Computing det(V) separately
    # can dominate the whole sampler when HNF coefficients are very large.
    # Neither this certificate nor construction below trusts Sage's claimed
    # transformation: both matrix identities and the determinant ratio run.
    return KernelBasis.from_upper_triangular_product(canonical.public, t, r, s)
