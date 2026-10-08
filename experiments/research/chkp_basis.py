"""CHKP T1 exact algebra, not GenBasis/RandBasis or a HIBE backend.

Source: Cash--Hofheinz--Kiltz--Peikert, fixed 36-page author version,
section 3.3, Lemma 3.2, PDF pp. 13--14. Basis vectors are COLUMNS;
basis_rows stores the rows of that integer matrix without reducing mod q.
Sage is used for exact ZZ/QQ/GF arithmetic and proven prime checks.
"""

from dataclasses import dataclass, field
from operator import index

from sage.all import GF, QQ, ZZ, matrix, vector


def _integer(value):
    if isinstance(value, bool):
        raise ValueError("boolean values are not integer matrix entries")
    try:
        return int(index(value))
    except TypeError as exc:
        raise ValueError("exact integer entries are required") from exc


def _rows(values):
    if hasattr(values, "rows") and callable(values.rows):
        values = values.rows()
    try:
        rows = tuple(tuple(_integer(x) for x in row) for row in values)
    except TypeError as exc:
        raise ValueError("expected a two-dimensional integer matrix") from exc
    if not rows or not rows[0] or any(len(row) != len(rows[0]) for row in rows):
        raise ValueError("matrix must be nonempty and rectangular")
    return rows


def _prime(q):
    q = _integer(q)
    if q < 2 or not ZZ(q).is_prime(proof=True):
        raise ValueError("this reference requires a proven prime modulus")
    return q


@dataclass(frozen=True)
class CHKPAlgebraParams:
    """T1 dimensions only; does not contain the cryptographic width conditions."""

    n: int
    m: int
    q: int
    depth: int = 2
    security_claim: str = field(default="none", init=False)

    def __post_init__(self):
        n, m, depth = _integer(self.n), _integer(self.m), _integer(self.depth)
        if n < 1 or m < n or depth != 2:
            raise ValueError("require n >= 1, m >= n, and fixed depth 2")
        object.__setattr__(self, "n", n)
        object.__setattr__(self, "m", m)
        object.__setattr__(self, "depth", depth)
        object.__setattr__(self, "q", _prime(self.q))


@dataclass(frozen=True)
class ModMatrixReference:
    rows: tuple[tuple[int, ...], ...]
    q: int

    def __post_init__(self):
        q = _prime(self.q)
        rows = _rows(self.rows)
        object.__setattr__(self, "q", q)
        object.__setattr__(self, "rows", tuple(tuple(x % q for x in row) for row in rows))

    @property
    def nrows(self):
        return len(self.rows)

    @property
    def ncols(self):
        return len(self.rows[0])

    def append(self, block):
        if not isinstance(block, ModMatrixReference):
            raise ValueError("expected a modular matrix block")
        if block.q != self.q or block.nrows != self.nrows:
            raise ValueError("appended block must have the same modulus and row count")
        return ModMatrixReference(tuple(a + b for a, b in zip(self.rows, block.rows)), self.q)


def _full_rank_field(public):
    if not isinstance(public, ModMatrixReference):
        raise ValueError("expected a modular reference matrix")
    a = matrix(GF(public.q), public.rows)
    pivots = tuple(a.pivots())
    if len(pivots) != public.nrows:
        raise ValueError("public matrix must have full row rank modulo q")
    return a, pivots


@dataclass(frozen=True)
class KernelBasis:
    """A complete integer basis certificate; no shortness or key secrecy claim."""

    public: ModMatrixReference
    basis_rows: tuple[tuple[int, ...], ...]
    security_claim: str = field(default="none", init=False)
    is_randomized: bool = field(default=False, init=False)

    def __post_init__(self):
        a, _ = _full_rank_field(self.public)
        rows = _rows(self.basis_rows)
        m = self.public.ncols
        if len(rows) != m or len(rows[0]) != m:
            raise ValueError("kernel basis must be an m by m integer matrix")
        s = matrix(ZZ, rows)
        if a * matrix(GF(self.public.q), s) != 0:
            raise ValueError("basis columns do not satisfy A S = 0 mod q")
        # For surjective A, the full kernel has index q^n in Z^m. Containment
        # alone is insufficient: a sublattice can satisfy every congruence.
        if abs(s.det()) != self.public.q**self.public.nrows:
            raise ValueError("basis determinant is not the complete kernel index q^n")
        object.__setattr__(self, "basis_rows", rows)


def _center(value, q):
    value = int(value)
    return value - q if value > q // 2 else value


def _solve_negative_block(public, block):
    a, pivots = _full_rank_field(public)
    if public.q != block.q or public.nrows != block.nrows:
        raise ValueError("extension block must share modulus and row count")
    c = a.matrix_from_columns(pivots)
    solved = -c.inverse() * matrix(GF(public.q), block.rows)
    w = [[0] * block.ncols for _ in range(public.ncols)]
    for row, coordinate in enumerate(pivots):
        for j in range(block.ncols):
            w[coordinate][j] = _center(solved[row, j], public.q)
    return w


def complete_kernel_basis(public):
    """Public algebraic completion, NOT the short/near-uniform GenBasis.

    Solve nonpivot columns with pivot variables, and give each pivot a q e_i
    basis vector. The resulting lattice has determinant q^n. Its basis is
    publicly computable and must never be treated as a cryptographic trapdoor.
    """
    a, pivots = _full_rank_field(public)
    free = tuple(i for i in range(public.ncols) if i not in pivots)
    m, n, q = public.ncols, public.nrows, public.q
    s = [[0] * m for _ in range(m)]
    for j, coordinate in enumerate(pivots):
        s[coordinate][j] = q
    if free:
        solved = -a.matrix_from_columns(pivots).inverse() * a.matrix_from_columns(free)
        for j, coordinate in enumerate(free):
            s[coordinate][n + j] = 1
            for i, pivot in enumerate(pivots):
                s[pivot][n + j] = _center(solved[i, j], q)
    return KernelBasis(public, s)


def ext_basis(parent, block):
    """CHKP Lemma 3.2: S' = [[S,W],[0,I]], with A W = -block mod q.

    This preserves the parent's full integer basis as a visible subblock.
    RandBasis is REQUIRED before this could become a delegated secret key.
    """
    if not isinstance(parent, KernelBasis) or not isinstance(block, ModMatrixReference):
        raise ValueError("ExtBasis requires a validated basis and a modular block")
    public = parent.public.append(block)
    w = _solve_negative_block(parent.public, block)
    m, k = parent.public.ncols, block.ncols
    rows = [list(parent.basis_rows[i]) + w[i] for i in range(m)]
    rows += [[0] * m + [int(i == j) for j in range(k)] for i in range(k)]
    return KernelBasis(public, rows)


def gram_schmidt_squared_lengths(basis_rows):
    """Exact rational GS lengths for COLUMN basis vectors (no float rounding)."""
    rows = _rows(basis_rows)
    if len(rows) != len(rows[0]):
        raise ValueError("Gram-Schmidt input must be a square full-rank basis")
    s = matrix(QQ, rows)
    orthogonal, lengths = [], []
    for column in s.columns():
        current = vector(QQ, column)
        for previous, squared in zip(orthogonal, lengths):
            current -= (current.dot_product(previous) / squared) * previous
        squared = current.dot_product(current)
        if squared == 0:
            raise ValueError("basis has deficient integer rank")
        orthogonal.append(current)
        lengths.append(squared)
    return tuple(lengths)


def two_level_matrices(params, root_rows, parent_rows, child_rows):
    """Matrix shape/order only; the blocks are supplied, not simulated oracles."""
    if not isinstance(params, CHKPAlgebraParams):
        raise ValueError("expected CHKPAlgebraParams")
    blocks = tuple(ModMatrixReference(rows, params.q)
                   for rows in (root_rows, parent_rows, child_rows))
    if any((block.nrows, block.ncols) != (params.n, params.m) for block in blocks):
        raise ValueError("root and both identity blocks must have shape n by m")
    root, parent_block, child_block = blocks
    parent = root.append(parent_block)
    return root, parent, parent.append(child_block)
