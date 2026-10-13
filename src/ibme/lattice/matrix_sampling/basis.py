"""Single deterministic full-lattice completion engine with explicit limits.

Column HNF of the full lattice, integral coordinates, a unimodular HNF
transformation, then T*R=S and exact ordered Gram-Schmidt postconditions.
Only GS norms are claimed; spectral/ordinary norms are not. No entropy,
randomized basis substitute, lattice truncation or security admission.
"""

from itertools import islice

from sage.all import QQ, ZZ, matrix, identity_matrix

from experiments.research.chkp_basis import KernelBasis, gram_schmidt_squared_lengths


from dataclasses import dataclass
from .scalar import exact_integer


@dataclass(frozen=True)
class MatrixBasisLimits:
    max_dimension: int = 1536
    max_entry_bits: int = 65536
    max_transform_content_bytes: int = 2**30

    def __post_init__(self):
        for name, high in (("max_dimension", 1536), ("max_entry_bits", 65536),
                           ("max_transform_content_bytes", 2**40)):
            object.__setattr__(self, name, exact_integer(getattr(self, name), name, minimum=1, maximum=high))


MATRIX_BASIS_LIMITS = MatrixBasisLimits()
LEGACY_BASIS_LIMITS = MatrixBasisLimits(192, 8192, 2**40)


def _checked_square(rows, dimension, *, limits=MATRIX_BASIS_LIMITS):
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
            if abs(value).bit_length() > limits.max_entry_bits:
                raise ValueError("integer matrix exceeds the entry bit budget")
            out.append(value)
        checked.append(out)
    return matrix(ZZ, checked)


def canonical_basis(basis, *, limits=MATRIX_BASIS_LIMITS):
    """Canonical COLUMN HNF of the complete lattice, never of sampled S.

Sage HNF acts on rows. Transposing both before and after is essential.
The result depends on the lattice, not on the secret basis used to sample.
"""
    if not isinstance(basis, KernelBasis):
        raise ValueError("need a validated complete KernelBasis")
    d = basis.public.ncols
    if not isinstance(limits, MatrixBasisLimits):
        raise ValueError("explicit MatrixBasisLimits required")
    if not 1 <= d <= limits.max_dimension:
        raise ValueError("basis exceeds the research dimension resource limit")
    b = _checked_square(basis.basis_rows, d, limits=limits)
    h = b.transpose().hermite_form().transpose()
    return KernelBasis(basis.public, h)


def to_basis(vectors_rows, basis, *, limits=MATRIX_BASIS_LIMITS):
    """Complete a full-rank set S in Lambda using canonical B for Lambda.

Compute Z=B^-1 S over QQ and REQUIRE integral coordinates. Row HNF gives
R=V Z with V unimodular and R upper triangular, so U=V^-1 and T=B U.
Then S=T R, L(T)=L(B), and tilde(s_i)=r_ii tilde(t_i).
As each r_ii is a nonzero integer, ordered GS lengths cannot increase.
No randomness, LLL approximation, mod-q basis reduction, or retry occurs.
"""
    canonical = canonical_basis(basis, limits=limits)
    d = canonical.public.ncols
    s = _checked_square(vectors_rows, d, limits=limits)
    if s.det() == 0:
        raise ValueError("sampled vectors must have full integer rank")
    b = matrix(ZZ, canonical.basis_rows)
    coordinates = matrix(QQ, b).solve_right(matrix(QQ, s))
    if any(x.denominator() != 1 for x in coordinates.list()):
        raise ValueError("sampled vectors are not in the complete input lattice")
    z = matrix(ZZ, coordinates)
    if any(abs(int(x)).bit_length() > limits.max_entry_bits for x in z.list()):
        raise ValueError("integer coordinates exceed the entry bit budget")
    # A declared admission estimate before constructing Hermite transforms.
    # It does not certify the library's actual workspace or process RSS.
    # Runtime checks below bound returned matrix content on the wide profile.
    entry_bits = max(abs(int(x)).bit_length() for x in z.list())
    admit_transform_content(d, entry_bits, limits=limits)
    if limits != LEGACY_BASIS_LIMITS:
        # Row HNF gives the same unique upper triangular R as R=V*Z,
        # without requesting the often enormous V. U=Z*R^-1 equals V^-1.
        # This keeps the exact same output T, using a triangular solve.
        r = z.hermite_form()
        if any(r[i,j] != 0 for i in range(d) for j in range(i)) or any(r[i,i] == 0 for i in range(d)):
            raise ArithmeticError("HNF unexpectedly lost its triangular full-rank form")
        rational_u = matrix(QQ, r).transpose().solve_right(matrix(QQ, z).transpose()).transpose()
        if any(x.denominator() != 1 for x in rational_u.list()):
            raise ArithmeticError("ToBasis transformation is not integral")
        u = matrix(ZZ, rational_u)
        if u*r != z:
            raise ArithmeticError("ToBasis integer factorization failed")
        t = b*u
        if t*r != s or any(abs(int(x)).bit_length() > limits.max_entry_bits for x in t.list()):
            raise ValueError("completed basis factorization or entry bit budget failed")
        content = sum(max(1,(abs(int(x)).bit_length()+7)//8) for item in (z,r,u,t) for x in item.list())
        if content > limits.max_transform_content_bytes:
            raise ValueError("returned exact transform content exceeds the resource budget")
        result = KernelBasis(canonical.public,t)
        # T*R=S, integral triangular R with |r_ii|>=1 proves ordered GS
        # quality exactly. Avoid forming secret rational GSO a second time.
        return result
    r, v = z.hermite_form(transformation=True)
    if (v * z != r or any(r[i, j] != 0 for i in range(d) for j in range(i))):
        raise ArithmeticError("HNF transformation failed its exact contract")
    if any(r[i, i] == 0 for i in range(d)):
        raise ArithmeticError("HNF unexpectedly lost full rank")
    inverse = v.inverse()
    if any(x.denominator() != 1 for x in inverse.list()):
        raise ArithmeticError("HNF transformation inverse is not integral")
    u = matrix(ZZ, inverse)
    if v*u != identity_matrix(ZZ, d) or u*v != identity_matrix(ZZ, d):
        raise ArithmeticError("HNF transformation is not exactly unimodular")
    t = b * u
    if limits != LEGACY_BASIS_LIMITS and any(abs(int(x)).bit_length() > limits.max_entry_bits for x in t.list()):
        raise ValueError("completed basis exceeds the entry bit budget")
    if limits != LEGACY_BASIS_LIMITS:
        content = sum(max(1, (abs(int(x)).bit_length()+7)//8)
                      for item in (z, r, v, u, t) for x in item.list())
        if content > limits.max_transform_content_bytes:
            raise ValueError("returned exact transform content exceeds the resource budget")
    if t * r != s:
        raise ArithmeticError("ToBasis factorization check failed")
    # Runtime verification is an implementation safeguard, not the proof.
    old = gram_schmidt_squared_lengths(s)
    new = gram_schmidt_squared_lengths(t)
    if any(new[i] * r[i, i] ** 2 != old[i] or new[i] > old[i]
           for i in range(d)):
        raise ArithmeticError("ordered Gram-Schmidt postcondition failed")
    return KernelBasis(canonical.public, t)


def admit_transform_content(dimension, coordinate_bits, *, limits=MATRIX_BASIS_LIMITS):
    """Declared Hadamard/cofactor workspace estimate, not a proven RSS bound.

    HNF elementary transforms can be large. An overestimate may reject an
    input whose actual library workspace is smaller. Nor does passing this
    estimate certify the library allocation. Rejection is a resource gate,
    never a mathematical impossibility or a reason to retry a sample.
    """
    if not isinstance(limits, MatrixBasisLimits):
        raise ValueError("explicit MatrixBasisLimits required")
    d = exact_integer(dimension, "dimension", minimum=1, maximum=limits.max_dimension)
    bits = exact_integer(coordinate_bits, "coordinate_bits", minimum=0, maximum=limits.max_entry_bits)
    transform_bits = max(1, d * (bits + (d-1).bit_length() + 4))
    if limits == LEGACY_BASIS_LIMITS:
        content = 4 * d*d * ((transform_bits+7)//8)
    else:
        # Forecast for the triangular-solve implementation, explicitly not
        # a worst-case HNF/allocator bound; real returned content is checked.
        content = 4*d*d*((bits+(d-1).bit_length()+11)//8) + 2*d*((transform_bits+7)//8)
    if content > limits.max_transform_content_bytes:
        raise ValueError("HNF transform content estimate exceeds the explicit resource budget")
    return content


def matrix_checked_lll(basis, gs_upper, *, limits=MATRIX_BASIS_LIMITS):
    """Fixed delta=.75 proposal, then exact full-lattice/GS/size/Lovasz tests.

    Exact column size reduction preserves every GS vector. The original
    eta=.501 permits a <=.002 adjacent-mu-square drop, so the verified .74
    Lovasz margin is below .75-.002. This is an implementation normalizer,
    not an LWE/security threshold or a replacement for GPV width checks.
    """
    from .gpv import _gs_geometry
    from .scalar import exact_rational
    if not isinstance(basis, KernelBasis):
        raise ValueError("complete KernelBasis required")
    original = _checked_square(basis.basis_rows, basis.public.ncols, limits=limits)
    upper = exact_rational(gs_upper, "public GS upper", max_bits=limits.max_entry_bits)
    if upper <= 0:
        raise ValueError("positive GS bound required")
    rows, transform = original.transpose().LLL(delta=QQ(3)/4, eta=QQ(501)/1000, transformation=True)
    reduced, column_transform = rows.transpose(), transform.transpose()
    _, lengths, weights = _gs_geometry(tuple(tuple(int(x) for x in row) for row in reduced.rows()),
        limits.max_entry_bits, limits.max_transform_content_bytes)
    for j in range(reduced.ncols()):
        for i in reversed(range(j)):
            mu = sum((x*w for x,w in zip(reduced.column(j),weights[i])), QQ(0))
            nearest = ZZ((mu+QQ(1)/2).floor())
            if nearest:
                reduced.add_multiple_of_column(j,i,-nearest)
                column_transform.add_multiple_of_column(j,i,-nearest)
    if original*column_transform != reduced:
        raise ArithmeticError("LLL exact integer transformation failed")
    result = KernelBasis(basis.public,reduced)
    # Both complete bases have determinant q^n; together with the exact
    # transform this verifies unimodularity without a giant det(transform).
    if max(lengths) > upper:
        raise ArithmeticError("LLL public GS bound failed")
    for j in range(reduced.ncols()):
        for i in range(j):
            mu = sum((x*w for x,w in zip(reduced.column(j),weights[i])), QQ(0))
            if abs(mu) > QQ(1)/2:
                raise ArithmeticError("LLL exact size reduction failed")
            if i == j-1 and lengths[j]+mu**2*lengths[i] < QQ(74)/100*lengths[i]:
                raise ArithmeticError("LLL exact Lovasz condition failed")
    return result
