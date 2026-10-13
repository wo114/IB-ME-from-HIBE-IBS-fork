"""Single deterministic full-lattice completion engine with explicit limits.

Column HNF of the full lattice, integral coordinates, a unimodular HNF
transformation, then T*R=S and exact ordered Gram-Schmidt postconditions.
Only GS norms are claimed; spectral/ordinary norms are not. No entropy,
randomized basis substitute, lattice truncation or security admission.
"""

from itertools import islice

from sage.all import GF, QQ, ZZ, matrix, identity_matrix, vector

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


def _integral_lower_solve(lower,right):
    """Exact B*Z=S with canonical lower B; reject any nonintegral coordinate."""
    d=lower.nrows()
    z=matrix(ZZ,d,right.ncols())
    for i in range(d):
        diagonal=lower[i,i]
        if diagonal<=0:raise ValueError("positive lower diagonal required")
        numerator=right.row(i)
        if any(lower[i,k] for k in range(i)):
            numerator=numerator-lower.row(i)*z
        if any(value%diagonal for value in numerator):
            raise ValueError("sampled vectors are not in the complete input lattice")
        z.set_row(i,tuple(value//diagonal for value in numerator))
    if lower*z!=right:raise ArithmeticError("exact lower factorization failed")
    return z


def _integral_right_upper_solve(right,upper):
    """Exact U*R=Z, exploiting the already checked upper row HNF."""
    d=upper.nrows()
    u=matrix(ZZ,right.nrows(),d)
    for j in range(d):
        diagonal=upper[j,j]
        if diagonal<=0:raise ValueError("positive upper diagonal required")
        numerator=right.column(j)
        if any(upper[k,j] for k in range(j)):
            numerator=numerator-u*upper.column(j)
        if any(value%diagonal for value in numerator):
            raise ArithmeticError("ToBasis transformation is not integral")
        u.set_column(j,tuple(value//diagonal for value in numerator))
    if u*upper!=right:raise ArithmeticError("exact upper factorization failed")
    return u


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
    if limits != LEGACY_BASIS_LIMITS:
        # The canonical lattice depends only on its public mod-q row space.
        # Rightmost field pivots yield its LOWER column HNF directly: reverse
        # coordinates, solve pivot variables, choose canonical [0,q) lifts,
        # then reverse rows and columns back. No private-basis HNF workspace.
        # This public algebraic anchor is NOT a short/cryptographic trapdoor;
        # ToBasis must still complete the actual sampled/transformed vectors.
        a=matrix(GF(basis.public.q),tuple(row[::-1] for row in basis.public.rows))
        pivots=tuple(a.pivots())
        if len(pivots)!=basis.public.nrows:
            raise ValueError("public kernel matrix lost full rank")
        free=tuple(i for i in range(d) if i not in pivots)
        upper=matrix(ZZ,d,d)
        for coordinate in pivots:upper[coordinate,coordinate]=basis.public.q
        for coordinate in free:upper[coordinate,coordinate]=1
        if free:
            solved=-a.matrix_from_columns(pivots).inverse()*a.matrix_from_columns(free)
            for j,coordinate in enumerate(free):
                for i,pivot in enumerate(pivots):upper[pivot,coordinate]=int(solved[i,j])
        h=matrix(ZZ,tuple(tuple(row)[::-1] for row in upper.rows()[::-1]))
        # Full-kernel containment/index plus these canonical lower-HNF
        # inequalities uniquely determine the same B as the general HNF.
        if (any(h[i,j]!=0 for i in range(d) for j in range(i+1,d)) or
                any(h[i,i] not in (1,basis.public.q) for i in range(d)) or
                any(not 0<=h[i,j]<h[i,i] for i in range(d) for j in range(i))):
            raise ArithmeticError("direct public canonical column HNF failed")
        return KernelBasis(basis.public,h)
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
    if limits != LEGACY_BASIS_LIMITS:
        z=_integral_lower_solve(b,s)
    else:
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
        # Predeclared exact p-adic engine with proof enabled. The default
        # FLINT recursive HNF exhausted the observer budget at dimension1280.
        # This computes the same unique row HNF, never a sampled substitute,
        # stabilized determinant heuristic or retry of private randomness.
        r = z.hermite_form(algorithm="padic",proof=True)
        if any(r[i,j] != 0 for i in range(d) for j in range(i)) or any(r[i,i] == 0 for i in range(d)):
            raise ArithmeticError("HNF unexpectedly lost its triangular full-rank form")
        u = _integral_right_upper_solve(z,r)
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
    # Same exact projections, evaluated by native rational vector arithmetic.
    # GS vectors do not change under upper triangular column size reduction.
    # Cache current columns and fixed weights instead of a Python per-entry
    # rational sum for every pair. This changes no nearest-integer decision.
    weight_vectors = tuple(vector(QQ,row) for row in weights)
    columns = list(vector(QQ,column) for column in reduced.columns())
    for j in range(reduced.ncols()):
        for i in reversed(range(j)):
            mu = columns[j].dot_product(weight_vectors[i])
            nearest = ZZ((mu+QQ(1)/2).floor())
            if nearest:
                reduced.add_multiple_of_column(j,i,-nearest)
                column_transform.add_multiple_of_column(j,i,-nearest)
                columns[j] -= nearest*columns[i]
    if original*column_transform != reduced:
        raise ArithmeticError("LLL exact integer transformation failed")
    result = KernelBasis(basis.public,reduced)
    # Both complete bases have determinant q^n; together with the exact
    # transform this verifies unimodularity without a giant det(transform).
    if max(lengths) > upper:
        raise ArithmeticError("LLL public GS bound failed")
    for j in range(reduced.ncols()):
        for i in range(j):
            mu = columns[j].dot_product(weight_vectors[i])
            if abs(mu) > QQ(1)/2:
                raise ArithmeticError("LLL exact size reduction failed")
            if i == j-1 and lengths[j]+mu**2*lengths[i] < QQ(74)/100*lengths[i]:
                raise ArithmeticError("LLL exact Lovasz condition failed")
    return result
