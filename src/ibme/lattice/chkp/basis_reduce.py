"""Deterministic LLL with exact lattice, GS and Lovasz postconditions.

Fixed postprocess version 2 uses fpLLL wrapper delta=3/4, eta=501/1000,
without a transformation matrix; exact checks require size <=1/2, Lovasz
>=74/100 and the caller's unchanged GS bound. Version 1 used delta=999/1000.
The output basis may differ across these versions or library builds.

This consumes no entropy and does not choose a mode from sampled results.
Applying the same fixed deterministic postprocessor to actual and ideal
RandBasis outputs cannot increase their TV distance (data processing).
It does not make their encoded basis distributions equal or prove security.
Postprocess exceptions remain failures, not permission to sample again.
The explicit input budgets bound matrix size/entries, not wall clock time.
"""
from sage.all import ZZ, QQ, matrix
from .basis import KernelBasis


def _exact_column_gso(basis):
    """Sage's exact QQ column recurrence, caching each orthogonal norm.

    The numerator uses the original column, not the partially subtracted
    vector. Over QQ the dot product equals Sage's Hermitian inner product.
    As in Sage, zero orthogonal vectors are omitted; a complete input basis
    has none. This changes neither the arithmetic result nor rejection gates.
    """
    orthogonal, norms = [], []
    for original in basis.change_ring(QQ).columns():
        current = original
        for previous, squared_norm in zip(orthogonal, norms):
            coefficient = previous.dot_product(original)/squared_norm
            current = current - coefficient*previous
        squared_norm = current.dot_product(current)
        if squared_norm:
            orthogonal.append(current)
            norms.append(squared_norm)
    star = matrix(QQ, orthogonal) if orthogonal else matrix(QQ, 0, basis.nrows())
    return star, tuple(norms)


def checked_lll(basis, gs_squared_upper, *, max_dimension=512):
    if (not isinstance(basis, KernelBasis) or type(max_dimension) is not int
            or not 1 <= max_dimension <= 512 or basis.public.ncols > max_dimension):
        raise ValueError("LLL input exceeds its explicit dimension budget")
    if any(abs(x).bit_length() > 8192 for row in basis.basis_rows for x in row):
        raise ValueError("LLL input exceeds the integer bit budget")
    bound = QQ(gs_squared_upper)
    if bound < 1:
        raise ValueError("LLL needs a positive complete-kernel GS bound")
    original = matrix(ZZ, basis.basis_rows)
    rows = original.transpose().LLL(algorithm="fpLLL:wrapper",
        delta=QQ(3)/4, eta=QQ(501)/1000, transformation=False)
    reduced = rows.transpose()
    orthogonal, norms = _exact_column_gso(reduced)
    for j in range(reduced.ncols()):
        for i in reversed(range(j)):
            mu = reduced.column(j).dot_product(orthogonal.row(i))/norms[i]
            nearest = ZZ((mu+QQ(1)/2).floor())
            if nearest:
                reduced.add_multiple_of_column(j, i, -nearest)
    result = KernelBasis(basis.public, reduced)
    # Both original (the validated input) and reduced (just checked) have
    # containment in the SAME kernel and absolute determinant q^n. They
    # therefore generate exactly the same complete lattice, independently
    # of any claimed LLL transformation; no transformation matrix is needed.
    # Integer subtraction of earlier columns leaves each ordered orthogonal
    # GS vector unchanged, so the exact pre-size-reduction geometry is valid
    # after all these operations. The output mu coefficients are recomputed.
    star, lengths = orthogonal, norms
    mu = lambda i,j: reduced.column(i).dot_product(star.row(j))/lengths[j]
    if (max(lengths) > bound
            or any(abs(mu(i,j)) > QQ(1)/2 for i in range(len(lengths)) for j in range(i))
            or any(lengths[i]+mu(i,i-1)**2*lengths[i-1] < QQ(74)/100*lengths[i-1]
                   for i in range(1,len(lengths)))):
        raise ArithmeticError("exact LLL size, GS or Lovasz postcondition failed")
    return result
