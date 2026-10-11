"""Deterministic LLL with exact lattice, GS and Lovasz postconditions.

This promotes the already-tested root_sampler_audit rule. It is a public
profile choice, not a failed-sampling retry or a new trapdoor distribution.
The explicit input budgets bound matrix size/entries, not wall clock time.
"""
from sage.all import ZZ, QQ, matrix
from .basis import KernelBasis


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
    rows, transform = original.transpose().LLL(
        delta=QQ(999)/1000, eta=QQ(501)/1000, transformation=True)
    reduced, change = rows.transpose(), transform.transpose()
    orthogonal, _ = reduced.transpose().change_ring(QQ).gram_schmidt()
    norms = tuple(row.dot_product(row) for row in orthogonal.rows())
    for j in range(reduced.ncols()):
        for i in reversed(range(j)):
            mu = reduced.column(j).dot_product(orthogonal.row(i))/norms[i]
            nearest = ZZ((mu+QQ(1)/2).floor())
            if nearest:
                reduced.add_multiple_of_column(j, i, -nearest)
                change.add_multiple_of_column(j, i, -nearest)
    if original*change != reduced:
        raise ArithmeticError("LLL transformation did not preserve the complete lattice")
    result = KernelBasis(basis.public, reduced)
    # Both original (the validated input) and reduced (just checked) have
    # absolute determinant q^n. The exact product above therefore certifies
    # |det(change)|=1 without a costly determinant of its huge coefficients.
    # Integer subtraction of earlier columns leaves each ordered orthogonal
    # GS vector unchanged, so the exact pre-size-reduction geometry is valid
    # after all these operations. The output mu coefficients are recomputed.
    star, lengths = orthogonal, norms
    mu = lambda i,j: reduced.column(i).dot_product(star.row(j))/lengths[j]
    if (max(lengths) > bound
            or any(abs(mu(i,j)) > QQ(1)/2 for i in range(len(lengths)) for j in range(i))
            or any(lengths[i]+mu(i,i-1)**2*lengths[i-1] < QQ(99)/100*lengths[i-1]
                   for i in range(1,len(lengths)))):
        raise ArithmeticError("exact LLL size, GS or Lovasz postcondition failed")
    return result
