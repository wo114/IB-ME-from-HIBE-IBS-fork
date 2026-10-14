"""Original 192-dimensional ToBasis compatibility interface.

Exact mathematics lives once in ibme.lattice.matrix_sampling.basis. This
entry retains dimension192/entry8192 and the original column/GS semantics.
No widening is implicit; new matrix consumers select their own limits.
"""

from ibme.lattice.matrix_sampling.basis import (
    LEGACY_BASIS_LIMITS, _checked_square as _matrix_checked_square,
    canonical_basis as _matrix_canonical_basis, to_basis as _matrix_to_basis,
)

MAX_DIMENSION = 192
MAX_ENTRY_BITS = 8192


def _checked_square(rows, dimension):
    return _matrix_checked_square(rows, dimension, limits=LEGACY_BASIS_LIMITS)


def canonical_basis(basis):
    return _matrix_canonical_basis(basis, limits=LEGACY_BASIS_LIMITS)


def to_basis(vectors_rows, basis):
    return _matrix_to_basis(vectors_rows, basis, limits=LEGACY_BASIS_LIMITS)
