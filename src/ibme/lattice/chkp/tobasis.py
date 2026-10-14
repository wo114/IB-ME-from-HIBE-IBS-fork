"""Candidate deterministic shared-engine ToBasis bridge."""
from ibme.lattice.matrix_sampling.chkp_profiles import (chkp_canonical_basis as canonical_basis, chkp_to_basis as to_basis, _basis_limits, MAX_ENTRY_BITS)
from ibme.lattice.matrix_sampling.basis import _checked_square as _shared_square
MAX_DIMENSION=192
EXTENDED_MAX_DIMENSION=512
def _dimension_limit(value):
    return _basis_limits(value).max_dimension
def _checked_square(rows, dimension):
    return _shared_square(rows, dimension, limits=_basis_limits(512))
