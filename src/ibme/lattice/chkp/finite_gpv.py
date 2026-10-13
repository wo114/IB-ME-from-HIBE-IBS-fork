"""Candidate CHKP explicit 512/2048-bit profile over the shared engine."""
from ibme.core.randomness import SecureRandom
from ibme.lattice.matrix_sampling.gpv import (_bit_length, _bounded_rational, _bounded_basis, _gs_geometry as _shared_geometry, _admit_paths)
from ibme.lattice.matrix_sampling.chkp_profiles import (CHKPFiniteGPV as FirstFiniteGPV, MAX_INPUT_BITS, MAX_SQUARED_WIDTH)
MAX_DIMENSION=256
EXTENDED_MAX_DIMENSION=512

_bounded_qq = _bounded_rational
def _gs_geometry(rows, bits):
    return _shared_geometry(rows, bits, gate=_bounded_qq)
