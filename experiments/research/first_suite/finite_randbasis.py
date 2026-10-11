"""Compatibility import for the promoted CHKP runtime; see ibme.lattice.chkp.finite_randbasis."""
import sys
from ibme.lattice.chkp import finite_randbasis as _runtime
sys.modules[__name__] = _runtime
