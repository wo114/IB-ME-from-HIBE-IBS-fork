"""Compatibility import for the promoted CHKP runtime; see ibme.lattice.chkp.finite_gaussian."""
import sys
from ibme.lattice.chkp import finite_gaussian as _runtime
sys.modules[__name__] = _runtime
