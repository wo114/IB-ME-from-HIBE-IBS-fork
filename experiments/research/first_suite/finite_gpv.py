"""Compatibility import for the promoted CHKP runtime; see ibme.lattice.chkp.finite_gpv."""
import sys
from ibme.lattice.chkp import finite_gpv as _runtime
sys.modules[__name__] = _runtime
