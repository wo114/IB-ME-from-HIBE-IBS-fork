"""Compatibility import for the promoted CHKP runtime; see ibme.lattice.chkp.gaussian."""
import sys
from ibme.lattice.chkp import gaussian as _runtime
sys.modules[__name__] = _runtime
