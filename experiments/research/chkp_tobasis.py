"""Compatibility import for the promoted CHKP runtime; see ibme.lattice.chkp.tobasis."""
import sys
from ibme.lattice.chkp import tobasis as _runtime
sys.modules[__name__] = _runtime
