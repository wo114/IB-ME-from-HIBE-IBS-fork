"""Compatibility import for the promoted CHKP runtime; see ibme.lattice.chkp.identity."""
import sys
from ibme.lattice.chkp import identity as _runtime
sys.modules[__name__] = _runtime
