"""Compatibility import for the promoted CHKP runtime; see ibme.lattice.chkp.leaf_state."""
import sys
from ibme.lattice.chkp import leaf_state as _runtime
sys.modules[__name__] = _runtime
