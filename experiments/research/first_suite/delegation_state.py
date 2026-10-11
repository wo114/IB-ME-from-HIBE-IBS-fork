"""Compatibility import for the promoted CHKP runtime; see ibme.lattice.chkp.delegation_state."""
import sys
from ibme.lattice.chkp import delegation_state as _runtime
sys.modules[__name__] = _runtime
