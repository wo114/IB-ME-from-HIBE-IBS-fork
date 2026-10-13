"""Compatibility import for the promoted CHKP runtime; see ibme.lattice.chkp.entropy."""
import sys
from ibme.lattice.chkp import entropy as _runtime
sys.modules[__name__] = _runtime
