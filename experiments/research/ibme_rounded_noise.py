"""Compatibility import for the promoted CHKP runtime; see ibme.lattice.chkp.rounded_noise."""
import sys
from ibme.lattice.chkp import rounded_noise as _runtime
sys.modules[__name__] = _runtime
