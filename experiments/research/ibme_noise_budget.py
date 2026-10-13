"""Compatibility import for the promoted CHKP runtime; see ibme.lattice.chkp.noise_budget."""
import sys
from ibme.lattice.chkp import noise_budget as _runtime
sys.modules[__name__] = _runtime
