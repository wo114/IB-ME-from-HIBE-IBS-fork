"""Compatibility import for the promoted CHKP runtime; see ibme.lattice.chkp.basis."""
import sys
from ibme.lattice.chkp import basis as _runtime
sys.modules[__name__] = _runtime
