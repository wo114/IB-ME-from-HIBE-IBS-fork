"""Compatibility import for the promoted CHKP runtime; see ibme.lattice.chkp.seed_kem."""
import sys
from ibme.lattice.chkp import seed_kem as _runtime
sys.modules[__name__] = _runtime
