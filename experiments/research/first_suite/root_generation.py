"""Compatibility import for the promoted CHKP runtime; see ibme.lattice.chkp.root_generation."""
import sys
from ibme.lattice.chkp import root_generation as _runtime
sys.modules[__name__] = _runtime
