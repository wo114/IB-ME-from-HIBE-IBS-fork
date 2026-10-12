"""ABB10 CRYPTO-ROM building blocks, not yet a registered HIBE backend.

Original ABB10 teaching code is separate. The names below expose real finite
SampleR/BasisDel primitives; no empty adapter or security admission is implied.
"""

from importlib import import_module
from ibme.lattice.research import require_sage

__all__ = ["FiniteSampleR", "SampleRResult", "BasisDelPrepared", "prepare_basis_del",
           "FiniteBasisDel", "prefix_matrices"]


def __getattr__(name):
    if name not in __all__:raise AttributeError(name)
    require_sage()
    value=getattr(import_module("ibme.hibe.abb_rom.primitives"),name)
    globals()[name]=value
    return value


def __dir__():return sorted(set(globals())|set(__all__))
