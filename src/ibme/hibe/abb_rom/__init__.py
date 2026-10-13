"""ABB10 CRYPTO-ROM building blocks, not yet a registered HIBE backend.

Original ABB10 teaching code is separate. The names below expose real finite
SampleR/BasisDel primitives; no empty adapter or security admission is implied.
"""

from importlib import import_module
from ibme.lattice.research import require_sage

__all__ = ["FiniteSampleR", "SampleRResult", "BasisDelPrepared", "prepare_basis_del",
           "FiniteBasisDel", "prefix_matrices", "ABBTrapGenParams", "ABBTrapGenResult",
           "abb_trapgen", "ABBBitPublic", "ABBBitCiphertext", "ABBBitEncryptor",
           "abb_decode_phase", "abb_decrypt_bit", "ABBBitDecryptor", "abb_parameter_screen",
           "MatrixSampleR", "MatrixBasisDel", "prepare_matrix_basis_del"]

_TRAPGEN = {"ABBTrapGenParams", "ABBTrapGenResult", "abb_trapgen"}
_BITS = {"ABBBitPublic", "ABBBitCiphertext", "ABBBitEncryptor", "abb_decode_phase", "abb_decrypt_bit", "ABBBitDecryptor"}


def __getattr__(name):
    if name not in __all__:raise AttributeError(name)
    require_sage()
    module = ("trapgen" if name in _TRAPGEN else "bit_encryption" if name in _BITS
              else "parameter_screen" if name == "abb_parameter_screen" else "primitives")
    value=getattr(import_module("ibme.hibe.abb_rom." + module),name)
    globals()[name]=value
    return value


def __dir__():return sorted(set(globals())|set(__all__))
