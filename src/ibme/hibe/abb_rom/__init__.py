"""ABB10 CRYPTO-ROM primitives and explicit research backend proposal.

Original ABB10 teaching code is separate. The names below expose real finite
SampleR/BasisDel primitives; no empty adapter or security admission is implied.
"""

from importlib import import_module
from ibme.lattice.research import require_sage

__all__ = ["FiniteSampleR", "SampleRResult", "BasisDelPrepared", "prepare_basis_del",
           "FiniteBasisDel", "prefix_matrices", "ABBTrapGenParams", "ABBTrapGenResult",
           "abb_trapgen", "ABBBitPublic", "ABBBitCiphertext", "ABBBitEncryptor",
           "abb_decode_phase", "abb_decrypt_bit", "ABBBitDecryptor", "abb_parameter_screen",
           "MatrixSampleR", "MatrixBasisDel", "prepare_matrix_basis_del", "ABBROMParams",
           "ABBPublicKey", "ABBMasterSecret", "ABBLevel1Key", "ABBLevel2Key", "ABBCiphertext",
           "ABBROMHIBE", "ABBSamplingAbort", "backend_spec", "q104_research_params"]

_TRAPGEN = {"ABBTrapGenParams", "ABBTrapGenResult", "abb_trapgen"}
_BITS = {"ABBBitPublic", "ABBBitCiphertext", "ABBBitEncryptor", "abb_decode_phase", "abb_decrypt_bit", "ABBBitDecryptor"}
_PORTABLE = {"ABBROMParams":"params", "ABBPublicKey":"objects", "ABBMasterSecret":"objects",
    "ABBLevel1Key":"objects", "ABBLevel2Key":"objects", "ABBCiphertext":"objects", "backend_spec":"registration",
    "q104_research_params":"profiles"}


def __getattr__(name):
    if name not in __all__:raise AttributeError(name)
    if name not in _PORTABLE:require_sage()
    module = (_PORTABLE[name] if name in _PORTABLE else "backend" if name in {"ABBROMHIBE","ABBSamplingAbort"}
              else "trapgen" if name in _TRAPGEN else "bit_encryption" if name in _BITS
              else "parameter_screen" if name == "abb_parameter_screen" else "primitives")
    value=getattr(import_module("ibme.hibe.abb_rom." + module),name)
    globals()[name]=value
    return value


def __dir__():return sorted(set(globals())|set(__all__))
