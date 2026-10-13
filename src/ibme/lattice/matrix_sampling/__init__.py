"""Explicit finite matrix profiles, lazily requiring prescribed Sage.

Old first_suite entries are compatibility consumers of this one implementation.
Wide domains and certificates are independent inputs, never implicit upgrades.
"""

from importlib import import_module
from ibme.lattice.research import require_sage

_PROVIDERS = {
    "MatrixFiniteOptions": ("scalar", "MatrixFiniteOptions"),
    "MatrixFiniteGaussian": ("scalar", "MatrixFiniteGaussian"),
    "MatrixFiniteGPV": ("gpv", "MatrixFiniteGPV"),
    "MatrixBasisLimits": ("basis", "MatrixBasisLimits"),
    "matrix_canonical_basis": ("basis", "canonical_basis"),
    "matrix_to_basis": ("basis", "to_basis"),
    "matrix_checked_lll": ("basis", "matrix_checked_lll"),
    "MatrixFiniteRandBasis": ("randbasis", "MatrixFiniteRandBasis"),
    "MatrixFiniteRandResult": ("randbasis", "MatrixFiniteRandResult"),
    "matrix_modular_inverse": ("modular", "modular_inverse"),
    "matrix_modular_determinant": ("modular", "modular_determinant"),
}
__all__ = list(_PROVIDERS)


def __getattr__(name):
    if name not in _PROVIDERS:
        raise AttributeError(name)
    require_sage()
    module, attribute = _PROVIDERS[name]
    value = getattr(import_module(__name__ + "." + module), attribute)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(__all__))
