"""Structured MP12/CHKP H/G research implementation, separately versioned.

This namespace does not replace original CHKP or the full-basis MP12 variant.
Portable parameters are importable without Sage; execution is explicit.
"""

BACKEND_ID = "mp12-structured-hg"
BACKEND_VERSION = "mp12-structured-hg-finite-v1"

_EXPORTS = {
    "StructuredHIBEParams": "params",
    "StructuredMP12HIBE": "backend",
    "StructuredPublicKey": "objects", "StructuredMasterSecret": "objects",
    "StructuredLevel1Key": "objects", "StructuredLevel2Key": "objects",
    "StructuredCiphertext": "objects", "backend_spec": "registration",
}
__all__ = ["BACKEND_ID", "BACKEND_VERSION", *_EXPORTS]


def __getattr__(name):
    from importlib import import_module
    if name not in _EXPORTS: raise AttributeError(name)
    value = getattr(import_module(f"{__name__}.{_EXPORTS[name]}"), name)
    globals()[name] = value
    return value
