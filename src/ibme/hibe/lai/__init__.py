"""Lai 2015 ideal-lattice HIBE research backend (A point, none/false).

The package import is Sage-free; ``LaiHIBE`` (and therefore the arithmetic
engine) is loaded lazily so registry/catalog discovery works on non-Sage hosts.
"""
from .params import LaiParams, VERSION
from .objects import (
    LaiCiphertext,
    LaiLevel1SecretKey,
    LaiLevel2SecretKey,
    LaiMasterSecret,
    LaiPublicKey,
)

__all__ = [
    "LaiParams",
    "VERSION",
    "LaiHIBE",
    "LaiPublicKey",
    "LaiMasterSecret",
    "LaiLevel1SecretKey",
    "LaiLevel2SecretKey",
    "LaiCiphertext",
]


def __getattr__(name):
    if name == "LaiHIBE":
        from .backend import LaiHIBE

        return LaiHIBE
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
