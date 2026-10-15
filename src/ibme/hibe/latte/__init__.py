"""Independent patched LATTE-3 research HIBE. No security admission."""
__all__=["LATTEParams","LATTEHIBE","LATTEPublicKey","LATTEMasterSecret",
    "LATTELevel1SecretKey","LATTELevel2SecretKey","LATTECiphertext","backend_spec"]


def __getattr__(name):
    if name=="LATTEParams":
        from .params import LATTEParams
        return LATTEParams
    if name=="LATTEHIBE":
        from .backend import LATTEHIBE
        return LATTEHIBE
    if name=="backend_spec":
        from .registration import backend_spec
        return backend_spec
    if name in __all__:
        from . import objects
        return getattr(objects,name)
    raise AttributeError(name)
