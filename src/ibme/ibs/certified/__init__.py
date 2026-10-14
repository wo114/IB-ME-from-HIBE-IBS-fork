"""Standalone BNN certification IBS; no default registry side effects."""
__all__ = ["CertifiedIBSParams", "CertifiedIBS", "IssuancePending", "CertifiedPublicKey",
           "CertifiedMasterSecret", "CertifiedSigningKey", "CertifiedSignature"]


def __getattr__(name):
    if name == "CertifiedIBSParams":
        from .params import CertifiedIBSParams
        return CertifiedIBSParams
    if name in ("CertifiedIBS", "IssuancePending"):
        from . import backend
        return getattr(backend, name)
    if name in __all__:
        from . import objects
        return getattr(objects, name)
    raise AttributeError(name)
