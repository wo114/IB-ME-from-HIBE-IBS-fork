"""Complete real research Wang IBS + PW conversion, using an UNSAFE debug profile.

Import/verify/wire work without Sage. Setup/extraction/signing require the
prescribed WSL Sage runtime. No default registry or production installation.
"""
from .backend import Backend
from .objects import PublicKey, MasterSecret, SigningKey, Signature
from .params import Params


def __getattr__(name):
    if name == "SamplingAbort":
        from experiments.research.gaussian_reference import SamplingAbort
        return SamplingAbort
    raise AttributeError(name)


__all__ = ["Backend", "PublicKey", "MasterSecret", "SigningKey", "Signature", "Params"]
