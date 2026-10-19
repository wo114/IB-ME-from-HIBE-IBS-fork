"""Adaptive Sageloli SIS/RSIS research IBS implementations.

Both routes expose the common ``setup/key_extract/sign/verify/load_signature``
surface and the same persistent :class:`FixedIssuer`.  The profiles are
research/teaching configurations and intentionally retain
``security_claim='none'`` and ``backend_admitted=False``.
"""

from importlib import import_module

__all__ = [
    "Backend", "SISBackend", "RSISBackend", "SamplingAbort", "SISParams", "RSISParams",
    "SisPublicKey", "RsisPublicKey", "SisMasterSecret", "RsisMasterSecret",
    "SisSigningKey", "RsisSigningKey", "SisSignature", "RsisSignature",
    "PublicKey", "MasterSecret", "SigningKey", "Signature", "FixedIssuer",
    "IssuerPendingError", "IssuerStateError",
]

# Importing ring.params/codec for static discovery must not initialize the
# legacy sampler. Preserve the public v2 exports, resolving them only on use.
_MODULES = {
    **{name: ".backend" for name in ("Backend", "SISBackend", "RSISBackend", "SamplingAbort")},
    **{name: ".config" for name in ("SISParams", "RSISParams")},
    **{name: ".objects" for name in (
        "SisPublicKey", "RsisPublicKey", "SisMasterSecret", "RsisMasterSecret",
        "SisSigningKey", "RsisSigningKey", "SisSignature", "RsisSignature",
        "PublicKey", "MasterSecret", "SigningKey", "Signature")},
    **{name: ".service" for name in ("FixedIssuer", "IssuerPendingError", "IssuerStateError")},
}


def __getattr__(name):
    if name not in _MODULES:
        raise AttributeError(name)
    value = getattr(import_module(_MODULES[name], __name__), name)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(__all__))
