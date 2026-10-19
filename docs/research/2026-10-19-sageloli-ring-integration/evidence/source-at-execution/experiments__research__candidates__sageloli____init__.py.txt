"""Adaptive Sageloli SIS/RSIS research IBS implementations.

Both routes expose the common ``setup/key_extract/sign/verify/load_signature``
surface and the same persistent :class:`FixedIssuer`.  The profiles are
research/teaching configurations and intentionally retain
``security_claim='none'`` and ``backend_admitted=False``.
"""

from .backend import Backend, SISBackend, RSISBackend, SamplingAbort
from .config import SISParams, RSISParams
from .objects import (
    SisPublicKey, RsisPublicKey, SisMasterSecret, RsisMasterSecret,
    SisSigningKey, RsisSigningKey, SisSignature, RsisSignature,
    PublicKey, MasterSecret, SigningKey, Signature,
)
from .service import FixedIssuer, IssuerPendingError, IssuerStateError

__all__ = [
    "Backend", "SISBackend", "RSISBackend", "SamplingAbort", "SISParams", "RSISParams",
    "SisPublicKey", "RsisPublicKey", "SisMasterSecret", "RsisMasterSecret",
    "SisSigningKey", "RsisSigningKey", "SisSignature", "RsisSignature",
    "PublicKey", "MasterSecret", "SigningKey", "Signature", "FixedIssuer",
    "IssuerPendingError", "IssuerStateError",
]
