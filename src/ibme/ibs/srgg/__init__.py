"""Standalone SRGG IBS adapter.

The research implementation remains under ``experiments`` so that its Sage
sampling dependency is explicit.  This package exposes only the primitive
objects and registration descriptor; it does not register a default backend
or make a security claim.
"""

__all__ = [
    "Backend", "Config", "FixedIssuer", "IssuerCapacityError",
    "IssuerPendingError", "IssuerStateError", "MasterSecret", "PublicKey",
    "Signature", "SigningKey",
]


def __getattr__(name):
    if name == "Backend":
        from experiments.research.candidates.srgg.backend import Backend
        return Backend
    if name == "Config":
        from experiments.research.candidates.srgg.config import Config
        return Config
    if name in {"MasterSecret", "PublicKey", "Signature", "SigningKey"}:
        from experiments.research.candidates.srgg import objects
        return getattr(objects, name)
    if name in {"FixedIssuer", "IssuerCapacityError", "IssuerPendingError", "IssuerStateError"}:
        from ibme.ibs.srgg_service import (
            FixedIssuer, IssuerCapacityError, IssuerPendingError, IssuerStateError,
        )
        return locals()[name]
    raise AttributeError(name)
