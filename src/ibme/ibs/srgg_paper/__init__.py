"""Paper Table 4 source-Schur SRGG IBS adapter (caller-owned).

This package exposes the literal paper-order backend:
``SourceSchurBackend`` (Algorithms 3-4 source-order ring Schur, Table 4
parameters, factor1) plus the persistent ``SourceSchurFixedIssuer``.

The default assembly route ``srgg2025`` is a different research backend
(``Config`` degree-8 profile, zeta2/factor2).  This adapter is intentionally
caller-owned, like ``srgg2025-structured``: it does not mutate the default
registry or the default paper service.  Callers build a registry with
``backend_spec()`` when they want the paper source-Schur variant.

Table 4 values in ``PaperParams`` are not changed by this package.
"""
from __future__ import annotations

__all__ = [
    "Backend", "SourceSchurBackend", "GuardedSourceSchurBackend",
    "SourceSchurFixedIssuer", "GuardedSourceSchurFixedIssuer", "FixedIssuer",
    "PublicKey", "MasterSecret", "SigningKey", "Signature", "backend_spec",
]


def __getattr__(name):
    if name == "backend_spec":
        from .registration import backend_spec
        return backend_spec
    if name in {"Backend", "SourceSchurBackend"}:
        from experiments.research.candidates.srgg import paper_schur_backend
        return getattr(paper_schur_backend, name)
    if name == "GuardedSourceSchurBackend":
        from .guarded import GuardedSourceSchurBackend
        return GuardedSourceSchurBackend
    if name in {"PublicKey", "MasterSecret", "SigningKey", "Signature"}:
        from experiments.research.candidates.srgg import paper_objects
        return getattr(paper_objects, name)
    if name in {"SourceSchurFixedIssuer", "GuardedSourceSchurFixedIssuer",
                "FixedIssuer"}:
        from .service import (
            FixedIssuer, GuardedSourceSchurFixedIssuer, SourceSchurFixedIssuer,
        )
        return {
            "SourceSchurFixedIssuer": SourceSchurFixedIssuer,
            "GuardedSourceSchurFixedIssuer": GuardedSourceSchurFixedIssuer,
            "FixedIssuer": FixedIssuer,
        }[name]
    raise AttributeError(name)
