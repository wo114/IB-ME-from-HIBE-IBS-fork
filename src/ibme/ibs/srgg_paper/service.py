"""Persistent issuer convenience for the paper source-Schur backend.

``srgg_paper_service.FixedIssuer`` remains byte-compatible and accepts an
explicit backend.  This wrapper only changes the *default* backend to
``SourceSchurBackend`` for callers that select the paper source-Schur route.
It does not change Table 4, the paper objects or the old service default.
"""
from __future__ import annotations

from ibme.ibs.srgg_paper_service import (
    FixedIssuer,
    IssuerCapacityError,
    IssuerPendingError,
    IssuerStateError,
    StateBusyError,
)

__all__ = [
    "FixedIssuer", "SourceSchurFixedIssuer", "GuardedSourceSchurFixedIssuer",
    "IssuerStateError", "IssuerPendingError", "IssuerCapacityError",
    "StateBusyError",
]


class SourceSchurFixedIssuer(FixedIssuer):
    """Fixed issuer defaulting to the paper-order source-Schur backend."""

    def __init__(self, path, backend=None, **kwargs):
        if backend is None:
            from experiments.research.candidates.srgg.paper_schur_backend import (
                SourceSchurBackend,
            )
            backend = SourceSchurBackend()
        super().__init__(path, backend, **kwargs)


class GuardedSourceSchurFixedIssuer(FixedIssuer):
    """Fixed issuer defaulting to the guarded paper source-Schur backend.

    Setup gate failures are ``RootGateRejection`` (retryable by the unchanged
    Setup loop).  Signing-plan gate failures abort the fixed key.
    """

    def __init__(self, path, backend=None, **kwargs):
        if backend is None:
            from .guarded import GuardedSourceSchurBackend
            backend = GuardedSourceSchurBackend()
        super().__init__(path, backend, **kwargs)
