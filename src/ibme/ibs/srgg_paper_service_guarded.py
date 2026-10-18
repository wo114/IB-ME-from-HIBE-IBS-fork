"""Guarded source-Schur fixed issuer for the corrected v2 live path.

The frozen v1 ``srgg_paper_service.FixedIssuer`` and ``SourceSchurBackend``
remain byte-for-byte evidence of what was executed.  They are not silently
rewritten.  This module provides the corrected live path: a fixed issuer whose
default backend is ``GuardedSourceSchurBackend``, so Setup runs the complete
gate set (root rejection/retry) and signing aborts on a fixed-key gate failure.

The original unguarded paper backend is not certified by this class; the
guarantee is about the modified protected accept set.  No security claim is
made.
"""
from __future__ import annotations

from .srgg_paper_service import (
    FixedIssuer,
    IssuerStateError,
    IssuerPendingError,
    IssuerCapacityError,
    StateBusyError,
)

__all__ = [
    "GuardedSourceSchurIssuer",
    "IssuerStateError",
    "IssuerPendingError",
    "IssuerCapacityError",
    "StateBusyError",
]


class GuardedSourceSchurIssuer(FixedIssuer):
    """Persistent fixed issuer over the complete-gate source-Schur backend."""

    def __init__(self, path, backend=None, **kwargs):
        if backend is None:
            from experiments.research.candidates.srgg.paper_distribution_guard import (
                GuardedSourceSchurBackend,
            )
            backend = GuardedSourceSchurBackend()
        super().__init__(path, backend=backend, **kwargs)
