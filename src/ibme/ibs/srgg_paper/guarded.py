"""Compatibility names for the single guarded paper source-Schur backend.

``SourceSchurBackend`` itself installs the complete guard. The historical
``GuardedSourceSchurBackend`` spelling is an alias, so selecting it cannot
run the independent audit twice or introduce a second exception namespace.
The guard is a service/accept-set policy; Table 4 and object formats are unchanged.
"""
from __future__ import annotations

from experiments.research.candidates.srgg.paper_distribution_guard import (
    RootGateRejection, SigningKeyGateRejection,
)
from experiments.research.candidates.srgg.paper_schur_backend import SourceSchurBackend

__all__ = [
    "GuardedSourceSchurBackend", "RootGateRejection", "SigningKeyGateRejection",
]


GuardedSourceSchurBackend = SourceSchurBackend
