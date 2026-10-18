"""Guarded paper source-Schur backend.

The functional backend in ``registration.py``/``service.py`` does not execute
the distribution-chain audit gates.  This module adds the explicit guard used
by the distribution-chain theorem:

* Setup/master-plan gate failure raises ``RootGateRejection``, a subclass of
  ``WitnessGeometryError``, so the unchanged Setup loop retries the root.
* Signing-plan gate failure raises ``SigningKeyGateRejection``; the fixed key
  aborts and is never retried or silently replaced.

This is a service/accept-set policy, not a change to Table 4, the paper
algorithms or the object formats.
"""
from __future__ import annotations

from experiments.research.candidates.srgg.paper_distribution_chain import (
    ChainCertificateError, require_gates,
)
from experiments.research.candidates.srgg.paper_samplef import WitnessGeometryError
from experiments.research.candidates.srgg.paper_schur_backend import SourceSchurBackend

__all__ = [
    "GuardedSourceSchurBackend", "RootGateRejection", "SigningKeyGateRejection",
]


class RootGateRejection(WitnessGeometryError):
    """A master plan failed the complete distribution-chain gate set."""


class SigningKeyGateRejection(Exception):
    """A fixed signing key failed the signing-plan gate set."""


class GuardedSourceSchurBackend(SourceSchurBackend):
    """Source-Schur backend that executes the audit gates before use."""

    def _master_plan(self, params, witness):
        plan = super()._master_plan(params, witness)
        try:
            gadget, _scalar = self._components(params)
            require_gates(plan, params=params, gadget=gadget, root_phase=True)
        except ChainCertificateError as error:
            raise RootGateRejection(str(error)) from error
        return plan

    def _sign_plan(self, key):
        plan = super()._sign_plan(key)
        try:
            require_gates(plan)
        except ChainCertificateError as error:
            raise SigningKeyGateRejection(str(error)) from error
        return plan
