"""Explicit opt-in structured SRGG research API; no registry mutation."""

__all__ = ["Backend", "Parameters", "PublicKey", "MasterSecret", "SigningKey",
           "Signature", "FixedIssuer", "IssuerStateError", "IssuerPendingError", "IssuerCapacityError",
           "backend_spec"]


def __getattr__(name):
    if name == "backend_spec":
        from .structured_registration import backend_spec
        return backend_spec
    if name == "Parameters":
        from experiments.research.candidates.srgg.structured_execution import ExecutionParams
        return ExecutionParams
    if name in {"Backend", "PublicKey", "MasterSecret", "SigningKey", "Signature"}:
        from experiments.research.candidates.srgg import structured_backend
        return getattr(structured_backend, name)
    if name in {"FixedIssuer", "IssuerStateError", "IssuerPendingError", "IssuerCapacityError"}:
        from ibme.ibs import srgg_structured_service
        return getattr(srgg_structured_service, name)
    raise AttributeError(name)
