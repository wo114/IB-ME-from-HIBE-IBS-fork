"""Caller-owned descriptor for structured SRGG; no default registration."""
from __future__ import annotations

from dataclasses import asdict
import importlib.util

from ibme.core.errors import InvalidParameterError, SerializationError
from experiments.research.candidates.srgg import structured_backend as api
from experiments.research.candidates.srgg.structured_execution import ExecutionParams
from experiments.research.candidates.srgg.formal_candidates import conditional_candidate


BACKEND_ID = "srgg2025-structured"
VERSION = "SRGG-zeta2-structured-deep-research-v1"


def check_object(value, params):
    if type(params) is not ExecutionParams or type(value) not in (
            api.PublicKey, api.MasterSecret, api.SigningKey):
        raise SerializationError("complete structured SRGG object and parameters required")
    public = value if type(value) is api.PublicKey else value.public_key
    if public.params != params:
        raise SerializationError("structured SRGG object differs from parameter snapshot")


def _format(value):
    if value not in ("reference", "canonical-json-v1"):
        raise InvalidParameterError("structured SRGG requires reference/canonical-json-v1")


def signature_size(params, signature_format):
    _format(signature_format)
    if type(params) is not ExecutionParams:
        raise InvalidParameterError("complete structured SRGG parameters required")
    return api.signature_size(params)


def factory(rng, signature_format):
    _format(signature_format)
    return api.Backend(rng=rng)


def master_public_key(master):
    if type(master) is not api.MasterSecret:
        raise TypeError("structured SRGG MasterSecret required")
    return master.public_key


def validate_configuration(params, config):
    if type(params) is not ExecutionParams:
        raise InvalidParameterError("complete structured SRGG parameters required")
    try:
        if ExecutionParams(**asdict(params)) != params:
            raise ValueError("structured SRGG parameter snapshot changed")
        api.signature_size(params)
    except (ValueError, TypeError, SerializationError) as exc:
        raise InvalidParameterError("structured SRGG resource preflight failed") from exc


def environment():
    if (importlib.util.find_spec("sage") is None
            or importlib.util.find_spec("sage.all") is None):
        raise InvalidParameterError(
            "structured SRGG sampling requires WSL ~/miniconda3/envs/sage; no fallback")


def backend_spec():
    """Expose full parameters and decoders for the coordinator's own registry."""
    from ibme.assembly.registry import BackendSpec
    return BackendSpec(
        BACKEND_ID, "ibs", VERSION, ExecutionParams,
        {"research-small": ExecutionParams.from_candidate(
            conditional_candidate(degree=8, rank=1, digits=3)),
         "research-n512": ExecutionParams.from_candidate(
            conditional_candidate(degree=512, rank=2, digits=8))},
        factory, {"ipk": api.PublicKey, "imsk": api.MasterSecret, "sk": api.SigningKey},
        check_object, signature_size=signature_size,
        signature_formats=("reference", "canonical-json-v1"),
        key_binding=True, persistent_identity_cache=True,
        object_parameter_binding="full-parameter-snapshot",
        master_public_key=master_public_key,
        reason="structured deep-profile research execution; hardness and QROM unadmitted",
        # Multiple research points remain an explicit caller choice.
        validate_configuration=validate_configuration, validate_environment=environment)
