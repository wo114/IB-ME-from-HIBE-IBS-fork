"""Public SRGG IBS registration adapter.

This descriptor is deliberately independent of any HIBE choice.  It describes
the complete research IBS object contract and runtime dependency while leaving
the shared coordinator's default registry as the owner of registration.  The
registered profile is an engineering/research profile only:
``security_claim=none``, ``backend_admitted=False`` and
``parameters_are_formal=False``.
"""

from __future__ import annotations

import importlib.util
import math

from ibme.core.errors import InvalidParameterError, SerializationError

from experiments.research.candidates.srgg.backend import Backend
from experiments.research.candidates.srgg.config import Config
from experiments.research.candidates.srgg.objects import (
    MasterSecret,
    PublicKey,
    Signature,
    SigningKey,
)


BACKEND_ID = "srgg2025"
VERSION = "SRGG-zeta2-research-v1"


def check_object(value, params):
    """Check a public/private SRGG object against the complete snapshot."""

    if type(params) is not Config:
        raise SerializationError("SRGG requires a complete Config snapshot")
    if type(value) not in (PublicKey, MasterSecret, SigningKey):
        raise SerializationError("SRGG object type is not registered")
    public = value if type(value) is PublicKey else value.public_key
    if public.config != params:
        raise SerializationError("SRGG object differs from selected parameter snapshot")


def signature_size(params, signature_format):
    """Return the conservative maximum wire size for a valid response."""

    if type(params) is not Config:
        raise InvalidParameterError("SRGG requires Config parameters")
    if signature_format not in ("reference", "canonical-json-v1"):
        raise InvalidParameterError("SRGG supports reference/canonical-json-v1 only")
    bound = math.isqrt(params.signature_bound_squared)
    return len(Signature(
        bytes(32),
        ((-bound,) * params.degree,) * (params.algebra.columns + 1),
        (1,) * params.degree,
    ).to_bytes())


def factory(rng, signature_format):
    if signature_format not in ("reference", "canonical-json-v1"):
        raise InvalidParameterError("SRGG supports reference/canonical-json-v1 only")
    return Backend(rng=rng)


def master_public_key(master):
    if type(master) is not MasterSecret:
        raise TypeError("expected SRGG MasterSecret")
    return master.public_key


def validate_configuration(params, config):
    """Run Config's local resource/invariant checks without Setup or entropy."""

    if type(params) is not Config:
        raise InvalidParameterError("SRGG requires Config parameters")
    # Config is frozen and validates all public arithmetic/resource bounds in
    # __post_init__. Reconstructing from its record also rejects subclasses or
    # mutable/partial snapshots before a caller builds a runtime.
    try:
        if Config.from_record(params.record()) != params:
            raise ValueError("parameter snapshot changed during validation")
    except (TypeError, ValueError) as exc:
        raise InvalidParameterError("SRGG research parameter preflight failed") from exc


def environment():
    """Require the prescribed Sage runtime for real sampling."""

    if (importlib.util.find_spec("sage") is None
            or importlib.util.find_spec("sage.all") is None):
        raise InvalidParameterError(
            "SRGG execution requires SageMath in WSL ~/miniconda3/envs/sage; no fallback"
        )


def backend_spec():
    """Build an explicit descriptor without mutating any registry."""

    from ibme.assembly.registry import BackendSpec

    return BackendSpec(
        BACKEND_ID,
        "ibs",
        VERSION,
        Config,
        {"research": Config()},
        factory,
        {"ipk": PublicKey, "imsk": MasterSecret, "sk": SigningKey},
        check_object,
        signature_size=signature_size,
        signature_formats=("reference", "canonical-json-v1"),
        key_binding=True,
        persistent_identity_cache=True,
        object_parameter_binding="full-parameter-snapshot",
        master_public_key=master_public_key,
        reason=(
            "degree8 zeta2 research profile; finite numeric error and formal "
            "parameters unadmitted"
        ),
        default_preset=lambda transport: "research",
        validate_configuration=validate_configuration,
        validate_environment=environment,
    )

