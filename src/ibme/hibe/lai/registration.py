"""Registry descriptor for the Lai A-point research backend."""
from __future__ import annotations

import importlib.util

from ibme.core.errors import InvalidParameterError, SerializationError
from . import codec
from .objects import (
    LaiCiphertext,
    LaiLevel1SecretKey,
    LaiLevel2SecretKey,
    LaiMasterSecret,
    LaiPublicKey,
)
from .params import LaiParams, TARGET_CANDIDATE_PARAMS, VERSION

ASSEMBLY_VERSION = VERSION


def check_object(value, params):
    if getattr(value, "params", None) != params:
        raise SerializationError("Lai object differs from selected parameters")


def ciphertext_size(params, payload_bytes, identity_bytes):
    if type(payload_bytes) is not int or type(identity_bytes) is not int:
        raise InvalidParameterError("Lai capacity arguments must be integers")
    if not 0 <= payload_bytes <= params.max_message_bytes:
        raise InvalidParameterError("Lai payload exceeds max_message_bytes")
    if not 1 <= identity_bytes <= params.identity_bytes:
        raise InvalidParameterError("Lai identity exceeds identity_bytes")
    width = params.coefficient_bytes
    params_len = len(codec.params_bytes(params))
    ring_len = width * params.n
    body = (params_len + 1 + ring_len
            + 2 + (params.l + 2 * params.k) * ring_len
            + 2 + params.k * ring_len)
    return len(codec.MAGIC_CT) + 4 + body


def environment():
    if importlib.util.find_spec("sage") is None or \
            importlib.util.find_spec("sage.all") is None:
        raise InvalidParameterError(
            "Lai requires WSL ~/miniconda3/envs/sage; no fallback")


def factory(rng, signature_format):
    from .backend import LaiHIBE

    return LaiHIBE()


def configuration(params, config):
    expected = "hybrid" if params.message_mode == "seed32" else "direct"
    if config["transport"] != expected:
        raise InvalidParameterError(
            "Lai plaintext framing differs from selected transport")


def backend_spec():
    from ibme.assembly.registry import BackendSpec, PROJECT_SECURITY_CLAIM

    return BackendSpec(
        "lai-ideal-hibe", "hibe", ASSEMBLY_VERSION, LaiParams,
        {"hybrid-research": LaiParams(),
         "direct-research": LaiParams(message_mode="framed32"),
         "target-research": TARGET_CANDIDATE_PARAMS},
        factory,
        {"hpk": LaiPublicKey, "hmsk": LaiMasterSecret,
         "sk1": LaiLevel1SecretKey, "sk2": LaiLevel2SecretKey},
        check_object, two_level=True, key_binding=True,
        reason="completed Lai backend; target-research C2 profile project admitted",
        ciphertext_size=ciphertext_size,
        object_parameter_binding="full-parameter-snapshot",
        default_preset=lambda transport: (
            "hybrid-research" if transport == "hybrid" else "direct-research"),
        validate_environment=environment, validate_configuration=configuration,
        security_claim=PROJECT_SECURITY_CLAIM, backend_admitted=True,
        formal_parameter_presets=("target-research",),
        admission_basis="cited Lai construction, selected C2 target profile, and completed target lifecycle/combination acceptance")
