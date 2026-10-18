"""Caller-owned BackendSpec for the paper Table 4 source-Schur backend.

The six presets are exactly the three original Table 4 rows under the two
explicitly labelled Gaussian readings.  ``PaperParams`` is imported unchanged;
this module does not alter any Table 4 value, width, factor or norm.
"""
from __future__ import annotations

import importlib.util
from math import isqrt

from ibme.core.errors import InvalidParameterError, SerializationError
from experiments.research.candidates.srgg import paper_objects as api
from experiments.research.candidates.srgg.paper_parameters import PaperParams
from experiments.research.candidates.srgg.paper_schur_backend import SourceSchurBackend


BACKEND_ID = "srgg2025-source-schur"
VERSION = "SRGG-paper-source-schur-v1"
PROFILE_NAMES = ("PARAM-I", "PARAM-II", "PARAM-III")
INTERPRETATIONS = ("table-standard-deviation", "literal-density-width")


def _format(value):
    if value not in ("reference", "canonical-json-v1"):
        raise InvalidParameterError(
            "paper source-Schur requires reference/canonical-json-v1")


def check_object(value, params):
    if type(params) is not PaperParams or type(value) not in (
            api.PublicKey, api.MasterSecret, api.SigningKey):
        raise SerializationError(
            "complete paper source-Schur object and parameter snapshot required")
    public = value if type(value) is api.PublicKey else value.public_key
    if type(public) is not api.PublicKey or public.params != params:
        raise SerializationError(
            "paper source-Schur object differs from parameter snapshot")


def signature_size(params, signature_format):
    """Conservative canonical wire size for one Table 4 signature."""
    _format(signature_format)
    if type(params) is not PaperParams:
        raise InvalidParameterError("complete paper Table 4 parameters required")
    bound = isqrt(params.signature_norm_cap)
    # Signature.__post_init__ accepts any 256-bit coordinates; using the
    # positive norm bound in the negative direction maximizes the JSON digits.
    challenge = (1,) * params.degree
    response = tuple((-bound,) * params.degree
                     for _ in range(params.columns + 1))
    return len(api.Signature(bytes(32), response, challenge).to_bytes())


def factory(rng, signature_format):
    _format(signature_format)
    return SourceSchurBackend(rng=rng)


def master_public_key(master):
    if type(master) is not api.MasterSecret:
        raise TypeError("paper SRGG MasterSecret required")
    return master.public_key


def validate_configuration(params, config):
    if type(params) is not PaperParams:
        raise InvalidParameterError("complete paper Table 4 parameters required")
    try:
        if PaperParams.from_record(params.record()) != params:
            raise ValueError("paper parameter snapshot changed")
        signature_size(params, "canonical-json-v1")
    except (ValueError, TypeError, SerializationError) as exc:
        raise InvalidParameterError(
            "paper source-Schur parameter preflight failed") from exc


def environment():
    if (importlib.util.find_spec("sage") is None
            or importlib.util.find_spec("sage.all") is None):
        raise InvalidParameterError(
            "paper source-Schur sampling requires WSL ~/miniconda3/envs/sage; "
            "no fallback")


def _presets():
    return {
        f"{profile}-{interpretation}": PaperParams(profile, interpretation)
        for profile in PROFILE_NAMES
        for interpretation in INTERPRETATIONS
    }


def backend_spec():
    """Expose the source-Schur backend without changing the default registry."""
    from ibme.assembly.registry import BackendSpec
    presets = _presets()
    return BackendSpec(
        BACKEND_ID, "ibs", VERSION, PaperParams, presets,
        factory,
        {"ipk": api.PublicKey, "imsk": api.MasterSecret, "sk": api.SigningKey},
        check_object,
        signature_size=signature_size,
        signature_formats=("reference", "canonical-json-v1"),
        key_binding=True,
        persistent_identity_cache=True,
        object_parameter_binding="full-parameter-snapshot",
        master_public_key=master_public_key,
        reason=("paper Table 4 source-order Algorithms 3-4; factor1; "
                "research only; none/false"),
        default_preset=lambda transport: "PARAM-I-table-standard-deviation",
        validate_configuration=validate_configuration,
        validate_environment=environment,
    )
