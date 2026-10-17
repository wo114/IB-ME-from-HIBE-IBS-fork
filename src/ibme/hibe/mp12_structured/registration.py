"""Portable, explicit structured H/G adapter; no native-engine fallback."""

from ibme.core.errors import InvalidParameterError
from ibme.lattice.research import sage_available
from importlib.util import find_spec
from . import BACKEND_ID, BACKEND_VERSION
from .params import StructuredHIBEParams, StructuredHIBEParams192, FINITE192_VERSION
from .objects import (StructuredPublicKey, StructuredMasterSecret,
    StructuredLevel1Key, StructuredLevel2Key, StructuredCiphertext, check_object,
    MAGIC)


def environment():
    if not sage_available():
        raise InvalidParameterError("structured MP12 H/G requires WSL ~/miniconda3/envs/sage; no fallback")
    try:
        found = find_spec("experiments.research.first_suite.entropy")
    except ModuleNotFoundError as exc:
        if exc.name not in ("experiments", "experiments.research", "experiments.research.first_suite"):
            raise
        found = None
    if found is None:
        raise InvalidParameterError("structured H/G requires the packaged research support modules; install the complete ibme wheel or expose the project root; no fallback")


def factory(rng, signature_format):
    if signature_format != "reference": raise InvalidParameterError("structured H/G format")
    environment()
    from .backend import StructuredMP12HIBE
    return StructuredMP12HIBE()


def configuration(params, config):
    if config["transport"] != "hybrid":
        raise InvalidParameterError("structured H/G seed32 profile requires hybrid transport")
    environment()


def ciphertext_size(params, payload_bytes, identity_bytes):
    if type(payload_bytes) is not int or payload_bytes != 32:
        raise InvalidParameterError("structured H/G seed32 raw payload capacity")
    from ibme.lattice.chkp.seed_kem import MAGIC as CAPSULE_MAGIC
    capsule = len(CAPSULE_MAGIC)+64+8+4+(params.leaf_dimension+256)*(((params.q-1).bit_length()+7)//8)
    # Both frame fields have an explicit 4-byte length.
    return len(MAGIC)+4+len(b"CIPHERTEXT")+4+capsule


def backend_spec():
    from ibme.assembly.registry import BackendSpec
    return BackendSpec(BACKEND_ID, "hibe", BACKEND_VERSION, StructuredHIBEParams,
        {"n2-full-hg-research": StructuredHIBEParams()}, factory,
        dict(hpk=StructuredPublicKey, hmsk=StructuredMasterSecret, sk1=StructuredLevel1Key, sk2=StructuredLevel2Key),
        check_object, two_level=True, key_binding=True, persistent_identity_cache=True,
        reason="structured MP12 variant with full CHKP ROM H/G; n2 public-attack negative control; none/false/false",
        ciphertext_size=ciphertext_size, object_parameter_binding="full-parameter-snapshot",
        default_preset=lambda transport: "n2-full-hg-research",
        validate_configuration=configuration, validate_environment=environment)


def finite192_backend_spec():
    """Explicit caller-owned v2 registration; never changes the default v1 registry."""
    from dataclasses import replace
    return replace(backend_spec(), version=FINITE192_VERSION,
        params_type=StructuredHIBEParams192,
        presets={"n2-full-hg-finite192-research": StructuredHIBEParams192()},
        default_preset=lambda transport: "n2-full-hg-finite192-research",
        reason="same structured MP12/CHKP algorithm, explicitly versioned finite192 recipe; insecure n2, none/false/false")
