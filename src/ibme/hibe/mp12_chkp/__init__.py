"""Installable public entry for the MP12/CHKP finite research variant.

The providers retain their canonical source, classes and wire versions. This
is a real reference backend with explicitly insecure n2 parameters, not an
original-CHKP or security-admitted preset. Sage and the private basis engine
are separate runtime requirements; an unavailable backend never falls back.
"""

from importlib import import_module
from importlib.util import find_spec
from pathlib import Path
import os

from ibme.lattice.research import require_sage, sage_available

BACKEND_ID = "mp12-chkp-reference"
BACKEND_VERSION = "mp12-chkp-finite-v1"
ENGINE_ENV = "IBME_QFALL_PRIVATE_ENGINE"
_PROVIDERS = {
    name: ("experiments.research.first_suite.hibe_reference", name)
    for name in ("MP12HIBEParams", "MP12HIBEPublicKey", "MP12HIBEMasterSecret",
                 "MP12HIBEReceiver", "MP12HIBELeaf", "MP12HIBECiphertext", "MP12CHKPResearchHIBE")
}
_PROVIDERS.update({
    name: ("experiments.research.first_suite.hibe_registry", name)
    for name in ("backend_spec", "research_registry", "research_suite")
})
__all__ = ["BACKEND_ID", "BACKEND_VERSION", "ENGINE_ENV", "configured_engine",
           "default_backend_spec", "backend_metadata", "sage_available", *_PROVIDERS]


def configured_engine():
    """An explicit local executable, never a path/import supplied by JSON."""
    value = os.environ.get(ENGINE_ENV)
    return None if not value else Path(value).expanduser().resolve()


def _provider_available():
    # A src-only checkout import outside the repository need not contain the
    # optional experiments package. Inspect its provider without importing Sage
    # arithmetic; missing optional code must not disable unrelated selections.
    try:
        return find_spec("experiments.research.first_suite.hibe_registry") is not None
    except ModuleNotFoundError as exc:
        if exc.name not in ("experiments", "experiments.research", "experiments.research.first_suite"):
            raise
        return False


def _unavailable_reason():
    if not sage_available():
        return "requires SageMath in WSL ~/miniconda3/envs/sage; no fallback"
    if not _provider_available():
        return "optional experiments.research.first_suite provider missing; install the complete ibme wheel or expose the project root; no fallback"
    return ""


def default_backend_spec():
    from ibme.assembly.registry import BackendSpec
    reason = _unavailable_reason()
    if reason:
        return BackendSpec(BACKEND_ID, "hibe", BACKEND_VERSION, available=False,
            reason=reason)
    binary = configured_engine()
    # Decode/reuse/derive from a stored full parent basis do not invoke native
    # conversion. Setup/new-receiver admission owns the engine-file check.
    provider = import_module("experiments.research.first_suite.hibe_registry")
    return provider.backend_spec(binary)


def backend_metadata():
    """Public discovery only; importing the real provider initializes Sage.

    This record has no factories, decoders or parameter objects. Runtime
    selection still obtains the complete, validated default_backend_spec.
    """
    missing = _unavailable_reason()
    present = not missing
    reason = ("Source-checkout Sage/qFALL reference; n2 is insecure; no formal or original-CHKP theorem admission"
              if present else missing)
    return dict(
        id=BACKEND_ID, version=BACKEND_VERSION, available=present,
        test_only=False, reason=reason,
        parameter_presets=["n2-reference"] if present else [],
        security_claim="none", backend_admitted=False,
        formal_parameter_presets=[], admission_basis="",
        signature_formats=["reference"], two_level=present, key_binding=present,
        object_parameter_binding="full-parameter-snapshot" if present else "backend-specific",
        master_public_key_capability=False, persistent_identity_cache=present,
        runtime_available=present, runtime_reason="" if present else reason,
    )


def __getattr__(name):
    if name not in _PROVIDERS:
        raise AttributeError(name)
    require_sage()
    module, attribute = _PROVIDERS[name]
    value = getattr(import_module(module), attribute)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(__all__))
