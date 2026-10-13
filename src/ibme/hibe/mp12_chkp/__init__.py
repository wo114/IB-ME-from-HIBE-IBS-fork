"""Installable public entry for the MP12/CHKP finite research variant.

The providers retain their canonical source, classes and wire versions. This
is a real reference backend with explicitly insecure n2 parameters, not an
original-CHKP or security-admitted preset. Sage and the private basis engine
are separate runtime requirements; an unavailable backend never falls back.
"""

from importlib import import_module
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
           "default_backend_spec", "sage_available", *_PROVIDERS]


def configured_engine():
    """An explicit local executable, never a path/import supplied by JSON."""
    value = os.environ.get(ENGINE_ENV)
    return None if not value else Path(value).expanduser().resolve()


def default_backend_spec():
    from ibme.assembly.registry import BackendSpec
    if not sage_available():
        return BackendSpec(BACKEND_ID, "hibe", BACKEND_VERSION, available=False,
            reason="requires SageMath in WSL ~/miniconda3/envs/sage; no fallback")
    binary = configured_engine()
    # Decode/reuse/derive from a stored full parent basis do not invoke native
    # conversion. Setup/new-receiver admission owns the engine-file check.
    provider = import_module("experiments.research.first_suite.hibe_registry")
    return provider.backend_spec(binary)


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
