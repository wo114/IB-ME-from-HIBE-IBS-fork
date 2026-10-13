"""Public access to the single finite Sage research implementation.

Importing this namespace never imports Sage or samples entropy. Providers are
shipped in the wheel under their original research names; no second copy of
the mathematics is maintained. Limits/certificates/abort behavior are those
of the named providers. This API does not admit security parameters.
"""

from importlib import import_module, util

from ibme.core.errors import InvalidParameterError

_PROVIDERS = {
    "KernelBasis": ("experiments.research.chkp_basis", "KernelBasis"),
    "ModMatrixReference": ("experiments.research.chkp_basis", "ModMatrixReference"),
    "ext_basis": ("experiments.research.chkp_basis", "ext_basis"),
    "SamplingAbort": ("experiments.research.gaussian_reference", "SamplingAbort"),
    "FirstFiniteOptions": ("experiments.research.first_suite.finite_gaussian", "FirstFiniteOptions"),
    "FirstFiniteGaussian": ("experiments.research.first_suite.finite_gaussian", "FirstFiniteGaussian"),
    "FirstFiniteGPV": ("experiments.research.first_suite.finite_gpv", "FirstFiniteGPV"),
    "FiniteDelTrap": ("experiments.research.first_suite.compact_delegation", "FiniteDelTrap"),
    "CompactGTrapdoor": ("experiments.research.first_suite.compact_delegation", "CompactGTrapdoor"),
    "ComputationalRootParams": ("experiments.research.first_suite.computational_root", "ComputationalRootParams"),
    "ComputationalRootGenerator": ("experiments.research.first_suite.computational_root", "ComputationalRootGenerator"),
}
__all__ = ["sage_available", "require_sage", *_PROVIDERS]


def sage_available():
    try:
        return util.find_spec("sage") is not None and util.find_spec("sage.all") is not None
    except (ImportError, ValueError, AttributeError):
        return False


def require_sage():
    if not sage_available():
        raise InvalidParameterError(
            "finite research tools require SageMath; use WSL ~/miniconda3/envs/sage; no fallback")


def __getattr__(name):
    if name not in _PROVIDERS:
        raise AttributeError(name)
    require_sage()
    module, attribute = _PROVIDERS[name]
    try:
        value = getattr(import_module(module), attribute)
    except ModuleNotFoundError as exc:
        raise InvalidParameterError("research support package missing; install the complete ibme wheel") from exc
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(__all__))
