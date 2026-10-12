"""Optional public entry, explicit engine selection and single-source identity."""

from pathlib import Path
import importlib
import json
import os
import subprocess
import sys

import pytest

from ibme.core.errors import InvalidParameterError
from ibme.hibe import mp12_chkp
from ibme.lattice import research


def test_plain_public_import_does_not_import_or_require_sage():
    script = (
        "import sys; import ibme.hibe.mp12_chkp, ibme.lattice.research; "
        "assert 'sage.all' not in sys.modules; print('ok')"
    )
    env=dict(os.environ,PYTHONPATH=str(Path(research.__file__).resolve().parents[3]))
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True,env=env)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip() == "ok"


def test_unknown_public_names_remain_attribute_errors():
    for module in (research, mp12_chkp):
        with pytest.raises(AttributeError):
            getattr(module, "not_a_backend")


def test_engine_is_explicit_local_configuration(monkeypatch,tmp_path):
    monkeypatch.delenv(mp12_chkp.ENGINE_ENV,raising=False)
    assert mp12_chkp.configured_engine() is None
    path=tmp_path/"engine"
    monkeypatch.setenv(mp12_chkp.ENGINE_ENV,str(path))
    assert mp12_chkp.configured_engine()==path.resolve()


def test_missing_sage_advertises_unavailable_and_never_imports_provider(monkeypatch):
    monkeypatch.setattr(mp12_chkp,"sage_available",lambda:False)
    def forbidden(*args):raise AssertionError("unavailable backend imported its provider")
    monkeypatch.setattr(mp12_chkp,"import_module",forbidden)
    spec=mp12_chkp.default_backend_spec()
    assert not spec.available and spec.factory is None and "SageMath" in spec.reason


def test_missing_engine_still_constructs_a_restore_capable_real_backend(monkeypatch):
    if not research.sage_available():pytest.skip("prescribed Sage needed for actual backend construction")
    monkeypatch.delenv(mp12_chkp.ENGINE_ENV,raising=False)
    spec=mp12_chkp.default_backend_spec()
    assert spec.available
    backend=spec.factory(None,"reference")
    with pytest.raises(InvalidParameterError,match="before entropy"):
        backend.setup(spec.presets["n2-reference"],rng=NoEntropy())


class NoEntropy:
    def read(self,count):raise AssertionError("missing dependency consumed entropy")


def test_default_registry_includes_optional_descriptor_without_aliasing_chkp(monkeypatch):
    from ibme.assembly import default_registry
    monkeypatch.delenv(mp12_chkp.ENGINE_ENV,raising=False)
    registry=default_registry()
    assert registry.get("hibe",mp12_chkp.BACKEND_ID).available is research.sage_available()
    assert not registry.get("hibe","chkp").available
    assert registry.get("hibe","abb10").available


def test_public_tools_are_same_provider_objects_not_forked_implementations():
    if not research.sage_available():pytest.skip("prescribed Sage needed for actual provider identity")
    for name in ("FirstFiniteGaussian","FirstFiniteGPV","FiniteDelTrap","ComputationalRootGenerator"):
        module,attribute=research._PROVIDERS[name]
        assert getattr(research,name) is getattr(importlib.import_module(module),attribute)
    from ibme.hibe.mp12_chkp import MP12CHKPResearchHIBE,MP12HIBEParams
    from experiments.research.first_suite.hibe_reference import MP12CHKPResearchHIBE as Original
    assert MP12CHKPResearchHIBE is Original
    assert MP12HIBEParams().security_claim=="none"
