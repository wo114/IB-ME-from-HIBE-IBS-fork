"""C primitive discovery and selection gates, without cryptographic stand-ins."""
from dataclasses import replace
import json
import subprocess
import sys

import pytest

from ibme.assembly import default_registry,BackendRegistry,make_suite,validate_suite,build_runtime
from ibme.core.errors import InvalidParameterError
from ibme.ibs.certified.params import CertifiedIBSParams
from ibme.ibs.certified.mldsa import NativeFailure


def test_c_routes_are_registered_separately_from_runtime_and_admission():
    registry=default_registry()
    from ibme.hibe.latte.registration import backend_spec
    assert registry.get("hibe","latte").factory is backend_spec().factory
    assert registry.get("hibe","latte").two_level
    assert set(registry.get("ibs","cert-ml-dsa").presets)=={"ml-dsa-44","ml-dsa-65","ml-dsa-87"}
    assert set(registry.get("ibs","cert-falcon").presets)=={"falcon-padded-512","falcon-padded-1024"}
    assert registry.get("hibe","lai-ideal-hibe").available
    assert registry.get("hibe","lai-ideal-hibe").two_level
    assert not registry.get("hibe","zhang2020").available
    assert not registry.get("ibs","xie-ntru-ibs").available
    from ibme.protocol.hybrid_hibe import HybridLimits
    assert HybridLimits(backend_id=backend_spec().version.encode("ascii"))


def test_fresh_discovery_does_not_import_sage_arithmetic_or_read_key_entropy():
    script="""import builtins,json,os,sys
original=builtins.__import__
def guarded(name,*args,**kwargs):
    if name=='sage.all':raise AssertionError('discovery imported Sage arithmetic')
    return original(name,*args,**kwargs)
builtins.__import__=guarded
from ibme.core.randomness import SecureRandom
def forbidden(*args,**kwargs):raise AssertionError('discovery consumed entropy')
SecureRandom.read=forbidden;os.urandom=forbidden
from ibme.assembly.catalog import algorithm_catalog
from ibme.assembly import list_backends
rows={r['id']:r for r in algorithm_catalog()['routes']}
for name in ('latte','cert-ml-dsa','cert-falcon'):
    assert rows[name]['adapter_available'] and rows[name]['execution']=='not_executed'
assert 'sage.all' not in sys.modules
print(json.dumps({'status':'passed','registered':3,'arithmetic_imported':False}))
"""
    result=subprocess.run([sys.executable,"-c",script],capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr
    assert json.loads(result.stdout)["registered"]==3


@pytest.mark.parametrize("route,profile",[("cert-ml-dsa","ml-dsa-65"),("cert-falcon","falcon-padded-512")])
def test_missing_selected_profile_rejected_even_when_default_engine_exists(monkeypatch,route,profile):
    from ibme.ibs.certified import registration as registration
    def ordinary(params):
        if params.base_algorithm==profile:raise NativeFailure("selected binary absent")
        return object()
    def forbidden(*args,**kwargs):pytest.fail("invalid selection reached setup or entropy")
    monkeypatch.setattr(registration,"ordinary",ordinary)
    monkeypatch.setattr(registration,"environment",lambda:None)
    monkeypatch.setattr(registration,"falcon_environment",lambda:None)
    registry=default_registry();spec=registry.get("ibs",route)
    isolated=BackendRegistry((registry.get("hibe","mock"),replace(spec,factory=forbidden)))
    config=make_suite(hibe="mock",ibs=route,ibs_params=profile,allow_mock=True,registry=isolated)
    report=validate_suite(config,registry=isolated)
    assert not report.ok and any("selected binary absent" in error for error in report.errors)
    with pytest.raises(InvalidParameterError):build_runtime(config,registry=isolated)


@pytest.mark.parametrize("route,profile",[("cert-ml-dsa","falcon-padded-512"),("cert-falcon","ml-dsa-44")])
def test_cross_family_profile_never_falls_back(route,profile):
    config=make_suite(hibe="latte",ibs=route,ibs_params=CertifiedIBSParams(base_algorithm=profile),transport="hybrid")
    report=validate_suite(config)
    assert not report.ok and any(route+" requires" in error for error in report.errors)


@pytest.mark.parametrize("route,profile,constructor",[
    ("cert-ml-dsa","ml-dsa-65","MLDSA"),
    ("cert-falcon","falcon-padded-512","Falcon"),
])
def test_selected_profile_works_without_the_default_family_binary(monkeypatch,route,profile,constructor):
    from ibme.ibs.certified import registration
    checked=[]
    def available(algorithm):
        checked.append(algorithm)
        if algorithm!=profile:raise NativeFailure("unselected engine absent")
        return object()
    monkeypatch.setattr(registration,constructor,available)
    monkeypatch.setattr(registration,"ordinary",lambda params:available(params.base_algorithm))
    registry=default_registry()
    config=make_suite(hibe="mock",ibs=route,ibs_params=profile,allow_mock=True,registry=registry)
    report=validate_suite(config,registry=registry)
    assert report.ok,report.errors
    assert profile in checked and report.metadata["runtime_available"]
    assert build_runtime(config,registry=registry).ibs_params.base_algorithm==profile


def test_latte_environment_gate_precedes_arithmetic(monkeypatch):
    from ibme.hibe.latte import registration
    monkeypatch.setattr(registration.importlib.util,"find_spec",lambda name:None)
    monkeypatch.setattr("ibme.hibe.latte.engine.Native",lambda *args:pytest.fail("missing Sage reached native probe"))
    with pytest.raises(InvalidParameterError,match="WSL"):registration.environment()


def test_invalid_hybrid_version_rejected_during_preflight():
    registry=default_registry()
    bad=replace(registry.get("hibe","mock"),version="INVALID/transport")
    isolated=BackendRegistry((bad,registry.get("ibs","mock")))
    config=make_suite(hibe="mock",ibs="mock",transport="hybrid",allow_mock=True,registry=isolated)
    result=validate_suite(config,registry=isolated)
    assert not result.ok and any("hybrid backend identifier" in error for error in result.errors)
