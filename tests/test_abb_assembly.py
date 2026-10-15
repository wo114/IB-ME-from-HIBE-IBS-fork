"""Public ABB registration, discovery and failure-before-entropy boundaries."""
from dataclasses import replace
import json
import subprocess
import sys

import pytest

from ibme.assembly import default_registry,make_suite,validate_suite,build_runtime
from ibme.assembly.catalog import algorithm_catalog
from ibme.core.errors import InvalidParameterError
from ibme.core.randomness import SecureRandom
from ibme.hibe.abb_rom import registration
from ibme.hibe.abb_rom.profiles import q26_level_quality_research_params


def test_real_abb_and_legacy_teaching_backend_are_separate():
    registry=default_registry();spec=registry.get("hibe","abb-rom")
    assert spec.available and spec.factory is registration.factory
    assert spec.factory is not registry.get("hibe","abb10").factory
    assert spec.default_preset("hybrid")=="n1-q26-level-quality-research"
    assert spec.two_level and spec.key_binding and spec.persistent_identity_cache
    config=make_suite(hibe="abb-rom",ibs="luo-module",transport="hybrid",signature_format="compact")
    assert config.to_dict()["hibe_params"]==q26_level_quality_research_params().to_record()
    fields=config.to_dict()
    assert fields["security_claim"]=="none" and not fields["backend_admitted"] and not fields["parameters_are_formal"]
    catalog=algorithm_catalog(registry=registry)
    row=next(r for r in catalog["routes"] if r["id"]=="abb-rom")
    assert row["backend_ids"]==["abb-rom","abb10"] and catalog["counts"]=={"hibe":8,"ibs":11}


def test_fresh_discovery_never_loads_abb_arithmetic_or_entropy():
    code="""import builtins,sys,json
original=builtins.__import__
def guarded(name,*args,**kwargs):
    if name=='sage.all':raise AssertionError('discovery imported arithmetic')
    return original(name,*args,**kwargs)
builtins.__import__=guarded
from ibme.core.randomness import SecureRandom
def forbidden(*args,**kwargs):raise AssertionError('discovery consumed private entropy')
SecureRandom.read=forbidden
from ibme.assembly import list_backends
rows=list_backends()['hibe']
assert next(r for r in rows if r['id']=='abb-rom')['available']
assert 'ibme.hibe.abb_rom.backend' not in sys.modules and 'sage.all' not in sys.modules
print(json.dumps({'status':'passed'}))
"""
    result=subprocess.run([sys.executable,"-c",code],capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr
    assert json.loads(result.stdout)["status"]=="passed"


def test_missing_sage_rejected_before_factory_entropy_or_state(monkeypatch,tmp_path):
    from ibme import cli
    def forbidden(*args,**kwargs):pytest.fail("missing runtime reached generation or entropy")
    monkeypatch.setattr(registration,"sage_available",lambda:False)
    monkeypatch.setattr(registration,"factory",forbidden)
    monkeypatch.setattr(SecureRandom,"read",forbidden)
    config=make_suite(hibe="abb-rom",ibs="sis",transport="hybrid")
    report=validate_suite(config)
    assert not report.ok and "sage" in " ".join(report.errors).lower()
    with pytest.raises(InvalidParameterError):build_runtime(config)
    state=tmp_path/"absent"
    assert cli.main(["setup","--state",str(state),"--hibe","abb-rom","--ibs","sis","--transport","hybrid"])==2
    assert not state.exists()


def test_direct_abb_selection_is_rejected_before_arithmetic(monkeypatch):
    monkeypatch.setattr(registration,"environment",lambda:pytest.fail("bad transport reached profile arithmetic"))
    with pytest.raises(InvalidParameterError,match="hybrid"):
        registration.validate_configuration(q26_level_quality_research_params(),{"transport":"direct"})


def test_abb_parameters_and_wire_capacity_are_exact_and_portable():
    p=q26_level_quality_research_params();spec=registration.backend_spec()
    assert spec.parse_params(p.to_record())==p
    assert spec.ciphertext_size(p,32,86)==215050
    for changed in (dict(security_claim="secure"),dict(backend_admitted=True),dict(parameters_are_formal=True)):
        with pytest.raises(InvalidParameterError):replace(p,**changed)
