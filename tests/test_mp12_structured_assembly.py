"""Structured variant discovery/selection without importing private arithmetic."""

import json
import subprocess
import sys
import pytest
from ibme.assembly import default_registry, make_suite, validate_suite, build_runtime
from ibme.assembly.catalog import algorithm_catalog
from ibme.core.errors import InvalidParameterError
from ibme.core.randomness import SecureRandom
from ibme.hibe.mp12_structured import registration
from ibme.hibe.mp12_structured.params import StructuredHIBEParams


def test_distinct_profile_preserves_nineteen_algorithm_routes_and_security_flags():
    registry = default_registry(); spec = registry.get("hibe", "mp12-structured-hg")
    assert spec.factory is registration.factory and spec.available
    assert spec.two_level and spec.key_binding and spec.persistent_identity_cache
    config = make_suite(hibe="mp12-structured-hg", ibs="luo-module", transport="hybrid", signature_format="compact")
    p = config.to_dict()
    assert p["hibe_params"] == dict(n=2, q=549755813911, root_r_squared=16, q_alpha=4, identity_bytes=86, max_receivers=2, max_children=2)
    assert (p["security_claim"], p["backend_admitted"], p["parameters_are_formal"]) == ("none", False, False)
    rows = algorithm_catalog(registry=registry)
    assert rows["counts"] == {"hibe":8,"ibs":11}
    assert next(r for r in rows["routes"] if r["id"]=="chkp-rom")["backend_ids"] == ["chkp","mp12-chkp-reference","mp12-structured-hg"]


def test_fresh_discovery_never_imports_structured_arithmetic_or_entropy():
    source = """import builtins,sys,json
original=builtins.__import__
def guarded(name,*args,**kwargs):
    if name=='sage.all':raise AssertionError('discovery imported Sage arithmetic')
    return original(name,*args,**kwargs)
builtins.__import__=guarded
from ibme.core.randomness import SecureRandom
def forbidden(*a,**k):raise AssertionError('discovery consumed entropy')
SecureRandom.read=forbidden
from ibme.assembly import list_backends
assert next(r for r in list_backends()['hibe'] if r['id']=='mp12-structured-hg')['available']
assert 'ibme.lattice.matrix_sampling.mp12_structured' not in sys.modules
assert 'sage.all' not in sys.modules
print(json.dumps({'status':'passed'}))
"""
    completed = subprocess.run([sys.executable,"-c",source],capture_output=True,text=True,timeout=30)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["status"] == "passed"


def test_missing_sage_fails_before_factory_entropy_and_state(monkeypatch,tmp_path):
    from ibme import cli
    def forbidden(*a, **k): pytest.fail("bad runtime reached factory or entropy")
    monkeypatch.setattr(registration,"sage_available",lambda:False)
    monkeypatch.setattr(registration,"factory",forbidden)
    monkeypatch.setattr(SecureRandom,"read",forbidden)
    config = make_suite(hibe="mp12-structured-hg",ibs="sis",transport="hybrid")
    assert not validate_suite(config).ok
    with pytest.raises(InvalidParameterError): build_runtime(config)
    state = tmp_path/"absent"
    assert cli.main(["setup","--state",str(state),"--hibe","mp12-structured-hg","--ibs","sis","--transport","hybrid"]) == 2
    assert not state.exists()


def test_direct_transport_rejected_before_arithmetic(monkeypatch):
    monkeypatch.setattr(registration,"environment",lambda:pytest.fail("invalid transport reached Sage"))
    with pytest.raises(InvalidParameterError,match="hybrid"):
        registration.configuration(StructuredHIBEParams(),dict(transport="direct"))
