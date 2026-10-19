"""Public paper-route selection and capacity checks, without sampled secrets."""
from dataclasses import asdict, replace
import importlib
import importlib.util
import json
import subprocess
import sys

import pytest

from ibme.assembly import BackendRegistry, default_registry, make_suite, validate_suite
from ibme.core.errors import InvalidParameterError


def registration():
    name = 'ibme.ibs.srgg.paper_registration'
    assert importlib.util.find_spec(name) is not None, 'paper SRGG has no public adapter'
    return importlib.import_module(name)


def test_paper_route_has_its_own_default_registration_without_replacing_degree8():
    reg = registration()
    registry = default_registry()
    paper = registry.get('ibs', 'srgg2025-paper')
    assert paper.version == reg.VERSION
    assert set(paper.presets) == {'PARAM-I', 'PARAM-II', 'PARAM-III'}
    assert paper.signature_formats == ('reference', 'compact')
    assert registry.get('ibs', 'srgg2025').version == 'SRGG-zeta2-research-v1'
    assert paper.persistent_identity_cache and paper.available
    from ibme.assembly.catalog import algorithm_catalog
    catalog = algorithm_catalog(registry=registry)
    assert catalog['counts'] == {'hibe': 8, 'ibs': 11}
    route = next(row for row in catalog['routes'] if row['id'] == 'srgg2025')
    assert 'srgg2025-paper' in route['backend_ids']


def test_fresh_discovery_imports_no_sage_arithmetic_and_reads_no_entropy():
    registration()
    script = '''import builtins,importlib.util,os,sys
real_find=importlib.util.find_spec
importlib.util.find_spec=lambda name,*a,**kw: None if name=='sage' else real_find(name,*a,**kw)
real_import=builtins.__import__
def guarded(name,*args,**kwargs):
    if name=='sage.all': raise AssertionError('discovery imported Sage arithmetic')
    return real_import(name,*args,**kwargs)
builtins.__import__=guarded
from ibme.core.randomness import SecureRandom
def forbidden(*args,**kwargs): raise AssertionError('discovery read entropy')
SecureRandom.read=forbidden;os.urandom=forbidden
from ibme.assembly import default_registry,make_suite
registry=default_registry()
assert registry.get('ibs','srgg2025-paper').available
for name in ('PARAM-I','PARAM-II','PARAM-III'):
    config=make_suite(hibe='latte',hibe_params='seed32',ibs='srgg2025-paper',ibs_params=name,transport='hybrid',signature_format='compact')
    assert config.to_dict()['ibs_params']['profile_name']==name
assert 'sage.all' not in sys.modules
'''
    result = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_missing_optional_candidate_does_not_break_other_backends(monkeypatch):
    registration()  # Cached adapters must still respect an absent provider.
    import builtins
    original = builtins.__import__
    def absent(name, *args, **kwargs):
        if name.startswith('experiments.research.candidates'):
            raise ModuleNotFoundError('candidate package absent', name='experiments.research.candidates')
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', absent)
    registry = default_registry()
    paper = registry.get('ibs', 'srgg2025-paper')
    assert not paper.available and 'not registered' in paper.reason
    assert registry.get('ibs', 'luo-module').available
    assert validate_suite(make_suite(registry=registry), registry=registry).ok


@pytest.mark.parametrize('profile', ['PARAM-I', 'PARAM-II', 'PARAM-III'])
@pytest.mark.parametrize('fmt', ['reference', 'compact'])
def test_fixed_paper_params_roundtrip_and_capacity_without_setup(monkeypatch, profile, fmt):
    reg = registration()
    spec = reg.backend_spec()
    params = spec.presets[profile]
    assert spec.parse_params(asdict(params)) == params
    assert params.identity_max_bytes == 4096 and params.message_max_bytes == 65536
    assert params.profile_name == profile and params.interpretation == 'table-standard-deviation'
    def forbidden(*args, **kwargs): pytest.fail('preflight executed a backend')
    registry = default_registry()
    hs = replace(registry.get('hibe','latte'), factory=forbidden, validate_environment=lambda:None)
    ins = replace(spec, factory=forbidden, validate_environment=lambda:None)
    isolated = BackendRegistry([hs,ins])
    config = make_suite(hibe='latte',hibe_params='seed32',ibs=spec.id,ibs_params=profile,
                        transport='hybrid',signature_format=fmt,registry=isolated,
                        hybrid_limits={'backend_id':hs.version,'identity_max_bytes':64,
                                       'max_payload_bytes':131072,'max_capsule_bytes':4194304})
    result = validate_suite(config,registry=isolated)
    assert result.ok, result.errors
    assert result.capacity['identity_bytes'] == 64
    assert result.capacity['max_application_bytes'] >= 1024
    assert result.capacity['signature_max_bytes'] == spec.signature_size(params,fmt)
    assert result.metadata['security_claim'] == 'none'
    assert not result.metadata['backend_admitted'] and not result.metadata['parameters_are_formal']


@pytest.mark.parametrize('bad', [None, {}, {'profile_name':'PARAM-I'},
    {'profile_name':'PARAM-I','interpretation':'table-standard-deviation','degree':8},
    {'profile_name':'PARAM-IV','interpretation':'table-standard-deviation'},
    {'profile_name':'PARAM-I','interpretation':'automatic'}])
def test_parameter_snapshot_rejects_missing_unknown_or_implicit_fields(bad):
    with pytest.raises((InvalidParameterError,TypeError,ValueError)):
        registration().backend_spec().parse_params(bad)


def test_formats_and_preset_never_fall_back():
    reg=registration();spec=reg.backend_spec()
    with pytest.raises(InvalidParameterError):spec.signature_size(spec.presets['PARAM-I'],'canonical-json-v1')
    with pytest.raises(InvalidParameterError):spec.factory(None,'unknown')
    with pytest.raises(InvalidParameterError):
        make_suite(hibe='latte',ibs=spec.id,ibs_params='research',transport='hybrid')
