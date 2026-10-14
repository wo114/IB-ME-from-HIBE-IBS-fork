"""A-owned descriptor fits the existing assembly without editing its registry."""
import os
import pytest
pytest.importorskip('sage.all',reason='prescribed WSL Sage required')
from ibme.assembly import BackendRegistry,default_registry,make_suite,validate_suite,build_runtime
from ibme.hibe.abb_rom.registration import backend_spec
from ibme.hibe.abb_rom.profiles import q26_level_quality_research_params
from ibme.ibs.luo_module_profiles import c64b_params


def test_explicit_q26_proposal_builds_without_private_entropy():
    if not os.environ.get('IBME_EXACT_GRAM_EXECUTABLE'):
        pytest.skip('explicit built native dependency required')
    registry=BackendRegistry([backend_spec(),default_registry().get('ibs','luo-module')])
    suite=make_suite(hibe='abb-rom-finite',ibs='luo-module',ibs_params=c64b_params(),
                     transport='hybrid',signature_format='compact',registry=registry)
    report=validate_suite(suite,registry=registry)
    assert report.ok,report.errors
    assert report.capacity['inner_hibe_payload_bytes']==32
    assert report.capacity['inner_hibe_identity_bytes']==86
    assert report.capacity['inner_hibe_ciphertext_max_bytes']==215050
    assert report.metadata['security_claim']=='none' and report.metadata['backend_admitted'] is False
    class Forbidden:
        def read(self,count):raise AssertionError('public assembly consumed private entropy')
    runtime=build_runtime(suite,registry=registry,ibs_rng=Forbidden(),ots_rng=Forbidden())
    assert runtime.hibe_params.inner_params==q26_level_quality_research_params()
    assert set(runtime.decoders)=={'hpk','hmsk','sk1','sk2','ipk','imsk','sk'}


def test_missing_native_dependency_rejects_before_factories(monkeypatch):
    monkeypatch.delenv('IBME_EXACT_GRAM_EXECUTABLE',raising=False)
    registry=BackendRegistry([backend_spec(),default_registry().get('ibs','luo-module')])
    suite=make_suite(hibe='abb-rom-finite',ibs='luo-module',ibs_params=c64b_params(),
                     transport='hybrid',signature_format='compact',registry=registry)
    report=validate_suite(suite,registry=registry)
    assert not report.ok and 'runtime dependency' in ' '.join(report.errors)
