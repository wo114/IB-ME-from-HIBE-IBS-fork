"""Probe bookkeeping fixtures only; cryptographic evidence is the real run JSON."""
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/research'))
import luo_candidate_probe as probe


class Wire:
    def to_bytes(self):
        return b'fixture-not-a-key-or-signature'


class Signature(Wire):
    z, c, w1, h = (1,), (2,), (3,), (4,)


class Compact(Wire):
    def __init__(self, signature):
        self.signature = signature


def install_fixtures(monkeypatch, *, setup_error=False, sign_abort=False, verify_error=False):
    class Engine:
        last_extract_attempts = 0
        last_sign_attempts = 0
        count = 0
        def __init__(self, rng):
            self.rng = rng
        def setup(self, p):
            if setup_error:
                raise RuntimeError('injected-setup-failure')
            return Wire(), Wire()
        def key_extract(self, master, identity):
            self.last_extract_attempts = 0 if isinstance(self.rng, probe.NoEntropy) else 1
            return Wire()
        def sign(self, key, message):
            Engine.count += 1
            self.last_sign_attempts = 3
            if sign_abort and Engine.count == 1:
                raise probe.LuoModuleSamplingAbort('injected-sign-abort')
            return Signature()
        def load_signature(self, pk, wire):
            return Signature()
        def verify(self, *args):
            return not verify_error
    class CompactEngine(Engine):
        def load_signature(self, pk, wire):
            return Compact(Signature())
    monkeypatch.setattr(probe, 'LuoModuleIBSBackend', Engine)
    monkeypatch.setattr(probe, 'LuoModuleCompactIBSBackend', CompactEngine)
    monkeypatch.setattr(probe, 'LuoModuleCompactSignature', Compact)
    monkeypatch.setattr(probe, 'LuoModuleMasterSecret', SimpleNamespace(from_bytes=lambda raw: Wire()))
    monkeypatch.setattr(probe, 'hashes', lambda: {'fixture': 'not-source-evidence'})
    monkeypatch.setattr(probe.subprocess, 'check_output', lambda *a, **kw: 'fixture-not-a-commit')


def test_planned_denominator_includes_all_54_calls():
    rows = probe.units()
    assert len(rows) == len({(r['system'],r['identity_len'],r['message_len'],r['repetition']) for r in rows}) == 54
    assert all(r['status']=='not_run' and not r['called'] for r in rows)


def test_fixture_success_does_not_grant_security_or_crypto_evidence(monkeypatch, tmp_path):
    install_fixtures(monkeypatch)
    r = probe.run(tmp_path/'out', 'availability-candidate')
    assert r['metadata']['completed'] and r['metadata']['successful_sign_calls'] == 54
    assert len(r['stages']) == 30 and all(x['status']=='ok' for x in r['stages'])
    assert r['metadata']['security_claim'] == 'none' and not r['metadata']['parameters_are_formal']
    assert all(c['reference_verify'] and c['compact_verify'] for c in r['calls'])


@pytest.mark.parametrize('kind,called,success', [('setup',0,0),('sign',54,53),('verify',1,0)])
def test_failed_runs_keep_planned_rows_and_abort_timing(monkeypatch, tmp_path, kind, called, success):
    install_fixtures(monkeypatch, setup_error=kind=='setup', sign_abort=kind=='sign', verify_error=kind=='verify')
    with pytest.raises((ValueError,RuntimeError)):
        probe.run(tmp_path/'out', 'availability-candidate')
    r=json.loads((tmp_path/'out/probe.json').read_text())
    assert len(r['calls'])==54 and not r['metadata']['completed']
    assert r['metadata']['attempted_sign_calls']==called and r['metadata']['successful_sign_calls']==success
    for c in r['calls']:
        assert (c['sign_seconds'] is not None) == c['called']
        if c['called']:
            assert c['sign_attempts']==3
    if kind=='sign':
        assert r['calls'][0]['error_type']=='LuoModuleSamplingAbort'


def test_probe_does_not_overwrite_existing_output(monkeypatch, tmp_path):
    install_fixtures(monkeypatch)
    output=tmp_path/'out'
    output.mkdir()
    with pytest.raises(FileExistsError):
        probe.run(output, 'availability-candidate')
    assert not list(output.iterdir())
