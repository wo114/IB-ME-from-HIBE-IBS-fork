"""Driver control-flow fixtures only: no key generation or real sampling."""

import json
from hashlib import sha256
from types import SimpleNamespace

import pytest

from experiments.research import chkp_combination as combination
from experiments.research import chkp_lifecycle as lifecycle
from ibme.cli_state import key_issuance_lock


def save_json(path, value):
    path.write_text(json.dumps(value), encoding='utf-8')


def forbid(*args, **kwargs):
    raise AssertionError('guard crossed into key generation or entropy')


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """Synthetic ignored workspace; subprocess stub performs no Git mutation."""
    for module in (lifecycle, combination):
        monkeypatch.setattr(module, 'BASE', tmp_path)
        monkeypatch.setattr(module.subprocess, 'run',
                            lambda *a, **k: SimpleNamespace(returncode=0))
    directory = tmp_path / 'test-results' / 'combination'
    lifetime = tmp_path / 'test-results' / 'lifetime'
    directory.mkdir(parents=True)
    lifetime.mkdir()
    config = SimpleNamespace(digest='public-fixture-digest', to_json=lambda: '{"fixture":true}')
    monkeypatch.setattr(combination, 'preflight', lambda: {'passed': True})
    monkeypatch.setattr(combination, 'selected_suite', lambda *a: config)
    monkeypatch.setattr(combination, 'build_runtime', forbid)
    for phase in ('setup', 'parent', 'leaf'):
        save_json(lifetime / (phase + '.json'), {'phase': phase, 'passed': True})
    (directory / 'suite.json').write_text(config.to_json(), encoding='utf-8')
    return directory, lifetime, config


def ready(directory, config, phase='prepare'):
    names = {'prepare': ['existing_Bob_Alice_leaf_reused', 'real_C64B_setup_and_sender'],
             'receiver-Carol': ['address_completed']}.get(
                 phase, ['new_leaf_canonical_restore', 'address_completed'])
    receipt = dict(phase=phase, passed=True, suite_digest=config.digest,
                   checks=[dict(name=name, passed=True) for name in names],
                   executed_checks=len(names))
    save_json(directory / (phase + '.json'), receipt)
    return receipt


def call_combination(directory, lifetime, phase='prepare'):
    return combination.main([phase, '--directory', str(directory), '--lifetime', str(lifetime)])


def call_lifecycle(directory, phase):
    return lifecycle.main([phase, '--directory', str(directory)])


@pytest.mark.parametrize('module', [combination, lifecycle])
def test_private_directory_requires_git_ignore(workspace, monkeypatch, module):
    directory, _, _ = workspace
    monkeypatch.setattr(module.subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=1))
    with pytest.raises(ValueError, match='not ignored'):
        module.private_directory(directory)


@pytest.mark.parametrize('module', [combination, lifecycle])
def test_private_directory_rejects_outside_or_shared_root(workspace, module):
    for value in (module.BASE, module.BASE / 'test-results', module.BASE / 'outside'):
        with pytest.raises(ValueError):
            module.private_directory(value)


def test_ready_combination_is_reused_without_runtime_or_entropy(workspace, monkeypatch, capsys):
    directory, lifetime, config = workspace
    previous = ready(directory, config)
    monkeypatch.setattr(combination, 'CountedSystem', forbid)
    before = (directory / 'prepare.json').read_bytes()
    assert call_combination(directory, lifetime) == 0
    output = json.loads(capsys.readouterr().out)
    assert output == {'event': 'ready_phase_reused', 'receipt': previous}
    assert (directory / 'prepare.json').read_bytes() == before
    assert not list(directory.glob('*.pending'))


@pytest.mark.parametrize('phase', ['prepare', 'leaf-Bob-Eve'])
def test_other_pending_blocks_ready_reuse_and_independent_address(workspace, monkeypatch, phase):
    directory, lifetime, config = workspace
    ready(directory, config)
    (directory / 'receiver-Carol.pending').write_bytes(b'failed sampler')
    (directory / 'master.bin').write_bytes(b'opaque-master-fixture')
    monkeypatch.setattr(combination, 'CountedSystem', forbid)
    with pytest.raises(SystemExit) as exc:
        call_combination(directory, lifetime, phase)
    assert exc.value.code == 2
    assert (directory / 'master.bin').read_bytes() == b'opaque-master-fixture'
    assert sorted(p.name for p in directory.glob('*.pending')) == ['receiver-Carol.pending']


@pytest.mark.parametrize('change', [
    {'checks': [], 'executed_checks': 0}, {'executed_checks': True},
    {'executed_checks': 1}, {'passed': 1}, {'phase': 'checks'},
    {'suite_digest': 'old-suite'}, {'checks': [{'name': 'fake', 'passed': True}], 'executed_checks': 1},
])
def test_bad_ready_receipt_never_reports_success(workspace, change):
    directory, lifetime, config = workspace
    receipt = ready(directory, config)
    receipt.update(change)
    save_json(directory / 'prepare.json', receipt)
    with pytest.raises(SystemExit) as exc:
        call_combination(directory, lifetime)
    assert exc.value.code == 2
    assert not list(directory.glob('*.pending'))


def test_saved_suite_checked_before_ready_reuse(workspace):
    directory, lifetime, config = workspace
    ready(directory, config)
    (directory / 'suite.json').write_bytes(b'other-suite')
    with pytest.raises(SystemExit):
        call_combination(directory, lifetime)


def test_failed_other_receipt_without_marker_still_blocks(workspace):
    directory, lifetime, config = workspace
    ready(directory, config)
    save_json(directory / 'receiver-Carol.json', {'phase': 'receiver-Carol', 'passed': False})
    with pytest.raises(SystemExit):
        call_combination(directory, lifetime)


def test_ready_leaf_requires_prepare_receipt(workspace):
    directory, lifetime, config = workspace
    ready(directory, config, 'leaf-Bob-Eve')
    with pytest.raises(SystemExit):
        call_combination(directory, lifetime, 'leaf-Bob-Eve')


@pytest.mark.parametrize('bad_source', ['pending', 'missing-setup', 'wrong-phase', 'failed-leaf'])
def test_prepare_requires_complete_successful_source(workspace, bad_source):
    directory, lifetime, _ = workspace
    if bad_source == 'pending':
        (lifetime / 'roundtrip.pending').write_bytes(b'pending')
    elif bad_source == 'missing-setup':
        (lifetime / 'setup.json').unlink()
    elif bad_source == 'wrong-phase':
        save_json(lifetime / 'parent.json', {'phase': 'leaf', 'passed': True})
    else:
        save_json(lifetime / 'leaf.json', {'phase': 'leaf', 'passed': False})
    with pytest.raises(SystemExit):
        call_combination(directory, lifetime)
    assert not (directory / 'prepare.pending').exists()


@pytest.mark.parametrize('locked_source', [False, True])
def test_combination_busy_or_reentrant_writer_stops_before_marker(workspace, locked_source):
    directory, lifetime, _ = workspace
    with key_issuance_lock(lifetime if locked_source else directory):
        with pytest.raises(SystemExit) as exc:
            call_combination(directory, lifetime)
    assert exc.value.code == 2
    assert not (directory / 'prepare.pending').exists()


def test_combination_failure_keeps_pending_and_redacts_exception(workspace, monkeypatch, capsys):
    directory, lifetime, _ = workspace
    (directory / 'suite.json').unlink()

    def fail_runtime(*a, **k):
        raise RuntimeError('PRIVATE_SENTINEL_opaque_secret')

    monkeypatch.setattr(combination, 'build_runtime', fail_runtime)
    assert call_combination(directory, lifetime) == 2
    receipt = json.loads((directory / 'prepare.json').read_bytes())
    assert receipt['passed'] is False and receipt['executed_checks'] == 0
    assert receipt['failure_type'] == 'RuntimeError'
    assert (directory / 'prepare.pending').exists()
    output = capsys.readouterr()
    assert 'PRIVATE_SENTINEL' not in output.out + output.err + json.dumps(receipt)


@pytest.mark.parametrize('rows', [[], [{'name': 'invented', 'passed': True}]])
def test_no_checks_or_incomplete_checks_cannot_pass(workspace, monkeypatch, rows):
    directory, lifetime, _ = workspace
    (directory / 'suite.json').unlink()
    monkeypatch.setattr(combination, 'build_runtime', lambda *a, **k: object())
    monkeypatch.setattr(combination, 'prepare', lambda runtime, directory, lifetime, source, receipt:
                        receipt['checks'].extend(rows))
    assert call_combination(directory, lifetime) == 2
    assert json.loads((directory / 'prepare.json').read_bytes())['passed'] is False
    assert (directory / 'prepare.pending').exists()


def test_lifecycle_writer_reentry_stops_before_marker(workspace):
    _, lifetime, _ = workspace
    with key_issuance_lock(lifetime):
        with pytest.raises(SystemExit) as exc:
            call_lifecycle(lifetime, 'roundtrip')
    assert exc.value.code == 2
    assert not (lifetime / 'roundtrip.pending').exists()


@pytest.mark.parametrize('problem', ['wrong-phase', 'missing-setup', 'other-pending'])
def test_lifecycle_requires_full_ready_prefix(workspace, monkeypatch, problem):
    _, lifetime, _ = workspace
    monkeypatch.setattr(lifecycle, 'CountedSystem', forbid)
    if problem == 'wrong-phase':
        save_json(lifetime / 'setup.json', {'phase': 'parent', 'passed': True})
    elif problem == 'missing-setup':
        (lifetime / 'setup.json').unlink()
    else:
        (lifetime / 'parent.pending').write_bytes(b'pending')
    with pytest.raises(SystemExit):
        call_lifecycle(lifetime, 'roundtrip')
    assert not (lifetime / 'roundtrip.pending').exists()


def test_lifecycle_setup_failure_is_redacted_and_not_retryable(workspace, monkeypatch, capsys):
    import ibme.hibe.chkp as chkp
    _, lifetime, _ = workspace
    directory = lifetime.parent / 'new-lifetime'

    class FailingBackend:
        def setup(self, *a, **k):
            raise RuntimeError('PRIVATE_SENTINEL_opaque_secret')

    monkeypatch.setattr(chkp, 'CHKPHIBE', FailingBackend)
    assert call_lifecycle(directory, 'setup') == 2
    receipt = json.loads((directory / 'setup.json').read_bytes())
    assert receipt['passed'] is False and receipt['entropy_bytes'] == 0
    assert receipt['failure_type'] == 'RuntimeError'
    assert (directory / 'setup.pending').exists()
    output = capsys.readouterr()
    assert 'PRIVATE_SENTINEL' not in output.out + output.err + json.dumps(receipt)
    with pytest.raises(SystemExit):
        call_lifecycle(directory, 'parent')


def test_lifecycle_leaf_checks_root_parent_correspondence_before_sampling(workspace, monkeypatch):
    import ibme.hibe.chkp as chkp
    from ibme.protocol.hybrid_hibe import HybridLimits, encoded_identity
    _, lifetime, _ = workspace
    (lifetime / 'leaf.json').unlink()
    for name in ('public', 'master', 'parent'):
        (lifetime / (name + '.bin')).write_bytes(b'opaque-fixture')
    parent = SimpleNamespace(identity=encoded_identity(b'Bob', HybridLimits(backend_id=b'chkp'), b'P'),
                             to_bytes=lambda: b'authoritative-parent')
    monkeypatch.setattr(chkp, 'CHKPPublicKey', SimpleNamespace(from_bytes=lambda data: object()))
    monkeypatch.setattr(chkp, 'CHKPMasterSecret', SimpleNamespace(from_bytes=lambda data: object()))
    monkeypatch.setattr(chkp, 'CHKPLevel1SecretKey', SimpleNamespace(from_bytes=lambda data: parent))

    class MismatchedBackend:
        validate_key_binding = staticmethod(lambda *a: True)
        extract = staticmethod(lambda *a, **k: SimpleNamespace(to_bytes=lambda: b'different-cached-parent'))
        derive = staticmethod(forbid)

    monkeypatch.setattr(chkp, 'CHKPHIBE', MismatchedBackend)
    assert call_lifecycle(lifetime, 'leaf') == 2
    receipt = json.loads((lifetime / 'leaf.json').read_bytes())
    assert receipt['passed'] is False and receipt['entropy_bytes'] == 0
    assert receipt['failure_type'] == 'AssertionError'
    assert (lifetime / 'parent.bin').read_bytes() == b'opaque-fixture'
    assert not (lifetime / 'child.bin').exists()


def test_failed_receiver_sampling_saves_changed_master_before_failure_receipt(workspace, monkeypatch):
    directory, lifetime, config = workspace
    ready(directory, config)
    state = {'wire': b'old-master'}
    master = SimpleNamespace(to_bytes=lambda: state['wire'])
    (directory / 'master.bin').write_bytes(state['wire'])

    def failed_extract(*a, **k):
        state['wire'] = b'opaque-failed-address-snapshot'
        raise RuntimeError('PRIVATE_SENTINEL')

    runtime = SimpleNamespace(validate_master=lambda *a: None,
                              proto=SimpleNamespace(rkgen=failed_extract))
    monkeypatch.setattr(combination, 'load_public', lambda *a: object())
    monkeypatch.setattr(combination, 'load_master', lambda *a: master)
    monkeypatch.setattr(combination, 'build_runtime', lambda *a, **k: runtime)
    assert call_combination(directory, lifetime, 'receiver-Carol') == 2
    assert (directory / 'master.bin').read_bytes() == b'opaque-failed-address-snapshot'
    assert (directory / 'receiver-Carol.pending').exists()
    assert not (directory / 'receiver-Carol.bin').exists()
    assert json.loads((directory / 'receiver-Carol.json').read_bytes())['passed'] is False
    with pytest.raises(SystemExit):
        call_combination(directory, lifetime, 'prepare')


@pytest.mark.parametrize('failed_filename', ['suite.json', 'prepare.json'])
def test_write_failure_keeps_pending_and_blocks_retry(workspace, monkeypatch, failed_filename):
    directory, lifetime, _ = workspace
    (directory / 'suite.json').unlink()
    monkeypatch.setattr(combination, 'build_runtime', lambda *a, **k: object())
    monkeypatch.setattr(combination, 'prepare', lambda *a: None)
    original_write = combination.write

    def fail_write(path, data):
        if path.name == failed_filename:
            raise PermissionError('fixture write refused')
        return original_write(path, data)

    monkeypatch.setattr(combination, 'write', fail_write)
    if failed_filename == 'prepare.json':
        with pytest.raises(PermissionError):
            call_combination(directory, lifetime)
    else:
        assert call_combination(directory, lifetime) == 2
    assert (directory / 'prepare.pending').exists()
    with pytest.raises(SystemExit):
        call_combination(directory, lifetime)


@pytest.mark.parametrize('matches_seed', [False, True])
def test_roundtrip_requires_actual_public_attack_hash_match(workspace, monkeypatch, matches_seed):
    import ibme.hibe.chkp as chkp
    import ibme.hibe.chkp.backend as backend_module
    from experiments.attacks import chkp_small_dimension
    from ibme.protocol.hybrid_hibe import HybridLimits, encoded_identity

    _, lifetime, _ = workspace
    for name in ('public', 'master', 'parent', 'child'):
        (lifetime / (name + '.bin')).write_bytes(b'opaque-control-fixture')
    seed = b's' * 32
    public = SimpleNamespace(oracle=object(), params=object())
    parent = SimpleNamespace(identity=encoded_identity(b'Bob', HybridLimits(backend_id=b'chkp'), b'P'),
                             to_bytes=lambda: b'parent')
    child = SimpleNamespace(to_bytes=lambda: b'child')
    capsule = SimpleNamespace(capsule=object(), to_bytes=lambda: b'capsule')
    for name, value in [('CHKPPublicKey', public), ('CHKPMasterSecret', object()),
                        ('CHKPLevel1SecretKey', parent), ('CHKPLevel2SecretKey', child)]:
        monkeypatch.setattr(chkp, name, SimpleNamespace(from_bytes=lambda data, value=value: value))

    class BackendFixture:
        validate_key_binding = staticmethod(lambda *a: True)
        extract = staticmethod(lambda *a, **k: parent)
        derive = staticmethod(lambda *a, **k: child)
        encrypt = staticmethod(lambda *a, **k: capsule)
        decrypt = staticmethod(lambda *a, **k: seed)

    class FixtureRandom:
        bytes_used = 0

        def read(self, size):
            assert size == 32
            self.bytes_used += size
            return seed

    monkeypatch.setattr(chkp, 'CHKPHIBE', BackendFixture)
    monkeypatch.setattr(lifecycle, 'CountedSystem', FixtureRandom)
    monkeypatch.setattr(backend_module, '_noise', lambda params: SimpleNamespace(radius=1))
    monkeypatch.setattr(chkp_small_dimension, 'recover_seed_hashes', lambda *a, **k:
                        {'recovered_seed_sha256': [sha256(seed).hexdigest()] if matches_seed else []})
    assert call_lifecycle(lifetime, 'roundtrip') == (0 if matches_seed else 2)
    receipt = json.loads((lifetime / 'roundtrip.json').read_bytes())
    assert receipt['passed'] is matches_seed
    assert receipt.get('public_attack_matches_seed', False) is matches_seed
    assert (lifetime / 'capsule.bin').exists() is matches_seed
    assert (lifetime / 'roundtrip.pending').exists() is not matches_seed
