"""Explicit research-branch recovery controls; no actual key generation/sample."""
from contextlib import contextmanager
from hashlib import sha256
import json
from types import SimpleNamespace

import pytest

from experiments.research import chkp_resume_pre_entropy as recovery
from experiments.research import chkp_lifecycle as lifecycle
from ibme.cli_state import LOCK_FILE, key_issuance_lock


def save(path, value):
    path.write_text(json.dumps(value), encoding='utf-8')


def load(path):
    return json.loads(path.read_bytes())


def forbidden(*args, **kwargs):
    raise AssertionError('unexpected generation or private mathematical operation')


def preflight(source):
    script = source/'leaf_full_preflight.py'
    script.write_text('# synthetic complete preflight source fixture\n', encoding='utf-8')
    paths = list((recovery.BASE/'src'/'ibme').rglob('*.py')) + [script]
    hashes = {path.relative_to(recovery.BASE).as_posix(): sha256(path.read_bytes()).hexdigest() for path in paths}
    parent_relative = (source/'parent.bin').relative_to(recovery.BASE).as_posix()
    receipt = dict(schema='ibme.chkp.leaf-preflight.v1', passed=True,
        all_gates={key: True for key in recovery.PREFLIGHT_GATES}, targets=256, entropy_bytes=0,
        sample_called=False, state_mutation_called=False, gso_recomputed=False,
        source_parent_unchanged=True, cache_geometry_old_new_ast_unchanged=True,
        source_parent_relative=parent_relative, source_sha256=hashes, source_relative=sorted(hashes),
        private_binding_relative=(source/recovery.BINDING).relative_to(recovery.BASE).as_posix())
    save(source/recovery.PREFLIGHT, receipt)
    save(source/recovery.BINDING, dict(schema='ibme.chkp.leaf-preflight-binding.v1',
        source_parent_relative=parent_relative,
        parent_snapshot_sha256=sha256((source/'parent.bin').read_bytes()).hexdigest(),
        receipt_sha256=sha256((source/recovery.PREFLIGHT).read_bytes()).hexdigest()))


@pytest.fixture
def source(tmp_path, monkeypatch):
    """Opaque IO fixtures; successful history counters are synthetic labels."""
    monkeypatch.setattr(recovery, 'BASE', tmp_path)
    monkeypatch.setattr(lifecycle, 'BASE', tmp_path)
    monkeypatch.setattr(lifecycle.subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=0))
    directory = tmp_path/'test-results'/'r3'
    directory.mkdir(parents=True)
    for name, raw in [('public.bin', b'public-fixture'), ('master.bin', b'master-fixture'),
                      ('parent.bin', b'failed-parent-fixture'), ('leaf.pending', b'old failed attempt'),
                      (LOCK_FILE, b'\0'), ('private_leaf_geometry.pkl', b'NEVER DESERIALIZE THIS FIXTURE')]:
        (directory/name).write_bytes(raw)
    for phase in ('setup', 'parent', 'leaf'):
        receipt = dict(phase=phase, passed=phase != 'leaf', entropy_bytes=0 if phase == 'leaf' else 10,
                       seconds=1.5, security_claim='none', backend_admitted=False, parameters_are_formal=False)
        if phase == 'leaf':
            receipt['failure_type'] = 'ValueError'
        save(directory/(phase+'.json'), receipt)
    save(directory/recovery.DIAGNOSTIC, dict(diagnostic='read_only_original_leaf_preflight',
        entropy_consumed=0, sampler_sample_called=False, state_mutation_called=False,
        private_geometry_printed=False, preflight_passed=False, original_failure_gate_identified=True,
        parent_snapshot_unchanged=True, error_type='ValueError', outcome='preflight_exception',
        safe_error='Scalar squared width outside independent finite profile 1..2^80',
        stack=[{'file': '/fixture/finite_gpv.py', 'function': '__init__', 'line': 197}]))
    for relative in recovery.CODE_INPUTS:
        path = tmp_path/relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('# synthetic source checksum fixture\n', encoding='utf-8')
    preflight(directory)
    @contextmanager
    def no_entropy(api):
        yield {'forbidden_calls': 0}
    monkeypatch.setattr(recovery, '_imports', lambda: {})
    monkeypatch.setattr(recovery, '_no_entropy', no_entropy)
    monkeypatch.setattr(recovery, '_prepare', lambda *args: object())
    monkeypatch.setattr(recovery, '_copy_verified_parent', lambda api, objects, blobs:
                        {'public.bin': blobs['public.bin'], 'master.bin': blobs['master.bin'],
                         'parent.bin': b'cached-successful-parent-fixture'})
    return directory


def invoke(source, *extra):
    return recovery.main(['--source', str(source), *extra])


def test_recovery_preserves_source_and_historical_measurements(source, capsys):
    before = recovery._inventory(source)
    assert invoke(source) == 0
    output = source.with_name(source.name+'-resumed')
    assert recovery._inventory(source) == before
    assert (source/'leaf.pending').exists()
    assert not (output/'resume.pending').exists()
    assert (output/'master.bin').read_bytes() == (source/'master.bin').read_bytes()
    assert (output/'parent.bin').read_bytes() == b'cached-successful-parent-fixture'
    assert not (output/'child.bin').exists()
    for phase in ('setup', 'parent'):
        receipt = load(output/(phase+'.json'))
        assert receipt['entropy_bytes'] == 10 and receipt['seconds'] == 1.5
        assert receipt['reused_actual_result'] is True and receipt['executed_this_run'] is False
        assert receipt['this_run_entropy_bytes'] == 0
        assert receipt['source_receipt_sha256'] == before[phase+'.json']
    private = load(output/'resume-intent.private.json')
    assert private['source_files_sha256'] == before
    public = load(output/'resume.json')
    assert public['passed'] is True and public['original_leaf_failure']['passed'] is False
    assert public['old_tombstone_preserved'] is True and public['entropy_bytes'] == 0
    emitted = capsys.readouterr().out + json.dumps(public)
    for name in ('master.bin', 'parent.bin', 'private_leaf_geometry.pkl'):
        assert before[name] not in emitted


@pytest.mark.parametrize('change', [
    {'entropy_bytes': 1}, {'entropy_bytes': False}, {'passed': True},
    {'failure_type': 'RuntimeError'}, {'phase': 'parent'}, {'backend_admitted': True},
])
def test_nonqualifying_leaf_failure_is_rejected_before_output(source, change):
    value = load(source/'leaf.json')
    value.update(change)
    save(source/'leaf.json', value)
    with pytest.raises(SystemExit) as exc:
        invoke(source)
    assert exc.value.code == 2
    assert not source.with_name(source.name+'-resumed').exists()


@pytest.mark.parametrize('change', [
    {'entropy_consumed': 1}, {'entropy_consumed': False}, {'sampler_sample_called': True},
    {'original_failure_gate_identified': False}, {'parent_snapshot_unchanged': False},
    {'safe_error': 'another error'}, {'stack': []}, {'preflight_passed': True},
])
def test_diagnostic_must_pin_original_pre_entropy_gate(source, change):
    value = load(source/recovery.DIAGNOSTIC)
    value.update(change)
    save(source/recovery.DIAGNOSTIC, value)
    with pytest.raises(SystemExit):
        invoke(source)
    assert not source.with_name(source.name+'-resumed').exists()


@pytest.mark.parametrize('kind', ['empty', 'gate-missing', 'gate-failed', 'source-empty', 'source-omitted',
                                 'old-hash', 'parent-hash', 'receipt-hash', 'escape', 'targets', 'entropy'])
def test_preflight_is_complete_current_and_bound(source, kind):
    receipt, binding = load(source/recovery.PREFLIGHT), load(source/recovery.BINDING)
    if kind == 'empty':
        receipt = {}
    elif kind == 'gate-missing':
        receipt['all_gates'].pop(next(iter(receipt['all_gates'])))
    elif kind == 'gate-failed':
        receipt['all_gates'][next(iter(receipt['all_gates']))] = False
    elif kind == 'source-empty':
        receipt['source_sha256'] = {}
        receipt['source_relative'] = []
    elif kind == 'source-omitted':
        receipt['source_sha256'].pop(next(iter(receipt['source_sha256'])))
        receipt['source_relative'] = sorted(receipt['source_sha256'])
    elif kind == 'old-hash':
        receipt['source_sha256'][next(iter(receipt['source_sha256']))] = '0'*64
    elif kind == 'parent-hash':
        binding['parent_snapshot_sha256'] = '0'*64
    elif kind == 'escape':
        receipt['source_sha256']['../escape.py'] = '0'*64
        receipt['source_relative'] = sorted(receipt['source_sha256'])
    elif kind == 'targets':
        receipt['targets'] = 32
    elif kind == 'entropy':
        receipt['entropy_bytes'] = 1
    save(source/recovery.PREFLIGHT, receipt)
    binding['receipt_sha256'] = '0'*64 if kind == 'receipt-hash' else sha256((source/recovery.PREFLIGHT).read_bytes()).hexdigest()
    save(source/recovery.BINDING, binding)
    with pytest.raises(SystemExit) as exc:
        invoke(source)
    assert exc.value.code == 2
    assert not source.with_name(source.name+'-resumed').exists()


@pytest.mark.parametrize('kind', ['missing-parent', 'extra-pending', 'child', 'empty-lock'])
def test_incomplete_or_downstream_source_is_rejected(source, kind):
    if kind == 'missing-parent':
        (source/'parent.json').unlink()
    elif kind == 'extra-pending':
        (source/'setup.pending').write_bytes(b'pending')
    elif kind == 'child':
        (source/'child.bin').write_bytes(b'not-a-real-key')
    else:
        (source/LOCK_FILE).write_bytes(b'')
    with pytest.raises(SystemExit):
        invoke(source)
    assert not source.with_name(source.name+'-resumed').exists()


def test_unique_output_branch_and_existing_directory_block_recovery(source):
    with pytest.raises(SystemExit):
        invoke(source, '--directory', str(source.with_name('another-branch')))
    output = source.with_name(source.name+'-resumed')
    output.mkdir()
    with pytest.raises(SystemExit):
        invoke(source)
    assert not list(output.iterdir())


def test_source_lock_prevents_racing_or_reentrant_recovery(source):
    with key_issuance_lock(source, timeout=0):
        with pytest.raises(SystemExit):
            invoke(source)
    assert not source.with_name(source.name+'-resumed').exists()


@pytest.mark.parametrize('failure', ['prepare', 'copy', 'write', 'changed-source', 'changed-code'])
def test_failure_preserves_new_pending_and_redacts_private_messages(source, monkeypatch, capsys, failure):
    def fail(*args, **kwargs):
        raise ValueError('PRIVATE_SENTINEL_geometry_or_secret')
    if failure == 'prepare':
        monkeypatch.setattr(recovery, '_prepare', fail)
    elif failure == 'copy':
        monkeypatch.setattr(recovery, '_copy_verified_parent', fail)
    elif failure == 'write':
        original = recovery.write
        def write(path, data):
            if path.name == 'master.bin':
                fail()
            original(path, data)
        monkeypatch.setattr(recovery, 'write', write)
    else:
        original = recovery._copy_verified_parent
        def mutate(*args):
            target = source/'parent.bin' if failure == 'changed-source' else recovery.BASE/recovery.CODE_INPUTS[0]
            target.write_bytes(b'changed underneath the tool')
            return original(*args)
        monkeypatch.setattr(recovery, '_copy_verified_parent', mutate)
    assert invoke(source) == 2
    output = source.with_name(source.name+'-resumed')
    assert (output/'resume.pending').exists()
    receipt = load(output/'resume.json')
    assert receipt['passed'] is False and receipt['failure_type'] == 'ValueError'
    assert 'PRIVATE_SENTINEL' not in capsys.readouterr().out + json.dumps(receipt)
    with pytest.raises(SystemExit):
        invoke(source)


def test_internal_state_gate_requires_only_the_original_tombstone():
    """Object-shaped fixtures exercise history rules; decoders validate math."""
    receiver, sender = b'Bob', b'Alice'
    public = SimpleNamespace(to_bytes=lambda: b'public')
    scope = SimpleNamespace(to_bytes=lambda: b'scope')
    basis = SimpleNamespace(basis_rows=((1, 0), (0, 17)))
    def parent(entries):
        return SimpleNamespace(public_key=public, identity=receiver,
            state=SimpleNamespace(scope=scope, _basis=basis, _seeds=SimpleNamespace(_entries=entries)))
    cached, failed = parent({}), parent({sender: None})
    master = SimpleNamespace(public_key=public, state=SimpleNamespace(_entries={receiver: cached.state}))
    recovery._state_case(public, master, failed, cached, receiver, sender)
    for bad in ({sender: object()}, {sender: None, b'Eve': None}, {}):
        failed.state._seeds._entries = bad
        with pytest.raises(ValueError):
            recovery._state_case(public, master, failed, cached, receiver, sender)
    failed.state._seeds._entries = {sender: None}
    failed.state._basis = SimpleNamespace(basis_rows=((2, 0), (0, 17)))
    with pytest.raises(ValueError):
        recovery._state_case(public, master, failed, cached, receiver, sender)
    failed.state._basis = basis
    failed.public_key = SimpleNamespace(to_bytes=lambda: b'foreign-public')
    with pytest.raises(ValueError):
        recovery._state_case(public, master, failed, cached, receiver, sender)
    failed.public_key = public
    cached.state._seeds._entries = {sender: None}
    with pytest.raises(ValueError):
        recovery._state_case(public, master, failed, cached, receiver, sender)


def test_no_entropy_guard_blocks_real_sources_and_sampling_entries():
    from ibme.core.randomness import SecureRandom, DeterministicRandom
    class Backend:
        setup = derive = forbidden
    class Sampler:
        generate = sample = forbidden
    api = {'CHKPHIBE': Backend, 'MP12RootGenerator': Sampler, 'FirstFiniteRandBasis': Sampler,
           'FirstFiniteGPV': Sampler, 'ExtendedGPV': Sampler}
    with recovery._no_entropy(api) as guard:
        for call in (lambda: SecureRandom().read(1), lambda: DeterministicRandom(b'fixture').read(1),
                     lambda: Backend().setup(), lambda: Sampler().sample()):
            with pytest.raises(AssertionError):
                call()
        assert guard['forbidden_calls'] == 4


def test_public_small_lattice_copies_only_successful_canonical_parent():
    """Actual object codecs over a public algebra fixture, not sampled keys."""
    pytest.importorskip('sage.all', reason='exact public algebra fixture requires prescribed Sage')
    from ibme.hibe.chkp import CHKPParams, CHKPPublicKey, CHKPMasterSecret, CHKPLevel1SecretKey
    from ibme.hibe.chkp.objects import _scope
    from ibme.lattice.chkp.identity import ROHIBEContext
    from ibme.lattice.chkp.basis import ModMatrixReference, complete_kernel_basis
    from ibme.lattice.chkp.delegation_state import MasterTreeState
    from ibme.lattice.chkp.leaf_state import SeedAddressBlocked
    from ibme.protocol.hybrid_hibe import encoded_identity, HybridLimits
    p = CHKPParams(n=1, q=17, m_bar=1, r_width_squared=1,
        root_gs_squared_bound=289, parent_width_squared=2**20, leaf_width_squared=2**36,
        alpha_numerator=1, alpha_denominator=17, epsilon_bits=16, regularity_bits=8,
        parent_max_vectors=20, max_dimension=32)
    oracle = ROHIBEContext(p.n, p.m, p.q, ((1,)+(0,)*(p.m-1),), p.to_bytes())
    public = CHKPPublicKey(p, oracle)
    tree = MasterTreeState(_scope(public), complete_kernel_basis(ModMatrixReference(oracle.root_rows, p.q)))
    limits = HybridLimits(backend_id=b'chkp')
    receiver, sender = encoded_identity(b'Bob', limits, b'P'), encoded_identity(b'Alice', limits, b'C')
    successful = CHKPLevel1SecretKey(public, tree.issue(receiver,
        lambda plan: complete_kernel_basis(ModMatrixReference(oracle.parent_rows(receiver), p.q))))
    original_parent = successful.to_bytes()
    failed = CHKPLevel1SecretKey.from_bytes(original_parent)
    def pre_entropy_failure(plan):
        raise ValueError('controlled public fixture failure')
    with pytest.raises(ValueError):
        failed.state.derive(sender, pre_entropy_failure)
    master = CHKPMasterSecret(public, tree)
    blobs = {'public.bin': public.to_bytes(), 'master.bin': master.to_bytes(), 'parent.bin': failed.to_bytes()}
    receipts = {'setup': {'root_dimension': p.m, 'public_bytes': len(public.to_bytes())},
                'parent': {'parent_dimension': 2*p.m, 'parent_bytes': len(original_parent)}}
    api = recovery._imports()
    api['research_params'] = lambda: p
    with recovery._no_entropy(api) as guard:
        objects = recovery._prepare(api, blobs, receipts)
        copied = recovery._copy_verified_parent(api, objects, blobs)
    assert guard['forbidden_calls'] == 0
    assert copied['master.bin'] == blobs['master.bin']
    assert copied['parent.bin'] == original_parent != blobs['parent.bin']
    with pytest.raises(SeedAddressBlocked):
        failed.state.lookup(sender)
    with pytest.raises(KeyError):
        CHKPLevel1SecretKey.from_bytes(copied['parent.bin']).state.lookup(sender)
