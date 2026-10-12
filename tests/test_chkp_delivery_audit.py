"""Synthetic public archives only; never manufacture actual success evidence."""

from hashlib import sha256
import json

import pytest

from experiments.research import audit_chkp_delivery as checker
from experiments.research.chkp_cli_acceptance import expected_commands


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding='utf-8')


def flags():
    return dict(checker.FLAGS)


def checked(names):
    return [dict(name=name, passed=True) for name in sorted(names)]


def cli_fixture(phase, suite):
    expected = expected_commands(phase)
    commands = [dict(name=name, passed=True, returncode=rc, expected_exit=rc,
                     no_entropy_guard=guard, timeout_seconds=timeout, bottom_token=True)
                for name, (rc, guard, timeout) in expected.items()]
    names = {name + '_exit' for name in expected}
    provenance = dict(suite_digest=suite.digest, public_sha256='a'*64)
    extra = {}
    if phase == 'setup':
        names.update(('fresh_setup_exact_suite', 'fresh_setup_v2_metadata', 'fresh_setup_public_master_bound',
                      'fresh_setup_no_issued_parent_or_sender', 'fresh_setup_no_pending', 'catalog_is_JSON'))
        provenance.update(mode='fresh actual CLI setup with system CSPRNG', imported_objects=False,
                          parent_or_leaf_generated=False)
    else:
        names.update(('empty_plaintext_match', 'small_plaintext_match', 'maximum_plaintext_match',
                      'maximum_application_capacity_3924', 'over_capacity_no_ciphertext'))
        for label in ('sender_reissue', 'receiver_reissue', 'empty', 'small', 'maximum', 'wrong-sender',
                      'wrong-receiver', 'both-wrong', 'tampered', 'truncated', 'appended', 'final'):
            names.update((label + '_key_and_metadata_bytes_unchanged', label + '_no_pending_state'))
        for label in ('wrong-sender', 'wrong-receiver', 'both-wrong', 'tampered', 'truncated', 'appended'):
            names.add(label + '_no_plaintext_published')
        provenance.update(mode='test import of completed real combination opaque objects',
                          imported_lifetime_was_generated_by_cli_setup=False,
                          source_relative='test-results/synthetic-source-not-read')
        extra.update(new_CHKP_parent_or_leaf_sampling=False, new_IBS_identity_sampling=False)
    return dict(phase=phase, passed=True, suite_digest=suite.digest, repetition_count=1, **flags(),
                checks=checked(names), executed_checks=len(names), commands=commands,
                executed_commands=len(commands), provenance=provenance, **extra)


@pytest.fixture
def archive(tmp_path):
    root, sources = tmp_path / 'public', tmp_path / 'source'
    source_entries = []
    for name in ('src/fixture.py', *checker.REQUIRED_SOURCES):
        source = sources / name
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text('# isolated audit fixture, not cryptographic code\n', encoding='utf-8')
        source_entries.append(dict(path=name, sha256=sha256(source.read_bytes()).hexdigest()))
    suite = checker.selected_suite()
    for phase in checker.LIFECYCLE:
        receipt = dict(phase=phase, passed=True, entropy_bytes=1, seconds=0.1,
                       randomness='system CSPRNG', **flags())
        if phase == 'setup':
            receipt['root_dimension'] = 127
        elif phase == 'parent':
            receipt['parent_dimension'] = 254
        elif phase == 'leaf':
            receipt.update(leaf_dimension=381, targets=256)
        else:
            attack = dict(seed_bits=256, n=2, q=1099511627791, preamble_coordinates=381,
                          recovered_seed_sha256=['a'*64], distinct_seed_candidates=1,
                          status='candidate_found', unique_seed_candidate=True, preamble_candidates=1,
                          finite_noise_radius=36, enumerated_error_tuples=5329,
                          max_candidates=10000, surviving_candidates=1, private_state_loaded=False,
                          private_seed_input=False, randomness_used=False, **flags())
            receipt.update(raw_roundtrip=True, zero_entropy_restore=True, public_attack_matches_seed=True,
                           actual_seed_sha256='a'*64, public_attack=attack, ciphertext_bytes=3919)
        write_json(root / f'evidence/lifecycle/{phase}.json', receipt)
    for phase in checker.PHASES[1:]:
        names = {'prepare': {'existing_Bob_Alice_leaf_reused', 'real_C64B_setup_and_sender'},
                 'receiver-Carol': {'address_completed'},
                 'checks': {'honest_roundtrip', 'wrong_sender', 'wrong_receiver', 'both_wrong',
                            'raw_low_coefficient_change_keeps_seed', 'hybrid_AAD_rejects_same_seed_capsule_change',
                            'full_BYTEAUTH_rejection_reaches_IBS', 'capacity_plus_one_rejects_before_entropy'}}.get(
                                phase, {'new_leaf_canonical_restore', 'address_completed'})
        write_json(root / f'evidence/combination/{phase}.json',
                   dict(phase=phase, passed=True, suite_digest=suite.digest, repetition_count=1,
                        checks=checked(names), executed_checks=len(names), **flags()))
    for phase in ('setup', 'imported'):
        write_json(root / f'evidence/cli/{phase}.json', cli_fixture(phase, suite))
    manifest = dict(schema=checker.SCHEMA, source_commit='a'*40, suite_digest=suite.digest,
                    source_files=source_entries,
                    evidence_files=[])
    for name in checker.REQUIRED:
        manifest['evidence_files'].append(dict(path=name, sha256=sha256((root/name).read_bytes()).hexdigest()))
    write_json(root/'source-manifest.json', manifest)
    return root, sources


def alter(archive, name, mutate):
    root, _ = archive
    value = json.loads((root/name).read_bytes())
    mutate(value)
    write_json(root/name, value)
    if name != 'source-manifest.json':
        manifest = json.loads((root/'source-manifest.json').read_bytes())
        next(row for row in manifest['evidence_files'] if row['path'] == name)['sha256'] = sha256((root/name).read_bytes()).hexdigest()
        write_json(root/'source-manifest.json', manifest)


def test_complete_synthetic_archive_checks_without_private_io_or_entropy(archive, monkeypatch):
    from ibme.core.randomness import SecureRandom
    from experiments.research import chkp_cli_acceptance

    def forbidden(*a, **k):
        pytest.fail('archive audit attempted entropy or private state validation')

    monkeypatch.setattr(SecureRandom, 'read', forbidden)
    monkeypatch.setattr(chkp_cli_acceptance, 'ready_cli_receipt', forbidden)
    result = checker.audit(*archive)
    assert result['passed'] and result['phases_checked'] == 12
    assert result['source_files_checked'] == 1 + len(checker.REQUIRED_SOURCES)
    assert result['evidence_files_checked'] == 12
    assert result['required_source_coverage_complete'] is True
    assert result['source_dependency_closure_proved'] is False
    assert result['seed_bytes'] == 32 and result['source_commit_verified'] is False
    assert result['experiments_rerun'] is result['private_state_read'] is False


def test_empty_public_directory_is_nonzero(tmp_path, capsys):
    assert checker.main(['--directory', str(tmp_path), '--source-root', str(tmp_path)]) == 2
    assert json.loads(capsys.readouterr().out)['passed'] is False


@pytest.mark.parametrize('target', ['source', 'evidence'])
def test_changed_bytes_are_not_accepted_by_original_manifest(archive, target):
    root, sources = archive
    path = sources/'src/fixture.py' if target == 'source' else root/checker.REQUIRED[0]
    path.write_bytes(path.read_bytes() + b' ')
    result = checker.audit(*archive)
    assert not result['passed'] and 'SHA-256 mismatch' in result['errors'][0]


@pytest.mark.parametrize('name', ['src/ibme/hibe/chkp/backend.py',
    'experiments/research/chkp_resume_pre_entropy.py', 'tests/test_chkp_resume_pre_entropy.py'])
def test_missing_critical_source_fails_even_when_all_remaining_hashes_match(archive, name):
    alter(archive, 'source-manifest.json', lambda m:
          m.update(source_files=[row for row in m['source_files'] if row['path'] != name]))
    result = checker.audit(*archive)
    assert not result['passed']
    assert result['errors'] == ['manifest omits required core sources: ' + name]
    assert result['source_files_checked'] == len(checker.REQUIRED_SOURCES)
    assert result['required_source_coverage_complete'] is False


def test_single_irrelevant_source_file_cannot_pass(archive):
    alter(archive, 'source-manifest.json', lambda m: m.update(source_files=m['source_files'][:1]))
    result = checker.audit(*archive)
    assert not result['passed'] and 'required core sources' in result['errors'][0]


@pytest.mark.parametrize('change', [
    lambda m: m.update(source_files=[]), lambda m: m.update(evidence_files=[]),
    lambda m: m['evidence_files'].pop(), lambda m: m.update(suite_digest='b'*64),
    lambda m: m.update(source_commit='unverified-name'),
    lambda m: m['source_files'].append(dict(m['source_files'][0])),
    lambda m: m['evidence_files'].append(dict(path='source-manifest.json', sha256='a'*64)),
])
def test_incomplete_mixed_or_self_referential_manifest_fails(archive, change):
    alter(archive, 'source-manifest.json', change)
    assert not checker.audit(*archive)['passed']


@pytest.mark.parametrize('path', ['../escape.py', '/absolute.py', 'C:/secret.py', 'src/../../escape.py',
                                 'src\\escape.py', 'src//fixture.py', 'src/./fixture.py', '.git/config',
                                 'test-results/master.bin', 'src/private.bin'])
def test_manifest_source_escape_or_nonpublic_file_rejected(archive, path):
    alter(archive, 'source-manifest.json', lambda m: m['source_files'][0].update(path=path))
    assert not checker.audit(*archive)['passed']


def test_source_symlink_rejected_before_reading_target(archive, tmp_path):
    root, sources = archive
    target = tmp_path/'private-outside.py'
    target.write_text('private fixture sentinel', encoding='utf-8')
    link = sources/'src/link.py'
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip('creating symlinks is unavailable on this OS account')
    alter(archive, 'source-manifest.json', lambda m: m['source_files'][0].update(path='src/link.py'))
    result = checker.audit(*archive)
    assert not result['passed'] and 'link or junction' in result['errors'][0]


@pytest.mark.parametrize('name,change', [
    ('lifecycle/setup', lambda r: r.clear()),
    ('lifecycle/parent', lambda r: r.update(passed=True, entropy_bytes=0)),
    ('lifecycle/parent', lambda r: r.update(seconds=10**1000)),
    ('lifecycle/leaf', lambda r: r.update(targets=32)),
    ('lifecycle/leaf', lambda r: r.update(security_claim='128-bit')),
    ('lifecycle/roundtrip', lambda r: r.update(actual_seed_sha256='b'*64)),
    ('lifecycle/roundtrip', lambda r: r.update(public_attack_matches_seed=False)),
    ('lifecycle/roundtrip', lambda r: r['public_attack'].update(distinct_seed_candidates=2)),
    ('lifecycle/roundtrip', lambda r: r['public_attack'].update(seed_bits=255)),
    ('lifecycle/roundtrip', lambda r: r['public_attack'].update(private_seed_input=True)),
    ('lifecycle/roundtrip', lambda r: r.update(ciphertext_bytes=1)),
    ('combination/checks', lambda r: r.update(checks=[], executed_checks=0)),
    ('combination/checks', lambda r: r.update(executed_checks=True)),
    ('combination/checks', lambda r: r.update(suite_digest='b'*64)),
    ('combination/checks', lambda r: r['checks'][0].update(passed=False)),
    ('combination/prepare', lambda r: r.update(phase='checks')),
    ('combination/prepare', lambda r: r.update(repetition_count=True)),
    ('cli/imported', lambda r: r.update(commands=[], executed_commands=0)),
    ('cli/imported', lambda r: r.update(provenance=[])),
    ('cli/imported', lambda r: r['commands'][0].update(returncode=7)),
    ('cli/imported', lambda r: r['provenance'].update(imported_lifetime_was_generated_by_cli_setup=True)),
    ('cli/setup', lambda r: r.update(backend_admitted=0)),
])
def test_rehashed_but_invalid_receipt_is_not_evidence(archive, name, change):
    alter(archive, 'evidence/'+name+'.json', change)
    assert not checker.audit(*archive)['passed']


def test_duplicate_json_keys_rejected_even_with_matching_hash(archive):
    root, _ = archive
    path = root/'source-manifest.json'
    raw = path.read_bytes()
    path.write_bytes(raw[:-1] + b',"schema":"'+checker.SCHEMA.encode()+b'"}')
    result = checker.audit(*archive)
    assert not result['passed'] and result['errors'] == ['duplicate JSON field']


@pytest.fixture
def resumed_archive(archive):
    """Synthetic evidence of a migration; no private state or real result created."""
    from experiments.research.chkp_resume_pre_entropy import PREFLIGHT_GATES
    root, _ = archive
    manifest = json.loads((root/'source-manifest.json').read_bytes())
    code_hashes = {row['path']: row['sha256'] for row in manifest['source_files']}
    original = {phase: json.loads((root/f'evidence/lifecycle/{phase}.json').read_bytes())
                for phase in ('setup', 'parent')}
    original['leaf'] = dict(phase='leaf', passed=False, entropy_bytes=0, seconds=3,
                            failure_type='ValueError', randomness='system CSPRNG', **flags())
    diagnosis = dict(diagnostic='read_only_original_leaf_preflight', entropy_consumed=0,
        sampler_sample_called=False, state_mutation_called=False, private_geometry_printed=False,
        preflight_passed=False, original_failure_gate_identified=True, parent_snapshot_unchanged=True,
        error_type='ValueError', outcome='preflight_exception',
        safe_error='Scalar squared width outside independent finite profile 1..2^80')
    preflight_hashes = {name: digest for name, digest in code_hashes.items() if name.startswith('src/ibme/')}
    preflight = dict(schema='ibme.chkp.leaf-preflight.v1', passed=True, source_parent_unchanged=True,
        cache_geometry_old_new_ast_unchanged=True, sample_called=False, state_mutation_called=False,
        gso_recomputed=False, targets=256, entropy_bytes=0, all_gates={name: True for name in PREFLIGHT_GATES},
        source_parent_relative='test-results/synthetic-r3/parent.bin',
        private_binding_relative='test-results/synthetic-r3/leaf_full_preflight_binding.json',
        source_sha256=preflight_hashes, source_relative=sorted(preflight_hashes))
    values = {'setup.json': original['setup'], 'parent.json': original['parent'], 'leaf.json': original['leaf'],
        'leaf_preflight_diagnostic_600.json': dict(diagnosis, stack=[{'file': '/fixture/finite_gpv.py',
                                                                  'function': '__init__', 'line': 197}]),
        'leaf_full_preflight_receipt.json': preflight}
    for name, path in checker.RESUME_HISTORY.items():
        write_json(root/path, values[name])
    hashes = {name: sha256((root/path).read_bytes()).hexdigest() for name, path in checker.RESUME_HISTORY.items()}
    resume = dict(schema='IBME/CHKP-ZERO-ENTROPY-RESUME/1', phase='resume', passed=True, **flags(),
        source_unchanged=True, complete_leaf_preflight_verified=True, full_256_target_entropy_budget_verified=True,
        ready_for_first_leaf_attempt=True, zero_entropy_restore=True, root_and_master_bytes_unchanged=True,
        cached_parent_bytes_unchanged=True, public_and_parameters_unchanged=True, old_tombstone_preserved=True,
        new_sampling_performed=False, basis_postprocessing_performed=False, preflight_executed_this_run=False,
        entropy_bytes=0, forbidden_calls=0, seconds=0.1, source_label='synthetic-r3',
        recovery='copy-successful-parent-after-zero-entropy-preflight-failure', source_receipt_sha256=hashes,
        original_leaf_failure=original['leaf'], original_diagnosis=diagnosis, source_code_sha256=code_hashes)
    write_json(root/checker.RESUME, resume)
    for phase in ('setup', 'parent'):
        write_json(root/f'evidence/lifecycle/{phase}.json', dict(original[phase], reused_actual_result=True,
            executed_this_run=False, this_run_entropy_bytes=0, source_receipt_sha256=hashes[phase+'.json'],
            source_relative='test-results/synthetic-r3', recovery_ledger='resume.json'))
    paths = [row['path'] for row in manifest['evidence_files']] + [checker.RESUME, *checker.RESUME_HISTORY.values()]
    manifest['evidence_files'] = [dict(path=path, sha256=sha256((root/path).read_bytes()).hexdigest()) for path in paths]
    write_json(root/'source-manifest.json', manifest)
    return archive


def test_explicit_recovery_keeps_history_separate_without_private_binding_io(resumed_archive, monkeypatch):
    from experiments.research import chkp_resume_pre_entropy
    monkeypatch.setattr(chkp_resume_pre_entropy, '_validate_preflight',
                        lambda *args: pytest.fail('archive audit attempted private source binding IO'))
    result = checker.audit(*resumed_archive)
    assert result['passed'] and result['phases_checked'] == 12 and result['evidence_files_checked'] == 18
    assert result['resumed_lifetime'] is result['historical_failure_preserved'] is True
    assert result['private_state_read'] is result['experiments_rerun'] is False


def test_historical_raw_code_hash_is_preserved_separately_from_current_git_bytes(resumed_archive):
    # For example CRLF at execution versus canonical LF in the final Git tree.
    alter(resumed_archive, checker.RESUME, lambda r:
          r['source_code_sha256'].update({'experiments/research/chkp_resume_pre_entropy.py': 'c'*64}))
    result = checker.audit(*resumed_archive)
    assert result['passed'] and result['resumed_lifetime']
    assert result['historical_source_bytes_verified'] is result['source_commit_verified'] is False


@pytest.mark.parametrize('missing', [checker.RESUME, *checker.RESUME_HISTORY.values()])
def test_reused_lifetime_requires_each_public_history_file(resumed_archive, missing):
    alter(resumed_archive, 'source-manifest.json', lambda value:
          value.update(evidence_files=[row for row in value['evidence_files'] if row['path'] != missing]))
    result = checker.audit(*resumed_archive)
    assert not result['passed'] and 'recovery history' in result['errors'][0]


@pytest.mark.parametrize('name,change', [
    (checker.RESUME, lambda r: r.update(entropy_bytes=1)),
    (checker.RESUME, lambda r: r.update(new_sampling_performed=True)),
    (checker.RESUME, lambda r: r.update(root_and_master_bytes_unchanged=False)),
    (checker.RESUME, lambda r: r['source_receipt_sha256'].update({'parent.json': 'b'*64})),
    (checker.RESUME, lambda r: r.update(original_leaf_failure={})),
    ('evidence/lifecycle/parent.json', lambda r: r.update(seconds=99)),
    ('evidence/lifecycle/setup.json', lambda r: r.update(reused_actual_result=False)),
    ('evidence/lifecycle/parent.json', lambda r: r.update(source_relative='test-results/different')),
    ('evidence/lifecycle/history/leaf-failed.json', lambda r: r.update(passed=True)),
])
def test_rehashed_recovery_cannot_hide_failure_or_relabel_new_work(resumed_archive, name, change):
    alter(resumed_archive, name, change)
    assert not checker.audit(*resumed_archive)['passed']


def test_matching_history_hash_does_not_replace_complete_preflight(resumed_archive):
    path = checker.RESUME_HISTORY['leaf_full_preflight_receipt.json']
    alter(resumed_archive, path, lambda r: r.update(all_gates={}))
    root, _ = resumed_archive
    digest = sha256((root/path).read_bytes()).hexdigest()
    alter(resumed_archive, checker.RESUME, lambda r:
          r['source_receipt_sha256'].update({'leaf_full_preflight_receipt.json': digest}))
    result = checker.audit(*resumed_archive)
    assert not result['passed'] and 'preflight' in result['errors'][0]
