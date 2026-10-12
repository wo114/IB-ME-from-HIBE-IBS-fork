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


def test_missing_critical_source_fails_even_when_all_remaining_hashes_match(archive):
    name = 'src/ibme/hibe/chkp/backend.py'
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
