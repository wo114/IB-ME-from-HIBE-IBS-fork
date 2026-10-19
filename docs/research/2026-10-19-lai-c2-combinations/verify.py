"""Read-only validation of the public C2 composition evidence; no Sage needed."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def verify():
    count = 0
    def check(value, label):
        nonlocal count
        if not value:
            raise ValueError(label)
        count += 1
    manifest = json.loads((HERE / 'manifest.json').read_bytes())
    for name, digest in manifest['artifacts'].items():
        path = (HERE / name).resolve()
        check(path.is_relative_to(HERE), 'artifact path')
        check(hashlib.sha256(path.read_bytes()).hexdigest() == digest, 'artifact changed: ' + name)
    for name, digest in manifest['source_files'].items():
        path = (ROOT / name).resolve()
        check(path.is_relative_to(ROOT), 'source path')
        check(hashlib.sha256(path.read_bytes()).hexdigest() == digest, 'source changed: ' + name)
    for digest, paths in manifest['source_sets'].items():
        check(len(paths) == len(set(paths)), 'duplicate provider path')
        subset = {name: manifest['source_files'][name] for name in paths}
        check(hashlib.sha256(canonical(subset)).hexdigest() == digest, 'provider set changed')
    data = json.loads((HERE / 'evidence/trials.json').read_bytes())
    check(data['schema'] == 'LAI-C2-COMPOSITIONS/1' and data['status'] == 'passed', 'execution result')
    check(data['source_commit'] == '48f72292177a695a437154a91d315f76cb4e8d21', 'fixed run source')
    check(data['hibe_root_count'] == 1 and data['receiver_key_count'] == 2, 'shared root accounting')
    check(data['shared_hibe_root'] is True and data['shared_level1_keys'] is True
          and data['leaf_cache'] is False, 'reuse scope')
    check(data['repetitions_per_suite'] == 1 and data['message_bytes'] == 32
          and data['identity_bytes'] == 64 and data['inner_identity_bytes'] == 86
          and data['inner_payload_bytes'] == 32, 'inputs and repetitions')
    check(data['source_set'] in manifest['source_sets'], 'preparation providers')
    check(data['preparation_process'] == {'returncode': 0, 'timed_out': False}
          and data['concurrent_decrypt_limit'] == 6, 'completed bounded preparation')
    check(len(data['phases']) == 3 and all(p['status'] == 'passed' for p in data['phases']), 'shared generation phases')
    cases = {'mldsa44': ('cert-ml-dsa', 'reference'), 'falcon512': ('cert-falcon', 'reference'),
             'srgg-I': ('srgg2025-paper', 'compact'), 'sageloli-I': ('sageloli-rsis', 'reference')}
    check(set(data['suites']) == set(cases), 'four actual IBS selections')
    expected = {'n': 2048, 'q': 274877976577, 'k': 39, 'l': 2, 'p': 2,
                'sigma': 2.0, 'sigma_r': 1.0, 'identity_bytes': 86,
                'max_message_bytes': 32, 'message_mode': 'seed32'}
    required = {'public_restore', 'master_restore', 'sender_restore', 'ciphertext_canonical',
                'byteauth_context', 'byteauth_inner_bytes', 'byteauth_signature', 'byteauth_ots_key',
                'outer_rejection_without_derive', 'ibs_honest', 'ibs_wrong_message', 'ibs_wrong_identity',
                'ibs_changed_signature', 'ibs_random_signature'}
    required |= {name + '_' + mode for name in ('truncated', 'appended', 'duplicate', 'version')
                 for mode in ('loader', 'decrypt')}
    functional = 0
    for name, row in data['suites'].items():
        suite = row['suite']
        check(suite['hibe'] == 'lai-ideal-hibe' and suite['hibe_params'] == expected, name + ': exact C2')
        check(suite['hibe_version'] == 'lai-a-256-v1', name + ': unchanged Lai version')
        check((suite['ibs'], suite['signature_format']) == cases[name], name + ': IBS and encoding')
        ip = suite['ibs_params']
        if name in ('mldsa44', 'falcon512'):
            check(ip['base_algorithm'] == ('ml-dsa-44' if name == 'mldsa44' else 'falcon-padded-512'), name + ': base signature')
        elif name == 'srgg-I':
            check(ip == {'profile_name': 'PARAM-I', 'interpretation': 'table-standard-deviation'}, name + ': paper profile')
        else:
            check(suite['ibs_version'] == 'Sageloli-RSIS-structured-v3'
                  and (ip['d'], ip['k'], ip['l']) == (2048, 65, 132)
                  and ip['identity_width_squared'] == 2720281532542
                  and ip['signature_width_squared'] == 270116709797628319132317,
                  name + ': full v3 paper parameters')
        check(suite['transport'] == 'hybrid' and suite['protocol'] == 'byteauth-v1'
              and suite['allow_mock'] is False, name + ': actual wrappers')
        check(suite['hybrid_limits']['max_payload_bytes'] == 8 * 2**20, name + ': explicit payload budget')
        check(hashlib.sha256(canonical(suite)).hexdigest() == row['suite_digest'], name + ': suite digest')
        for flags in (data, suite):
            check(flags['security_claim'] == 'none' and flags['backend_admitted'] is False
                  and flags['parameters_are_formal'] is False, name + ': security scope')
        checks = row['checks']
        check(len(checks) == len(required) and {c['name'] for c in checks} == required
              and all(c['passed'] is True for c in checks), name + ': negative and object checks')
        functional += len(checks)
        identities = row['identity_cases']
        check(set(identities) == {'honest', 'wrong_sender', 'wrong_receiver', 'both_wrong'}, name + ': identity coverage')
        for case, result in identities.items():
            check(result['status'] == 'passed' and result['process']['returncode'] == 0
                  and result['process']['timed_out'] is False, name + ': ' + case + ' completed')
            check(result['fresh_process'] is True and result['original_files_unchanged'] is True
                  and result['real_derive_calls'] == 1 and result['leaf_cache'] is False,
                  name + ': ' + case + ' real unchanged path')
            check(result['source_set'] in manifest['source_sets'], name + ': child providers')
            check(len(result['derive_phases']) == 1 and result['derive_phases'][0]['status'] == 'passed', name + ': sampled leaf')
            check(all(p['status'] == 'passed' and p['seconds'] > 0 for p in result['phases']), name + ': measured operations')
            check((result['matches'] is True and result['bottom'] is False and result['output_bytes'] == 32)
                  if case == 'honest' else
                  (result['matches'] is False and result['bottom'] is True and result['output_bytes'] == 0),
                  name + ': plaintext outcome')
            functional += 1
        check(all(p['status'] == 'passed' for p in row['phases']), name + ': preparation phases')
        check(row['object_bytes']['ciphertext'] > 2**20 and row['standalone_signature_bytes'] > 0, name + ': actual sizes')
    check(functional == 104, 'bounded functional observation count')
    return dict(status='passed', artifact_and_scope_checks=count, suites=4,
                identity_trials=16, functional_observations=functional,
                private_state_read=False, experiments_rerun=False, security_certified=False)


if __name__ == '__main__':
    print(json.dumps(verify(), sort_keys=True))
