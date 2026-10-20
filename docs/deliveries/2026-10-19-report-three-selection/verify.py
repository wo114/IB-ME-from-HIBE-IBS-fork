"""Read-only checks for the three report representatives; never runs crypto."""
import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BASE = 'docs/research/2026-10-18-full-system-baseline/evidence/latte-mldsa44.json'
SRGG = 'docs/research/2026-10-19-srgg-paper-latte/benchmark-param-i-compact.json'
SRGG_FUNCTIONAL = 'docs/research/2026-10-19-srgg-paper-latte/functional-param-i-compact.json'
SRGG_INSTALLED = 'docs/research/2026-10-19-srgg-paper-latte/installed-cli.json'
LAI = 'docs/research/2026-10-19-lai-c2-combinations/evidence/trials.json'
UI = 'docs/deliveries/2026-10-18-demo-acceptance/evidence/ui-mldsa44.json'
CLI = 'docs/deliveries/2026-10-18-demo-acceptance/evidence/cli-mldsa44-raw.json'
SAG_LATTE = 'docs/research/2026-10-19-sageloli-ring-integration/evidence/integration.json'
SOURCES = (
    BASE, SRGG, SRGG_FUNCTIONAL, SRGG_INSTALLED, LAI, UI, CLI, SAG_LATTE,
    'docs/research/2026-10-19-srgg-paper-latte/benchmark-param-i-reference.json',
    'src/ibme/hibe/latte/params.py',
    'experiments/research/candidates/srgg/paper_profiles.py',
    'docs/specs/latte-hibe.md', 'docs/specs/lai-hibe.md',
    'docs/specs/srgg-paper-assembly.md', 'docs/specs/sageloli-ring-ibs.md',
)
IDS = ('A-latte-mldsa44', 'B-latte-srgg-I-compact', 'C-lai-c2-sageloli-I')
ADMISSION_FIELDS = ('security_claim', 'backend_admitted', 'parameters_are_formal')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def digest(value):
    return sha256(canonical(value)).hexdigest()


def read(path):
    return json.loads((ROOT / path).read_bytes())


def legacy_admission_view(suite):
    """Return the executed cryptographic configuration with its original ledger values.

    Admission changed after the executions were archived.  This normalization
    is deliberately limited to the three ledger fields; every algorithm,
    parameter, wrapper, budget and wire version must still match byte-for-byte.
    """
    value = deepcopy(suite)
    value.update(security_claim='none', backend_admitted=False,
                 parameters_are_formal=False)
    params = value.get('ibs_params', {})
    if all(name in params for name in ADMISSION_FIELDS):
        params.update(security_claim='none', backend_admitted=False,
                      parameters_are_formal=False)
    return value


def benchmark_facts(report):
    sizes = [n for row in report['records']
             for n in row['generation']['full_ciphertext_bytes']]
    phases = [p for row in report['records'] for side in ('generation', 'restore')
              for p in row[side]['phases']]
    return {
        'kind': 'three-independent-root-benchmark',
        'source_commit': report['source_commit'],
        'environment': report['environment'],
        'identity_bytes': report['identity_bytes'],
        'message_bytes': report['message_bytes'],
        'independent_roots': report['repetitions'],
        'warm_pairs': report['repetitions'] * report['warm_repetitions_per_state'],
        'timing_seconds': {name: {k: report['timing_seconds'][name][k]
                                for k in ('count', 'median')}
                           for name in ('setup', 'sender-key', 'receiver-key',
                                        'cold-encrypt', 'first-decrypt-with-leaf-generation',
                                        'warm-encrypt', 'warm-decrypt', 'restore-objects',
                                        'restored-decrypt')},
        'full_ciphertext_bytes': {'count': len(sizes), 'minimum': min(sizes), 'maximum': max(sizes)},
        'sampled_process_tree_rss_max_bytes': max(p['sampled_process_tree_peak_rss_bytes'] for p in phases),
        'state_bytes': {name: {'minimum': min(row['generation']['sizes'][name] for row in report['records']),
                               'maximum': max(row['generation']['sizes'][name] for row in report['records'])}
                        for name in ('public.bin', 'master.bin', 'sender.bin', 'receiver.bin')},
        'uncertainty': report['uncertainty'],
    }


def lai_facts(report):
    row = report['suites']['sageloli-I']
    honest = row['identity_cases']['honest']
    phase = lambda rows, name: next(p for p in rows if p['name'] == name)
    decrypt = phase(honest['phases'], 'complete-protocol-decrypt')
    return {
        'kind': 'one-shared-root-concurrent-functional-batch',
        'source_commit': report['source_commit'],
        'environment': report['environment'],
        'identity_bytes': report['identity_bytes'], 'message_bytes': report['message_bytes'],
        'hibe_root_count': report['hibe_root_count'],
        'shared_hibe_root': report['shared_hibe_root'],
        'shared_level1_keys': report['shared_level1_keys'],
        'repetitions_per_suite': report['repetitions_per_suite'],
        'concurrent_decrypt_limit': report['concurrent_decrypt_limit'],
        'leaf_cache': report['leaf_cache'],
        'encrypt_seconds_observation': phase(row['phases'], 'encrypt')['seconds'],
        'decrypt_seconds_observation': decrypt['seconds'],
        'derive_seconds_observation': honest['derive_phases'][0]['seconds'],
        'decrypt_kernel_lifetime_rss_bytes': decrypt['self_kernel_lifetime_peak_rss_bytes'],
        'preparation_phase_sampled_tree_rss_max_bytes': max(p['sampled_process_tree_peak_rss_bytes'] for p in row['phases']),
        'full_ciphertext_bytes': row['object_bytes']['ciphertext'],
        'object_bytes': row['object_bytes'],
        'receiver_bytes': report['shared_object_bytes']['receiver'],
        'standalone_signature_bytes': row['standalone_signature_bytes'],
        'functional_observations_for_selected_suite': len(row['checks']) + len(row['identity_cases']),
        'identity_cases': {name: {'status': r['status'], 'matches': r['matches'],
                                  'bottom': r['bottom'], 'real_derive_calls': r['real_derive_calls']}
                           for name, r in row['identity_cases'].items()},
    }


def verify(data, *, assembly=False):
    count = 0

    def check(value, label):
        nonlocal count
        if not value:
            raise ValueError(label)
        count += 1

    check(data['schema'] == 'IBME-REPORT-THREE-SELECTION/1', 'selection schema')
    check(data['basis_commit'] == '6f04f2b73f69c96d4e8bea1d161655af39254d70', 'selection basis')
    check(data['admission_update'] == {
        'date': '2026-10-20', 'claim': 'project-admitted',
        'backend_admitted': True, 'parameters_are_formal': True,
        'historical_execution_receipts_rewritten': False,
    }, 'admission update boundary')
    check(set(data['sources']) == set(SOURCES), 'source inventory')
    for path, expected in data['sources'].items():
        check(sha256((ROOT / path).read_bytes()).hexdigest() == expected, 'source changed: ' + path)
    check(data['scope'] == {
        'selected_full_combinations': 3, 'distinct_hibe_algorithms': 2,
        'distinct_ibs_algorithms': 3, 'distinct_primitive_backends': 5,
        'new_algorithms_added_by_selection': 0,
        'equal_security_targets_established': False, 'cross_environment_timing_ranking': False,
        'all_three_have_measured_performance_advantages': False,
        'all_three_have_web_presets': False, 'security_claim': 'project-admitted',
        'backend_admitted': True, 'parameters_are_formal': True,
    }, 'scope and claim boundaries')
    rows = data['representatives']
    check(tuple(r['id'] for r in rows) == IDS, 'three fixed representatives')
    base, srgg, lai = read(BASE), read(SRGG), read(LAI)
    sg = lai['suites']['sageloli-I']
    evidence_suites = (base['suite'], srgg['suite'], sg['suite'])
    suite_files = ('suites/A-latte-mldsa44.json', 'suites/B-latte-srgg-I-compact.json',
                   'suites/C-lai-c2-sageloli-I.json')
    suites = tuple(json.loads((HERE / path).read_bytes()) for path in suite_files)
    facts = (benchmark_facts(base), benchmark_facts(srgg), lai_facts(lai))
    capacities = (read(UI)['capacity'], read(SRGG_FUNCTIONAL)['results'][0]['preflight']['capacity'],
                  sg['preflight']['capacity'])
    assembly_results = []
    for row, suite, evidence_suite, observed, capacity, suite_file in zip(
            rows, suites, evidence_suites, facts, capacities, suite_files, strict=True):
        name = row['id']
        check(row['suite_file'] == suite_file, name + ': suite file')
        check(row['suite_digest'] == digest(suite), name + ': suite digest')
        check(row['evidence_suite_digest'] == digest(evidence_suite), name + ': evidence suite digest')
        check(legacy_admission_view(suite) == evidence_suite,
              name + ': admission-only transition from executed suite')
        check(row['observations'] == observed, name + ': measured facts')
        check(row['capacity'] == capacity, name + ': capacity')
        check(suite['security_claim'] == 'project-admitted' and suite['backend_admitted'] is True
              and suite['parameters_are_formal'] is True and suite['allow_mock'] is False,
              name + ': project admission flags')
        check(suite['transport'] == 'hybrid' and suite['protocol'] == 'byteauth-v1', name + ': full wrappers')
        if assembly:
            from ibme.assembly import SuiteConfig, make_suite, validate_suite
            config = SuiteConfig.from_dict(suite)
            rebuilt = make_suite(**{k: suite[k] for k in ('hibe', 'ibs', 'hibe_params', 'ibs_params',
                                                         'transport', 'protocol', 'signature_format',
                                                         'allow_mock', 'hybrid_limits', 'state_policy')})
            check(config.digest == row['suite_digest'] and rebuilt.to_dict() == suite, name + ': current registry')
            report = validate_suite(config)
            check(report.ok, name + ': preflight failed: ' + repr(report.errors))
            check(report.capacity == capacity, name + ': current capacity')
            assembly_results.append({'id': name, 'runtime_available': report.metadata['runtime_available'],
                                     'preflight_ok': report.ok, 'errors': list(report.errors)})
    latte_note = {'N': 1024, 'q': 68718428161, 'depth': 2,
                  'root_source_revision': '18cfbf9a671fca34785583b58ab9f28e3be21a3c'}
    check(rows[0]['parameter_notes_not_an_alternative_config'] == {
        'hibe': latte_note, 'ibs': {'base_algorithm': 'ml-dsa-44', 'base_public_key_bytes': 1312,
                                  'base_signature_bytes': 2420, 'full_ibs_signature_bytes': 6237}}, 'A fixed parameter notes')
    check(rows[1]['parameter_notes_not_an_alternative_config'] == {
        'hibe': latte_note, 'ibs': {'degree': 512, 'rank': 2, 'p': 16383, 'base': 31,
        'digits': 2, 'Q': 15744063, 'r_stddev': '1.16', 'master_first_stddev': '2843.9',
        'master_second_stddev': '1023.0', 'signature_first_stddev': '843088.2',
        'signature_second_stddev': '310891.6', 'gamma': '42086491.7', 'factor': 1,
        'interpretation': 'table-standard-deviation', 'author_report_target_bits': 100,
        'author_report_key_recovery_quantum_bits': 95,
        'author_report_forgery_quantum_bits': 93}}, 'B fixed parameter notes')
    check(rows[2]['parameter_notes_not_an_alternative_config'] == {
        'hibe': suites[2]['hibe_params'], 'ibs': dict(suites[2]['ibs_params'], q=str(3**65))}, 'C fixed parameter notes')
    check(read(UI)['suite'] == evidence_suites[0] and read(UI)['ok'] is True,
          'A Web evidence configuration')
    cli = read(CLI)
    check(cli['parameters'] == evidence_suites[0] and cli['status'] == 'passed'
          and cli['restore']['status'] == 'passed', 'A installed CLI evidence configuration')
    functional = read(SRGG_FUNCTIONAL)
    check(functional['results'][0]['suite'] == evidence_suites[1]
          and functional['executed_checks'] == 34
          and functional['counts']['fail'] == 0, 'B functional evidence configuration')
    auxiliary = read(SRGG_INSTALLED)['parameters']
    changed = deepcopy(evidence_suites[1])
    changed['hybrid_limits']['max_payload_bytes'] = 65536
    check(auxiliary == changed and digest(auxiliary) != digest(suites[1]), 'B installed suite is different')
    check(data['auxiliary_evidence']['B_installed_suite_digest'] == digest(auxiliary)
          and data['auxiliary_evidence']['B_installed_exact_selected_suite'] is False, 'B no acceptance inheritance')
    check(data['auxiliary_evidence']['C_cli_wheel_for_exact_selected_suite'] is False
          and data['auxiliary_evidence']['C_repeated_benchmark'] is False, 'C pending acceptance')
    check(data['auxiliary_evidence']['A_web_exact_selected_suite'] is False
          and data['auxiliary_evidence']['A_installed_cli_exact_selected_suite'] is False
          and data['auxiliary_evidence']['A_web_exact_cryptographic_configuration'] is True
          and data['auxiliary_evidence']['A_installed_cli_exact_cryptographic_configuration'] is True
          and data['auxiliary_evidence']['B_installed_payload_budget_bytes'] == 65536
          and data['auxiliary_evidence']['B_selected_payload_budget_bytes'] == 131072, 'exact acceptance budgets')
    reference = read('docs/research/2026-10-19-srgg-paper-latte/benchmark-param-i-reference.json')
    check(data['auxiliary_evidence']['SRGG_reference_format_ciphertext_range_bytes']
          == benchmark_facts(reference)['full_ciphertext_bytes']
          and data['auxiliary_evidence']['SRGG_format_samples_are_paired'] is False, 'format comparison scope')
    check(sg['suite_digest'] == digest(evidence_suites[2]) and lai['status'] == 'passed',
          'C executed evidence suite')
    check(suites[2]['hibe_params']['n'] == 2048 and suites[2]['ibs_params']['d'] == 2048
          and suites[2]['ibs_version'] == 'Sageloli-RSIS-structured-v3', 'C target and v3, no debug')
    check(set(sg['identity_cases']) == {'honest', 'wrong_sender', 'wrong_receiver', 'both_wrong'}
          and all(r['status'] == 'passed' and r['real_derive_calls'] == 1 for r in sg['identity_cases'].values())
          and all(c['passed'] is True for c in sg['checks']), 'C actual observations')
    check(len({s['hibe'] for s in suites}) == 2 and len({s['ibs'] for s in suites}) == 3, 'algorithm counts')
    controls = data['bridge_controls']
    check(controls['latte-sageloli-I']['suite_digest'] == digest(read(SAG_LATTE)['parameters'])
          and controls['latte-sageloli-I']['full_ciphertext_bytes'] == read(SAG_LATTE)['ciphertext_bytes'], 'Sageloli bridge')
    for name, source_name in (('lai-c2-mldsa44', 'mldsa44'), ('lai-c2-srgg-I-compact', 'srgg-I')):
        check(controls[name]['suite_digest'] == lai['suites'][source_name]['suite_digest'], 'Lai bridge: ' + name)
    return {'status': 'passed', 'artifact_and_scope_checks': count, 'representatives': 3,
            'assembly_preflights': assembly_results, 'cryptographic_experiments_rerun': False,
            'private_state_read': False, 'security_certified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assembly', action='store_true', help='also check current registry/digests/capacities')
    parser.add_argument('--self-test', action='store_true', help='reject altered counts, timing, budget digest and scope')
    args = parser.parse_args()
    data = json.loads((HERE / 'selection.json').read_bytes())
    result = verify(data, assembly=args.assembly)
    if args.self_test:
        mutations = (
            lambda d: d['scope'].update(distinct_hibe_algorithms=3),
            lambda d: d['representatives'][1]['observations']['timing_seconds']['warm-encrypt'].update(median=0.001),
            lambda d: d['representatives'][1].update(suite_digest=data['auxiliary_evidence']['B_installed_suite_digest']),
            lambda d: d['auxiliary_evidence'].update(C_repeated_benchmark=True),
            lambda d: d['sources'].update({SRGG: '0' * 64}),
        )
        for mutate in mutations:
            invalid = deepcopy(data)
            mutate(invalid)
            try:
                verify(invalid)
            except ValueError:
                continue
            raise ValueError('negative control was accepted')
        result['rejected_negative_controls'] = len(mutations)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
