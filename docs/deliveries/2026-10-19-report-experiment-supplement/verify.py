"""Read-only report evidence checks: public JSON and fixed Git blobs only."""
from copy import deepcopy
import argparse
import hashlib
import io
import json
import math
from pathlib import Path
import statistics
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = 'eeb3108fc634a2d3d56b329c62f528414965e05d'
SUITE_DIR = 'docs/deliveries/2026-10-19-report-three-selection/suites/'
SELECTION = 'docs/deliveries/2026-10-19-report-three-selection/selection.json'
SUITE_FILES = {'A': 'A-latte-mldsa44.json', 'B': 'B-latte-srgg-I-compact.json', 'C': 'C-lai-c2-sageloli-I.json'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def git_blobs(names):
    names = sorted(set(names))
    query = ''.join(SOURCE + ':' + name + '\n' for name in names).encode()
    process = subprocess.run(['git', 'cat-file', '--batch'], cwd=ROOT, input=query, capture_output=True, check=True)
    stream = io.BytesIO(process.stdout)
    result = {}
    for name in names:
        header = stream.readline().split()
        if len(header) != 3 or header[1] != b'blob':
            raise ValueError('missing fixed source: ' + name)
        raw = stream.read(int(header[2]))
        if stream.read(1) != b'\n':
            raise ValueError('bad Git blob frame')
        result[name] = raw
    return result


def benchmark_summary(data):
    records = data['records']
    phases = [p for r in records for mode in ('generation', 'restore') for p in r[mode]['phases']]
    sizes = [n for r in records for n in r['generation']['full_ciphertext_bytes']]
    return dict(kind='three-root-nine-warm-pair-benchmark', independent_roots=3, warm_pairs=9,
        environment=data['environment'],
        timing_seconds=data['timing_seconds'],
        root_level_warm_medians={name: [statistics.median(p['seconds'] for p in r['generation']['phases'] if p['name'] == name)
                                       for r in records] for name in ('warm-encrypt', 'warm-decrypt')},
        ciphertext_bytes=dict(count=len(sizes), minimum=min(sizes), maximum=max(sizes)),
        object_bytes={name: dict(minimum=min(r['generation']['sizes'][name] for r in records),
                                 maximum=max(r['generation']['sizes'][name] for r in records))
                      for name in ('public.bin', 'master.bin', 'sender.bin', 'receiver.bin')},
        sampled_process_tree_peak_rss_bytes=max(p['sampled_process_tree_peak_rss_bytes'] for p in phases))


def cli_summary(data):
    commands = data['commands']
    return dict(kind='single-root-installed-cli-supplement', root_count=data['root_count'],
        environment=data['environment'], suite_digest=data['suite_digest'], capacity=data['capacity'],
        observations=data['observations'], state_file_bytes=data['state_file_bytes'],
        timings_seconds={r['name']: sum(p['seconds'] for p in r['phases']) for r in commands},
        process_wall_seconds={r['name']: r['fresh_process_wall_seconds'] for r in commands},
        sampled_process_tree_peak_rss_bytes=max(p['sampled_process_tree_peak_rss_bytes'] for r in commands for p in r['phases']),
        fresh_process_checks=len(commands), cli_command_count=len(commands) - int(data['inner_signature_check_executed']),
        identity_negatives_executed=data['identity_negatives_executed'],
        inner_signature_check_executed=data['inner_signature_check_executed'],
        restored_state_unchanged=data['restored_state_unchanged'],
        restored_decrypt_zero_entropy=data['restored_decrypt_zero_entropy'])


def master_table(read):
    return dict(schema='REPORT-EXPERIMENT-MASTER/1', source_commit=SOURCE, security_claim='none',
        backend_admitted=False, parameters_are_formal=False, equal_security_ranking=False,
        rows={name: dict(benchmark=benchmark_summary(read('evidence/benchmark-' + name + '.json')) if name != 'C' else None,
                         installed_cli=cli_summary(read('evidence/cli-' + name + '.json'))) for name in 'ABC'})


def verify(overrides=None):
    overrides = overrides or {}
    count = 0

    def check(value, label):
        nonlocal count
        if not value:
            raise ValueError(label)
        count += 1

    def raw(name):
        return overrides[name] if name in overrides else (HERE / name).read_bytes()

    def read(name):
        return json.loads(raw(name))

    manifest = read('manifest.json')
    check(manifest['runtime_source_commit'] == SOURCE, 'runtime source')
    for name, expected in manifest['artifacts'].items():
        check((HERE / name).resolve().is_relative_to(HERE), 'artifact path')
        check(hashlib.sha256(raw(name)).hexdigest() == expected, 'artifact changed: ' + name)
    progress = read('evidence/progress.json')
    check(progress['status'] == 'passed' and progress['source_commit'] == SOURCE, 'completed batch')
    check(progress['stages'] == [dict(name=name, status='passed') for name in
          ('benchmark-A', 'benchmark-B', 'cli-A', 'cli-B', 'cli-C')], 'completed stage inventory')
    archive = read('archive-status.json')
    check(archive['source_commit'] == SOURCE and archive['public_receipts_retained'] is True
          and archive['wheel_retained'] is True, 'public archive scope')
    check(archive['private_directory_present'] is False and archive['installed_prefix_present'] is False
          and archive['private_state_archive_available'] is False and archive['attempted_backup_bytes'] == 0
          and archive['private_state_handover_available'] is False
          and archive['completed_experiment_receipts_rewritten'] is False, 'private-state retention limitation')
    install = read('evidence/installation.json')
    env = read('evidence/runtime-environment.json')
    check(env['source_commit'] == SOURCE and env['sage'] == '10.7' and env['python'] == '3.12.13', 'runtime versions')
    check(install['source_commit'] == SOURCE and not install['execution_cwd'].startswith(str(ROOT)), 'outside-repository run')
    code = install['fixed_source_files']
    blobs = git_blobs([entry['source_path'] for entry in code.values()] + [SUITE_DIR + name for name in SUITE_FILES.values()] + [SELECTION])
    for name, row in code.items():
        fixed = blobs[row['source_path']].replace(b'\r\n', b'\n')
        check(row['sha256'] in (hashlib.sha256(fixed).hexdigest(), hashlib.sha256(fixed.replace(b'\n', b'\r\n')).hexdigest()),
              'wheel/Git source changed: ' + name)
    check('experiments/research/report_experiment_probe.py' in code, 'installed experiment driver')
    suites = {name: json.loads(blobs[SUITE_DIR + path]) for name, path in SUITE_FILES.items()}
    selected = json.loads(blobs[SELECTION])
    capacities = {name: row['capacity'] for name, row in zip('ABC', selected['representatives'], strict=True)}

    def provider(relative, sha):
        check(relative in code and code[relative]['sha256'] == sha, 'loaded provider changed: ' + relative)

    def claims(value):
        check(value['security_claim'] == 'none' and value['backend_admitted'] is False
              and value['parameters_are_formal'] is False, 'research flags')

    for name in ('A', 'B'):
        data = read('evidence/benchmark-' + name + '.json')
        claims(data)
        check(data['status'] == 'passed' and data['source_commit'] == SOURCE and data['suite'] == suites[name], 'benchmark suite/version')
        check(data['repetitions'] == data['warm_repetitions_per_state'] == len(data['records']) == 3
              and data['identity_bytes'] == 64 and data['message_bytes'] == 32
              and data['cross_security_group_ranking'] is False, 'benchmark scope')
        timings = {}
        for r in data['records']:
            for mode in ('generation', 'restore'):
                worker = r[mode]
                claims(worker)
                check(worker['status'] == 'passed' and worker['suite'] == suites[name], 'completed benchmark worker')
                check(worker['source_commit'] == SOURCE, 'fixed benchmark worker source')
                check(worker['entropy_bytes'] == 0 if mode == 'restore' else worker['entropy_bytes'] > 0, 'benchmark entropy')
                check(worker.get('state_unchanged') is True if mode == 'restore' else worker['fixed_receiver_reused'] is True,
                      'benchmark fixed state')
                for entry in worker['source_providers'].values():
                    path = Path(entry['path'])
                    prefix = Path(install['installed_prefix'])
                    check(path.is_relative_to(prefix), 'benchmark provider outside installation')
                    provider(path.relative_to(prefix).as_posix(), entry['sha256'])
                for phase in worker['phases']:
                    check(phase['status'] == 'passed' and phase['seconds'] > 0, 'completed benchmark phase')
                    timings.setdefault(phase['name'], []).append(phase['seconds'])
        for phase, values in timings.items():
            summary = data['timing_seconds'][phase]
            check(summary['observations'] == values and summary['count'] == len(values)
                  and summary['median'] == statistics.median(values), 'benchmark statistic: ' + phase)
            check(summary['minimum'] == min(values) and summary['maximum'] == max(values)
                  and math.isclose(summary['mean'], statistics.mean(values), rel_tol=1e-12, abs_tol=1e-12)
                  and math.isclose(summary['sample_stdev'], statistics.stdev(values), rel_tol=1e-12, abs_tol=1e-12),
                  'benchmark distribution: ' + phase)
        check(len(timings['warm-encrypt']) == len(timings['warm-decrypt']) == len(timings['restored-decrypt']) == 9,
              'nine warm/restored observations')
    check(read('evidence/benchmark-A.json')['environment'] == read('evidence/benchmark-B.json')['environment'], 'same benchmark environment')
    check(read('benchmark-suites.json') == [{'name': name, 'selection': read('evidence/benchmark-' + name + '.json')['selection']}
                                           for name in 'AB'], 'exact benchmark reproducibility selections')

    for name in 'ABC':
        data = read('evidence/cli-' + name + '.json')
        claims(data)
        check(data['schema'] == 'REPORT-EXACT-SUITE-CLI/1' and data['status'] == 'passed'
              and data['source_commit'] == SOURCE and data['suite'] == suites[name]
              and data['suite_digest'] == digest(suites[name]), 'installed exact Suite: ' + name)
        check(data['root_count'] == 1 and data['no_outer_retry'] is True
              and data['identity_bytes'] == 64 and data['restored_state_unchanged'] is True,
              'installed scope: ' + name)
        capacity = data['capacity']['max_application_bytes']
        check(data['capacity'] == capacities[name], 'frozen capacity: ' + name)
        lengths = [0, 1024] if name == 'C' else [0, 32, 1024, capacity]
        check([row['message_bytes'] for row in data['observations']] == lengths, 'actually tested lengths: ' + name)
        for row in data['observations']:
            n = row['message_bytes']
            message = (bytes(range(256)) * ((n + 255) // 256))[:n]
            check(row['recovered'] is True and row['message_sha256'] == hashlib.sha256(message).hexdigest()
                  and row['ciphertext_bytes'] > 0, 'honest recovery: ' + name)
        commands = {r['name']: r for r in data['commands']}
        mandatory = {'setup', 'sender', 'receiver', 'same-sender', 'same-receiver', 'capacity-plus-one',
                     'identity-plus-one', 'truncated', 'appended', 'duplicate', 'changed',
                     'fresh-process-restore', 'valid-outer-invalid-inner'}
        mandatory |= {mode + '-' + str(n) for n in lengths for mode in ('encrypt', 'decrypt')}
        if name != 'C':
            mandatory |= {'other-receiver', 'wrong-sender', 'wrong-receiver', 'both-wrong'}
        check(set(commands) == mandatory and len(commands) == len(data['commands']), 'command inventory: ' + name)
        zero_names = {'capacity-plus-one', 'identity-plus-one', 'truncated', 'appended', 'duplicate', 'changed'}
        if name != 'C':
            zero_names.add('fresh-process-restore')
        for label, r in commands.items():
            expected = 2 if label in ('capacity-plus-one', 'identity-plus-one') else 1 if label in (
                'truncated', 'appended', 'duplicate', 'changed', 'wrong-sender', 'wrong-receiver', 'both-wrong') else 0
            check(r['code'] == r['expected_code'] == expected and r['exception'] is None, 'actual CLI result: ' + label)
            check(r['zero_entropy_required'] == (label in zero_names), 'entropy guard scope: ' + label)
            if label in zero_names:
                check(r['entropy_reads'] == r['entropy_bytes'] == 0, 'actual zero entropy: ' + label)
            check(all(p['status'] == 'passed' for p in r['phases']), 'CLI measured phase: ' + label)
        check(data['restored_decrypt_zero_entropy'] == (name != 'C')
              and data['identity_negatives_executed'] == (name != 'C')
              and data['inner_signature_check_executed'] is True, 'installed coverage boundaries')
        inner = commands['valid-outer-invalid-inner']
        check(inner['outer_ots_valid'] is True and inner['honest_old_signature_valid'] is True
              and inner['altered_message_signature_valid'] is False and inner['complete_protocol_rejected'] is True
              and inner['ibs_verification_results'] == [False] and inner['original_state_unchanged'] is True,
              'actual IBS rejection behind a valid outer OTS')
        if name == 'C':
            check(all(commands[label]['native_calls'].get('lai:derive') == 1
                      for label in ('decrypt-0', 'decrypt-1024', 'fresh-process-restore', 'valid-outer-invalid-inner')),
                  'four real uncached Lai derivations')
            check(sum(r['native_calls'].get('lai:derive', 0) for r in commands.values()) == 4, 'total Lai derivations')
        for relative, sha in data['providers'].items():
            provider(relative, sha)
    check(read('master-table.json') == master_table(read), 'master table derived from actual receipts')
    return dict(status='passed', checks=count, source_commit=SOURCE, repeated_benchmark_suites=2,
                independent_benchmark_roots=6, installed_cli_roots=3, installed_cli_commands=64,
                installed_process_checks=67, full_protocol_inner_negative_probes=3,
                new_lai_derivations=4, private_state_read=False, experiments_rerun=False,
                security_claim='none', backend_admitted=False, parameters_are_formal=False)


def negative_controls():
    """Rehash controlled edits so rejection must come from semantic checks."""
    scenarios = []
    for name, target, expected in (
        ('alter-master-median', 'master-table.json', 'master table derived from actual receipts'),
        ('claim-C-restore-zero-entropy', 'evidence/cli-C.json', 'installed coverage boundaries'),
        ('provider-outside-installed-wheel', 'evidence/benchmark-A.json', 'benchmark provider outside installation'),
    ):
        value = json.loads((HERE / target).read_bytes())
        if name == 'alter-master-median':
            value['rows']['A']['benchmark']['timing_seconds']['warm-encrypt']['median'] += 1
        elif name == 'claim-C-restore-zero-entropy':
            value['restored_decrypt_zero_entropy'] = True
        else:
            first = next(iter(value['records'][0]['generation']['source_providers'].values()))
            first['path'] = '/outside-installed-prefix/ibme/protocol/baseline.py'
        changed = json.dumps(value, sort_keys=True, indent=2).encode() + b'\n'
        manifest = deepcopy(json.loads((HERE / 'manifest.json').read_bytes()))
        manifest['artifacts'][target] = hashlib.sha256(changed).hexdigest()
        overrides = {target: changed, 'manifest.json': json.dumps(manifest).encode()}
        try:
            verify(overrides)
        except ValueError as error:
            if str(error) != expected:
                raise ValueError('negative control rejected for an unexpected reason: ' + name) from error
        else:
            raise ValueError('negative control accepted: ' + name)
        scenarios.append(dict(name=name, result='rejected', reason=expected, manifest_rehashed_in_memory=True))
    return dict(status='passed', checks=len(scenarios), controls=scenarios,
                experiments_rerun=False, private_state_read=False, original_files_changed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--negative-controls', action='store_true')
    options = parser.parse_args()
    print(json.dumps(negative_controls() if options.negative_controls else verify(), indent=2, sort_keys=True))
