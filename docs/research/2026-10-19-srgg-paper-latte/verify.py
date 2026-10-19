"""Read-only audit of public SRGG receipts and their fixed Git providers."""
import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import statistics
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = '7573014d53b5367698e161abf354b643770cf20e'
BLOBS = {}
FILES = set()
CHECK_WORKTREE = True


def require(value, message):
    if not value:
        raise ValueError(message)


def read(name):
    return json.loads((HERE/name).read_bytes())


def source(relative):
    if relative not in BLOBS:
        BLOBS[relative] = subprocess.check_output(['git', 'show', SOURCE+':'+relative], cwd=ROOT)
    raw = BLOBS[relative]
    if CHECK_WORKTREE:
        require(raw.replace(b'\r\n', b'\n') == (ROOT/relative).read_bytes().replace(b'\r\n', b'\n'),
                'working source differs from frozen Git: '+relative)
    return raw


def providers(records, installed_root=None):
    require(bool(records), 'no source providers recorded')
    for name, record in records.items():
        require(name.startswith(('ibme.', 'experiments.research.')), 'unexpected provider module')
        path = record['path'].replace('\\', '/')
        if installed_root is not None:
            require(path.startswith(installed_root+'/'), 'installed run imported repository source')
            relative = path[len(installed_root)+1:]
        else:
            # Compatibility module names intentionally alias promoted CHKP
            # modules in sys.modules; audit their actual captured file bytes.
            anchors = [a for a in ('/src/ibme/', '/experiments/research/') if a in path]
            require(len(anchors) == 1, 'unexpected source provider root')
            relative = path[path.index(anchors[0])+1:]
        require(relative.endswith('.py') and '..' not in Path(relative).parts, 'invalid provider path')
        if relative.startswith('ibme/'):
            relative = 'src/'+relative
        require(relative.startswith(('src/ibme/', 'experiments/research/')), 'unexpected provider package')
        raw = source(relative).replace(b'\r\n', b'\n')
        require(record['sha256'] in {sha256(raw).hexdigest(), sha256(raw.replace(b'\n', b'\r\n')).hexdigest()},
                'provider hash differs from frozen Git: '+relative)
        FILES.add(relative)
    return len(records)


def flags(record):
    require(record['security_claim'] == 'none' and record['backend_admitted'] is False
            and record['parameters_are_formal'] is False, 'security metadata changed')


def benchmark(report, expected):
    require(report['source_commit'] == SOURCE and report['status'] == 'passed', 'benchmark failed/source changed')
    require(report['selection'] == expected['selection'] and report['suite'] == expected['suite'], 'benchmark suite differs')
    require(report['repetitions'] == len(report['records']) == 3
            and report['warm_repetitions_per_state'] == 3, 'benchmark repetitions differ')
    require(report['identity_bytes'] == 64 and report['message_bytes'] == 32
            and report['uses_ROM'] is True and report['cross_security_group_ranking'] is False,
            'benchmark inputs/model changed')
    flags(report)
    occurrences = 0
    phases = []
    for row in report['records']:
        generation, restore = row['generation'], row['restore']
        require(generation['status'] == restore['status'] == 'passed', 'worker failed')
        require(generation['source_commit'] == restore['source_commit'] == SOURCE, 'worker source changed')
        require(generation['suite'] == restore['suite'] == report['suite'], 'worker suite changed')
        require(generation['entropy_reads'] > 0 and generation['entropy_bytes'] > 0, 'no generation entropy')
        require(restore['entropy_reads'] == restore['entropy_bytes'] == 0 and restore['state_unchanged'],
                'restore read entropy or changed state')
        require(generation['fixed_receiver_reused'] and len(generation['full_ciphertext_bytes']) == 4,
                'warm cache or ciphertext sample count differs')
        require(generation['native_operation_counts_after_runtime_build']['latte:extract'] == 1,
                'first leaf was not measured')
        require(set(restore['native_operation_counts_after_runtime_build']) <= {'latte:meta', 'latte:decrypt'},
                'restore invoked native generation')
        for worker in (generation, restore):
            flags(worker)
            require(worker['native_engine_rebuild'] is False, 'native rebuild included')
            occurrences += providers(worker['source_providers'])
            phases += worker['phases']
    require(all(row['status'] == 'passed' for row in phases), 'phase failed')
    for name, summary in report['timing_seconds'].items():
        values = [row['seconds'] for row in phases if row['name'] == name]
        require(values == summary['observations'] and len(values) == summary['count']
                and statistics.median(values) == summary['median'], 'timing aggregate differs: '+name)
    for name in ('warm-encrypt', 'warm-decrypt', 'restored-decrypt'):
        require(report['timing_seconds'][name]['count'] == 9, 'missing warm/restore observations')
    return occurrences


def verify(*, historical=False):
    global CHECK_WORKTREE
    CHECK_WORKTREE = not historical
    suites = read('suites.json')
    planned = read('preflight.json')
    require(len(suites) == len(planned['results']) == 6, 'six explicit suites required')
    expected = {}
    checks = 0
    for case, preflight in zip(suites, planned['results']):
        name = case['name']
        require(case['selection'] == preflight['selection'] and preflight['preflight']['ok'], 'preflight mismatch')
        report = read('functional-'+name.removeprefix('latte-srgg-paper-')+'.json')
        require(report['status'] == 'pass' and report['executed_cases'] == 1
                and report['executed_checks'] == 34, 'functional case failed/missing')
        row = report['results'][0]
        require(row['case'] == name and row['selection'] == case['selection']
                and row['suite'] == preflight['suite'], 'functional selection differs')
        require(len(row['checks']) == 34 and all(c['status'] == 'pass' for c in row['checks']), 'functional check failed')
        require(row['sizes']['signature'] <= preflight['preflight']['capacity']['signature_max_bytes'], 'signature exceeds bound')
        require(row['suite']['ibs_params'] == dict(profile_name=case['selection']['ibs_params'],
                interpretation='table-standard-deviation'), 'paper interpretation changed')
        flags(report)
        expected[name] = dict(selection=case['selection'], suite=row['suite'])
        checks += row['executed_checks']
    # Functional runner does not capture providers; verify its unchanged source
    # separately, without turning this into a runtime-capture claim.
    source('experiments/run_combination_matrix.py')
    source('experiments/research/full_system_benchmark.py')
    source('experiments/research/srgg_paper_cli_probe.py')
    source('experiments/research/c_framework_cli_probe.py')
    source('experiments/research/wsl_wheel_runtime.py')
    occurrences = 0
    for fmt in ('reference', 'compact'):
        occurrences += benchmark(read('benchmark-param-i-'+fmt+'.json'), expected['latte-srgg-paper-param-i-'+fmt])
    installed = read('wheel-install.json')
    cli = read('installed-cli.json')
    require(installed['global_environment_modified'] is False and installed['verified_files'] > 0, 'invalid installation')
    require(cli['source_commit'] == SOURCE and cli['status'] == 'passed' and len(cli['commands']) == 15, 'CLI failed/missing')
    require(all(c['code'] == c['expected_code'] and c['exception'] is None for c in cli['commands']), 'CLI exit changed')
    restore = cli['restore']
    require(restore['original_state_unchanged'] and restore['command']['entropy_reads'] == 0
            and restore['command']['entropy_bytes'] == 0 and restore['command']['code'] == 0
            and restore['command']['exception'] is None, 'CLI restore failed')
    require(cli['parameters']['ibs'] == 'srgg2025-paper' and cli['parameters']['signature_format'] == 'compact'
            and cli['parameters']['ibs_params'] == dict(profile_name='PARAM-I', interpretation='table-standard-deviation')
            and cli['parameters']['hybrid_limits']['max_payload_bytes'] == 65536, 'CLI paper selection changed')
    flags(cli)
    installed_count = providers(cli['providers'], installed['runtime_root'])
    broken = deepcopy(cli['providers'])
    broken[next(iter(broken))]['sha256'] = '0'*64
    try:
        providers(broken, installed['runtime_root'])
    except ValueError as error:
        require('provider hash differs' in str(error), 'negative control failed for unrelated reason')
    else:
        raise ValueError('tampered provider accepted')
    env, build = read('environment.json'), read('native-build.json')
    require(env['native_binary_sha256'] == build['binary_sha256']
            and env['native_metadata']['source_id'] == build['source_id'], 'native provenance differs')
    return dict(schema='SRGG-PAPER-PUBLIC-VERIFICATION/1', status='passed', source_commit=SOURCE,
        source_mode='historical Git 7573014' if historical else 'current checkout',
        functional_cases=6, functional_checks=checks, independent_benchmark_roots=6,
        warm_encrypt_decrypt_pairs=18, zero_entropy_restored_decrypts=18,
        benchmark_provider_records=occurrences, installed_provider_records=installed_count,
        distinct_provider_files=len(FILES), cli_commands=15, cli_restore_commands=1,
        tampered_provider_rejected=True, private_state_read=False,
        security_claim='none', backend_admitted=False, parameters_are_formal=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--historical', action='store_true',
                        help='audit the original Git snapshot after later integration changes')
    print(json.dumps(verify(historical=parser.parse_args().historical), indent=2, sort_keys=True))
