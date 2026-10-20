"""Read-only verification of report C's installed target-scale acceptance."""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = 'f8ca35676f8926d96f55b286301037a13bc8e6af'
SUITE = 'docs/deliveries/2026-10-19-report-three-selection/suites/C-lai-c2-sageloli-I.json'
DIGEST = '9a3c66cfd5073721bf135466197522352010ecbc6a10a6794c710e9b10423c82'
WHEEL = '60413cd2ebcbfce81c595912a6eb414b71346e3a37022c0fa881efa441141e2c'
NAMES = ['setup', 'sender', 'receiver', 'same-sender', 'same-receiver', 'encrypt-empty',
         'truncated', 'appended', 'duplicate', 'changed', 'decrypt-empty', 'restore-empty']
FORBIDDEN = {'hibe:setup', 'hibe:extract', 'ibs:setup', 'ibs:key_extract', 'ibs:sign'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def frozen(paths):
    paths = sorted(set(paths))
    for path in paths:
        require(not PurePosixPath(path).is_absolute() and '..' not in PurePosixPath(path).parts
                and '\n' not in path and '\r' not in path, 'invalid source path')
    result = subprocess.run(['git', 'cat-file', '--batch'], cwd=ROOT,
        input=''.join(SOURCE+':'+path+'\n' for path in paths).encode(), capture_output=True, check=True).stdout
    blobs, pos = {}, 0
    for path in paths:
        end = result.index(b'\n', pos)
        fields = result[pos:end].split()
        require(len(fields) == 3 and fields[1] == b'blob', 'frozen source unavailable: '+path)
        size = int(fields[2]); pos = end+1
        blobs[path] = result[pos:pos+size]
        require(result[pos+size:pos+size+1] == b'\n', 'Git source framing changed')
        pos += size+1
    require(pos == len(result), 'unexpected Git data')
    return blobs


def verify(data, blobs):
    build, installed, env, run = (data[key] for key in ('wheel-build', 'wheel-install', 'environment', 'installed-cli'))
    require(build['source_commit'] == run['source_commit'] == SOURCE, 'execution source changed')
    require(build['wheel_sha256'] == installed['wheel_sha256'] == WHEEL, 'executed another wheel')
    require(build['global_environment_modified'] is False and installed['global_environment_modified'] is False
            and build['network_used'] is False, 'installation scope changed')
    require(build['verified_source_files'] == len(build['packaged_source_files']) == 583,
            'packaged source inventory changed')
    require(installed['verified_files'] == 588 and installed['native_source_checks'] == 'unchanged',
            'installed file inventory or native validation changed')
    for name, digest in build['packaged_source_files'].items():
        require(hashlib.sha256(blobs[name]).hexdigest() == digest, 'package/Git source mismatch: '+name)
    expected = json.loads(blobs[SUITE])
    canonical = json.dumps(expected, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
    require(hashlib.sha256(canonical.encode('ascii')).hexdigest() == DIGEST, 'frozen selection changed')
    require(run['parameters'] == expected and run['requested_suite_digest'] == run['installed_suite_digest'] == DIGEST,
            'actual target Suite changed')
    require(run['schema'] == 'REPORT-C-INSTALLED/1' and run['status'] == 'passed' and run['state_version'] == 2,
            'acceptance incomplete')
    require(run['message_bytes'] == 0 and run['changed_message_bytes'] == 1 and run['identity_bytes'] == 64,
            'input scope changed')
    require(run['independent_roots'] == run['repetitions'] == 1 and run['max_parallel_workers'] == 2
            and run['worker_timeout_seconds'] == 900 and run['overall_timeout_seconds'] == 1800,
            'trial count or resource budget changed')
    require(run['security_claim'] == 'none' and run['backend_admitted'] is False
            and run['parameters_are_formal'] is False, 'security metadata upgraded')
    require(run['restore_recomputes_leaf'] is True and run['leaf_cache'] is False
            and run['original_state_unchanged'] is True, 'restore semantics changed')
    rows = run['commands']
    require([row['name'] for row in rows] == NAMES, 'CLI lifecycle incomplete')
    for row in rows:
        expected_code = 1 if row['name'] in NAMES[6:10] else 0
        require(row['code'] == row['expected_code'] == expected_code and row['exception'] is None,
                'CLI operation failed: '+row['name'])
    by_name = {row['name']: row for row in rows}
    require(by_name['setup']['events']['calls'].get('hibe:setup') == 1
            and by_name['setup']['events']['calls'].get('ibs:setup') == 1, 'real roots missing')
    require(by_name['sender']['events']['calls'].get('ibs:key_extract') == 1
            and by_name['receiver']['events']['calls'].get('hibe:extract') == 1, 'real issuance missing')
    for name in NAMES[6:10]:
        require(by_name[name]['events']['calls'].get('hibe:derive', 0) == 0, 'outer rejection used Derive')
    for name in ('decrypt-empty', 'restore-empty'):
        row = by_name[name]
        require(row['events']['calls'].get('hibe:derive') == 1
                and row['events']['verify_results'] == [True], 'honest path omitted real verification')
    restored = by_name['restore-empty']
    require(restored['entropy_bytes'] > 0 and restored['entropy_reads'] > 0,
            'uncached Lai restoration was mislabeled zero-entropy')
    require(not FORBIDDEN.intersection(restored['events']['calls']), 'restore performed generation/issuance/signing')
    negative = run['inner_negative']
    require(negative['name'] == 'authenticated-inner-negative' and negative['code'] == negative['expected_code'] == 0
            and negative['exception'] is None, 'inner negative failed')
    detail = negative['details']
    require(all(detail[key] is True for key in ('original_signature_valid', 'altered_signature_invalid',
            'envelope_commitment_matches', 'outer_ots_valid', 'canonical_wire', 'bottom')),
            'invalid authenticated-inner construction')
    require(detail['real_derive_calls'] == 1 and detail['protocol_ibs_results'] == [False]
            and negative['events']['verify_results'] == [False], 'inner rejection did not reach IBS')
    require(negative['events']['calls'].get('hibe:derive') == 1
            and negative['events']['calls'].get('hibe:encrypt') == 1
            and negative['events']['calls'].get('ibs:sign') == 1, 'real inner negative computation missing')
    runtime = PurePosixPath(installed['runtime_root'])
    require(runtime.name == WHEEL and env['cwd_outside_repository'] is True
            and env['pythonpath_only_installed_runtime'] is True, 'installation isolation changed')
    for name, item in run['providers'].items():
        path = PurePosixPath(item['path'])
        require(path.is_relative_to(runtime) and '..' not in path.parts, 'provider escaped wheel: '+name)
        relative = path.relative_to(runtime).as_posix()
        source = 'src/'+relative if relative.startswith('ibme/') else relative
        require(build['packaged_source_files'].get(source) == item['sha256'], 'provider/source mismatch: '+name)
    native_source = 'experiments/research/candidates/sageloli/ring/native.cpp'
    native_id = hashlib.sha256(blobs[native_source]+b'-O3 -fopenmp -lflint -lgmp v1').hexdigest()
    require(env['sageloli_native_metadata']['source_id'] == native_id, 'native source mismatch')
    require(env['sage'] == '10.9' and env['omp_num_threads'] == env['openblas_num_threads'] == 1,
            'recorded execution environment changed')
    return dict(status='passed', source_commit=SOURCE, suite_digest=DIGEST,
                packaged_sources=583, installed_files=installed['verified_files'],
                dynamic_providers=len(run['providers']), independent_roots=1, cli_commands=12,
                installed_empty_roundtrips=2, authenticated_inner_negative=1,
                real_lai_derivations=3, restored_project_entropy_bytes=restored['entropy_bytes'],
                original_state_unchanged=True, leaf_cache=False, experiments_rerun=False,
                security_claim='none', backend_admitted=False, parameters_are_formal=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    data = {name: json.loads((HERE/(name+'.json')).read_bytes())
            for name in ('wheel-build', 'wheel-install', 'environment', 'installed-cli')}
    blobs = frozen(list(data['wheel-build']['packaged_source_files'])+[SUITE])
    result = verify(data, blobs)
    xml = ET.fromstring((HERE/'probe-tests.xml').read_bytes())
    cases = list(xml.iter('testcase'))
    require(len(cases) == 12 and all(not any(row.find(tag) is not None
            for tag in ('failure', 'error', 'skipped')) for row in cases), 'twelve harness tests incomplete')
    require(all('hostname' not in row.attrib for row in xml.iter()), 'hostname not redacted')
    result['harness_tests'] = 12
    if args.self_test:
        def suite(d): d['installed-cli']['parameters']['hibe_params']['n'] = 256
        def outer(d): d['installed-cli']['inner_negative']['details']['outer_ots_valid'] = False
        def reached(d): d['installed-cli']['inner_negative']['details']['protocol_ibs_results'] = []
        def entropy(d): d['installed-cli']['commands'][-1]['entropy_bytes'] = 0
        def source(d): d['installed-cli']['providers'][next(iter(d['installed-cli']['providers']))]['sha256'] = '0'*64
        def generation(d): d['installed-cli']['commands'][-1]['events']['calls']['hibe:setup'] = 1
        for change in (suite, outer, reached, entropy, source, generation):
            broken = deepcopy(data); change(broken)
            try:
                verify(broken, blobs)
            except ValueError:
                continue
            raise ValueError('tampered receipt accepted: '+change.__name__)
        result['rejected_tamper_controls'] = 6
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
