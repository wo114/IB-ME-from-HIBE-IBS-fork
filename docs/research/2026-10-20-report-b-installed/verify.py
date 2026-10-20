"""Verify public installation evidence without Sage, native binaries or state."""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = 'f24a333c74e923226be6dbbc876937668ecb3f59'
SUITE = 'docs/deliveries/2026-10-19-report-three-selection/suites/B-latte-srgg-I-compact.json'
DIGEST = '37a0d413d5daed2c407c03b4b4f1a1fe4b6454e786e9cea3dfe8676a60ce9c97'
WHEEL = '8278aea61875a9b51b2698b028ce9f7c06b6ffc69046f0c95c3e65a0cb849223'
NAMES = ['setup', 'sender', 'receiver', 'other-receiver', 'same-sender', 'same-receiver',
         'encrypt', 'decrypt', 'wrong-sender', 'wrong-receiver', 'both-wrong',
         'truncated', 'appended', 'duplicate', 'changed']


def require(value, message):
    if not value:
        raise ValueError(message)


def frozen(paths):
    paths = sorted(set(paths))
    for path in paths:
        require(not PurePosixPath(path).is_absolute() and '..' not in PurePosixPath(path).parts
                and '\n' not in path and '\r' not in path, 'invalid public source path')
    request = ''.join(SOURCE+':'+path+'\n' for path in paths).encode()
    result = subprocess.run(['git', 'cat-file', '--batch'], input=request, capture_output=True,
                            cwd=ROOT, check=True).stdout
    blobs = {}
    pos = 0
    for path in paths:
        end = result.index(b'\n', pos)
        fields = result[pos:end].split()
        require(len(fields) == 3 and fields[1] == b'blob', 'missing frozen Git source: '+path)
        size = int(fields[2])
        pos = end+1
        blobs[path] = result[pos:pos+size]
        require(result[pos+size:pos+size+1] == b'\n', 'invalid Git batch framing')
        pos += size+1
    require(pos == len(result), 'unexpected Git output')
    return blobs


def verify(data, blobs):
    build, installed, env, cli = (data[key] for key in ('wheel-build', 'wheel-install', 'environment', 'installed-cli'))
    require(build['source_commit'] == cli['source_commit'] == SOURCE, 'source commit changed')
    require(build['wheel_sha256'] == installed['wheel_sha256'] == WHEEL, 'wheel changed')
    require(build['global_environment_modified'] is False and installed['global_environment_modified'] is False
            and build['network_used'] is False, 'installation scope changed')
    require(build['verified_source_files'] == len(build['packaged_source_files']) == 582,
            'packaged source inventory changed')
    require(installed['verified_files'] == 587, 'installed wheel inventory changed')
    for name, digest in build['packaged_source_files'].items():
        require(hashlib.sha256(blobs[name]).hexdigest() == digest, 'wheel source differs from Git: '+name)
    expected = json.loads(blobs[SUITE])
    canonical = json.dumps(expected, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
    require(hashlib.sha256(canonical.encode('ascii')).hexdigest() == DIGEST, 'frozen report selection changed')
    require(cli['parameters'] == expected and expected['hybrid_limits']['max_payload_bytes'] == 131072,
            'executed the wrong report Suite')
    require(cli['requested_suite_digest'] == cli['installed_suite_digest'] == DIGEST
            and cli['frozen_suite_matched'] is True, 'runtime Suite binding missing')
    require(cli['schema'] == 'SRGG-PAPER-CLI/1' and cli['status'] == 'passed'
            and cli['state_version'] == 2 and cli['repetitions'] == 1, 'CLI acceptance status changed')
    require(cli['identity_bytes'] == 64 and cli['message_bytes'] == 32, 'input scope changed')
    require(cli['security_claim'] == 'none' and cli['backend_admitted'] is False
            and cli['parameters_are_formal'] is False, 'security metadata upgraded')
    require([row['name'] for row in cli['commands']] == NAMES, 'incomplete CLI lifecycle')
    for index, row in enumerate(cli['commands']):
        code = 0 if index < 8 else 1
        require(row['code'] == row['expected_code'] == code and row['exception'] is None,
                'CLI command failed: '+NAMES[index])
    rows = dict((row['name'], row) for row in cli['commands'])
    require(rows['setup']['native_calls']['latte:setup'] == 1, 'missing real HIBE setup')
    require(rows['decrypt']['native_calls']['latte:extract'] == 1, 'missing honest leaf derivation')
    require(rows['same-sender']['entropy_reads'] == rows['same-receiver']['entropy_reads'] == 0,
            'repeated issuance requested fresh project entropy')
    restore = cli['restore']
    require(restore['status'] == 'passed' and restore['original_state_unchanged'] is True
            and restore['new_root_or_keys_or_signature'] is False, 'restore state changed')
    row = restore['command']
    require(row['code'] == row['expected_code'] == 0 and row['exception'] is None
            and row['entropy_reads'] == row['entropy_bytes'] == restore['entropy_bytes'] == 0,
            'restore requested fresh entropy or failed')
    require(set(row['native_calls']) <= {'latte:meta', 'latte:decrypt'}
            and row['native_calls']['latte:decrypt'] == 1, 'restore generated new native keys')
    runtime = PurePosixPath(installed['runtime_root'])
    require(runtime.name == WHEEL and env['cwd_outside_repository'] is True
            and env['pythonpath_only_installed_runtime'] is True, 'repository leaked into execution path')
    require(len(cli['providers']) == 165, 'dynamic provider inventory changed')
    for name, record in cli['providers'].items():
        path = PurePosixPath(record['path'])
        require(path.is_relative_to(runtime) and '..' not in path.parts, 'provider outside wheel: '+name)
        relative = path.relative_to(runtime).as_posix()
        source = 'src/'+relative if relative.startswith('ibme/') else relative
        require(build['packaged_source_files'].get(source) == record['sha256'],
                'provider differs from wheel/Git: '+name)
    prefix = 'src/ibme/hibe/latte/native/'
    upstream = json.loads(blobs[prefix+'upstream/UPSTREAM.json'])
    hashes = {'upstream/'+name: item['sha256'] for name, item in upstream['files'].items()}
    for name in ('bridge.c', 'shake.c', 'build.py', 'compat/libXKCP.a.headers/SimpleFIPS202.h'):
        hashes[name] = hashlib.sha256(blobs[prefix+name]).hexdigest()
    expected_id = hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    require(env['native_metadata'] == dict(abi='IBME-LATTE3-COEFF-1', n=1024,
            q=68718428161, source_id=expected_id), 'native ABI/source metadata differs')
    require(env['native_binary_sha256'] == 'd5d965ab4fcc06ccd179f35e8e718bf6faae8b77d8e438567522f5f0b86e6e93',
            'recorded native binary changed')
    require(env['sage'] == '10.9' and env['omp_num_threads'] == 4 and env['openblas_num_threads'] == 1,
            'recorded environment changed')
    require(cli['ciphertext_bytes'] == 149279 and cli['public_key_bytes'] == 47353,
            'recorded wire/object sizes changed')
    return dict(status='passed', source_commit=SOURCE, suite_digest=DIGEST,
                packaged_sources=582, installed_files=587, dynamic_providers=165,
                cli_commands=15, fresh_process_restored_decrypts=1, project_restore_entropy_bytes=0,
                acceptance_scope='report B exact 128 KiB Suite; one-root installed CLI',
                security_claim='none', backend_admitted=False, parameters_are_formal=False,
                experiments_rerun=False)


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
    require(len(cases) == 9 and all(not any(row.find(tag) is not None
            for tag in ('failure', 'error', 'skipped')) for row in cases), 'nine harness tests did not pass')
    require(all('hostname' not in row.attrib for row in xml.iter()), 'hostname not redacted')
    result['harness_tests'] = 9
    if args.self_test:
        def budget(d): d['installed-cli']['parameters']['hybrid_limits']['max_payload_bytes'] = 65536
        def source(d): d['installed-cli']['providers'][next(iter(d['installed-cli']['providers']))]['sha256'] = '0'*64
        def entropy(d): d['installed-cli']['restore']['command']['entropy_bytes'] = 1
        def native(d): d['installed-cli']['restore']['command']['native_calls']['latte:extract'] = 1
        def exit_code(d): d['installed-cli']['commands'][-1]['code'] = 0
        for change in (budget, source, entropy, native, exit_code):
            broken = deepcopy(data)
            change(broken)
            try:
                verify(broken, blobs)
            except ValueError:
                continue
            raise ValueError('tampered evidence accepted: '+change.__name__)
        result['rejected_tamper_controls'] = 5
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
