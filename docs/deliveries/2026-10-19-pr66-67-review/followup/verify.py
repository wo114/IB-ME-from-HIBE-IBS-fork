"""Verify the post-fix numeric-research acceptance scope without executing it."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def require(value, message):
    if not value:
        raise ValueError(message)


def main():
    record = json.loads((HERE / 'record.json').read_bytes())
    require(record['source_commit'] == '1e735e8d13cfce43a04adc3f9d0430ad47b7e6db', 'fixed source')
    require(record['acceptance_scope'] == 'isolated_numeric_research'
            and record['wang_parameter_task_complete'] is False, 'acceptance boundary')
    require(record['fresh_n512_runs'] == record['fresh_security_estimates'] == 0, 'no target replay')
    require(record['security_claim'] == 'none' and record['backend_admitted'] is False
            and record['parameters_are_formal'] is False, 'research flags')
    for name, digest in record['artifacts'].items():
        path = (HERE / name).resolve()
        require(path.is_relative_to(HERE), 'unsafe artifact path')
        require(hashlib.sha256(path.read_bytes()).hexdigest() == digest, 'artifact changed: ' + name)
    for name, digest in record['source_sha256'].items():
        require(not Path(name).is_absolute() and '..' not in Path(name).parts, 'unsafe source path')
        raw = subprocess.check_output(['git', 'show', record['source_commit'] + ':' + name], cwd=ROOT)
        require(hashlib.sha256(raw).hexdigest() == digest, 'fixed source changed')
    for name in record['unchanged_from_original']:
        old = subprocess.check_output(['git', 'show', 'cbbfd442cd3992369570f4d32004a9db0bc5cfd7:' + name], cwd=ROOT)
        fixed = subprocess.check_output(['git', 'show', record['source_commit'] + ':' + name], cwd=ROOT)
        require(old == fixed, 'original C or n512 receipt changed')
    xml = ET.fromstring((HERE / 'pr67-fixed.xml').read_bytes())
    cases = list(xml.iter('testcase'))
    require(len(cases) == 23, 'actual test count')
    require(all(not any(row.find(k) is not None for k in ('failure', 'error', 'skipped')) for row in cases),
            'all tests passed without skip')
    require(sum('invalid_native_input_does_not_enter_c[' in row.get('name', '') for row in cases) == 18,
            'native boundary cases')
    require(sum(row.get('name') == 'test_native_shape_guard_survives_optimized_python' for row in cases) == 1,
            'optimized child process case')
    require(all('hostname' not in row.attrib for row in xml.iter()), 'redacted hostname')
    initial = subprocess.run([sys.executable, '-O', str(HERE.parent / 'verify.py')],
                             capture_output=True, text=True, check=True)
    require(json.loads(initial.stdout)['reviewed_prs'] == [66, 67], 'initial review retained')
    print(json.dumps(dict(status='passed', tests=23, new_native_boundary_tests=19,
                          acceptance_scope=record['acceptance_scope'], wang_parameter_task_complete=False,
                          original_receipts_unchanged=True, experiments_rerun=False)))


if __name__ == '__main__':
    main()
