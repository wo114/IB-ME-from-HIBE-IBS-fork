"""Check this frozen PR review's public source bindings and test evidence."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def require(value, message):
    if not value:
        raise ValueError(message)


def main():
    record = json.loads((HERE/'review.json').read_bytes())
    source = record['integration_source']
    require(source == '85b87fa63d8183ceafdfd5dcac8c2147cabbdc7b', 'integration snapshot changed')
    expected_states = {56: 'MERGED', 57: 'CLOSED', 58: 'MERGED', 59: 'MERGED', 60: 'MERGED', 61: 'MERGED'}
    rows = record['prs']
    require(len(rows) == 6 and {r['number']: r['state'] for r in rows} == expected_states, 'PR states differ')
    require(next(r for r in rows if r['number'] == 57)['mergedAt'] is None, 'PR57 was merged')
    for relative, expected in record['selected_runtime_and_test_sha256_lf'].items():
        require(not Path(relative).is_absolute() and '..' not in Path(relative).parts, 'source path escapes')
        raw = subprocess.check_output(['git', 'show', source+':'+relative], cwd=ROOT)
        require(sha256(raw.replace(b'\r\n', b'\n')).hexdigest() == expected, 'source binding differs: '+relative)
    unique = set()
    counts = {}
    for run in record['junit']:
        name = run['file']
        require(Path(name).name == name, 'JUnit path escapes')
        raw = (HERE/name).read_bytes()
        require(sha256(raw.replace(b'\r\n', b'\n')).hexdigest() == run['sha256'], 'JUnit hash differs: '+name)
        xml = ET.fromstring(raw)
        require(all('hostname' not in n.attrib for n in xml.iter()), 'hostname not removed')
        cases = list(xml.iter('testcase'))
        names = {(c.get('classname'), c.get('name')) for c in cases}
        require(len(cases) == len(names) == run['passed'], 'JUnit count differs: '+name)
        for case in cases:
            require(all(case.find(tag) is None for tag in ('failure', 'error', 'skipped')), 'test did not pass')
        unique.update(names)
        counts[name] = len(cases)
    require(counts == {'pr59-independent.xml': 35, 'pr60-independent.xml': 57,
                       'lai-merged-sage.xml': 132, 'lai-merged-portable.xml': 130}, 'test selection changed')
    require(len(unique) == record['distinct_test_identities_across_published_runs'] == 297, 'union count differs')
    require(record['fresh_target_lifecycle_runs'] == {'sageloli_paper_profiles': 0, 'lai_C2': 0}, 'rerun scope changed')
    require(record['security_claim'] == 'none' and record['backend_admitted'] is False
            and record['parameters_are_formal'] is False, 'security metadata changed')
    require(record['private_existing_state_files_read'] == 0 and record['remote_snapshot_is_live_check'] is False,
            'review scope changed')
    print(json.dumps(dict(status='passed', source_mode='frozen Git 85b87fa',
                          selected_source_bindings=len(record['selected_runtime_and_test_sha256_lf']),
                          junit=counts, distinct_test_identities=len(unique), live_github_check=False)))


if __name__ == '__main__':
    main()
