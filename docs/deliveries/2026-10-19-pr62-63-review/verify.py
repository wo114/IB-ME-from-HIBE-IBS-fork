"""Verify the fixed review, CI snapshots and actual local test counts."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def require(value, label):
    if not value:
        raise ValueError(label)


def digest(raw):
    return sha256(raw.replace(b'\r\n', b'\n')).hexdigest()


def verify():
    record = json.loads((HERE / 'review.json').read_bytes())
    require(record['integration_source'] == 'd20642d78fef7ac8a45d311569cc54cdc897cb3d', 'integration source')
    expected = {62: ('aa8dd3e12b9855aa47dd5682904dea0a283b00e8', 'a9d96155d476ae98ae59c717db2cf3f6e7e864e5'),
                63: ('b9a06b1f74ddbd3908a634be7cfa2a75582a7cc5', '7a53d173f0bf8b770a11bde3c39d3e32a4d8ae0c')}
    require({p['number'] for p in record['prs']} == set(expected), 'reviewed PRs')
    for row in record['prs']:
        require(row['state'] == 'MERGED' and (row['head'], row['merge_commit']) == expected[row['number']], 'merged fixed head')
        path = HERE / row['ci_file']
        require(path.resolve().is_relative_to(HERE), 'CI path')
        require(digest(path.read_bytes()) == row['ci_sha256_lf'], 'CI snapshot digest')
        ci = json.loads(path.read_bytes())
        require(ci['headRefOid'] == row['head'], 'CI head')
        runs = ci['statusCheckRollup']
        require(all(c['status'] == 'COMPLETED' and c['conclusion'] in ('SUCCESS', 'SKIPPED') for c in runs), 'CI outcomes')
        require(sum(c['conclusion'] == 'SUCCESS' for c in runs) == row['successful_check_runs'] == 46, 'CI successes')
        skipped = [c for c in runs if c['conclusion'] == 'SKIPPED']
        require(len(skipped) == row['expected_manual_skips'] == 2 and
                all(c['name'] == 'strict-security' for c in skipped), 'expected manual checks')
    unique, counts = set(), {}
    for row in record['junit']:
        path = HERE / row['file']
        require(path.resolve().is_relative_to(HERE), 'JUnit path')
        require(digest(path.read_bytes()) == row['sha256_lf'], 'JUnit digest')
        xml = ET.parse(path)
        require(all('hostname' not in n.attrib for n in xml.iter()), 'hostname redaction')
        cases = list(xml.iter('testcase'))
        require(len(cases) == row['passed'], 'JUnit count')
        for case in cases:
            require(all(case.find(t) is None for t in ('failure', 'error', 'skipped')), 'test did not pass')
            unique.add((case.get('classname'), case.get('name')))
        counts[row['file']] = len(cases)
    require(counts == {'pr62-fixed.xml': 33, 'pr63-fix.xml': 77, 'pr62-integrated.xml': 13}, 'selected test runs')
    require(len(unique) == record['distinct_test_identities'] == 110, 'distinct tests')
    for name, expected_hash in record['selected_source_sha256_lf'].items():
        require(not Path(name).is_absolute() and '..' not in Path(name).parts, 'source path')
        raw = subprocess.check_output(['git', 'show', record['integration_source'] + ':' + name], cwd=ROOT)
        require(digest(raw) == expected_hash, 'frozen reviewed source: ' + name)
    cold = json.loads((HERE / record['windows_cold_discovery']).read_bytes())
    require(cold['status'] == 'passed' and cold['fresh_process'] is True and cold['sage_hidden'] is True
            and cold['samplers_blocked'] is True and cold['returncode'] == 0, 'cold Windows discovery')
    require(record['original_c2_14_byte_batch_rerun_during_review'] is False, 'C2 review scope')
    require(record['security_claim'] == 'none' and record['backend_admitted'] is False
            and record['parameters_are_formal'] is False, 'security metadata')
    return dict(status='passed', merged_prs=[62, 63], distinct_local_tests=110,
                local_runs=counts, live_github_check=False, experiments_rerun=False)


if __name__ == '__main__':
    print(json.dumps(verify(), sort_keys=True))
