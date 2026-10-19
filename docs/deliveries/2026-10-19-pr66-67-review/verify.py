"""Read-only verification of the pinned PR66/67 review, not crypto execution."""
import hashlib
import json
import math
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def require(value, message):
    if not value:
        raise ValueError(message)


def main():
    manifest = json.loads((HERE / 'manifest.json').read_bytes())
    for name, expected in manifest['artifacts'].items():
        path = (HERE / name).resolve()
        require(path.is_relative_to(HERE), 'unsafe artifact path')
        require(hashlib.sha256(path.read_bytes()).hexdigest() == expected, 'changed artifact: ' + name)
    for commit, files in manifest['git_sources'].items():
        for name, expected in files.items():
            require(not Path(name).is_absolute() and '..' not in Path(name).parts, 'unsafe source path')
            raw = subprocess.check_output(['git', 'show', commit + ':' + name], cwd=ROOT)
            require(hashlib.sha256(raw).hexdigest() == expected, 'changed frozen source: ' + name)
    record = json.loads((HERE / 'review.json').read_bytes())
    require(record['decision'] == 'hold_both_prs' and record['merged_prs'] == [], 'decision scope')
    require(record['fresh_n512_runs'] == record['fresh_security_estimates'] == 0, 'no new large runs or estimates')
    require(record['word_page_review_completed'] is False, 'layout scope')
    require(record['security_claim'] == 'none' and record['backend_admitted'] is False
            and record['parameters_are_formal'] is False, 'research flags')
    for number, expected in ((66, '6c0e2d23bc39cc27378b65fb38b0acd4b93c30eb'),
                             (67, 'cbbfd442cd3992369570f4d32004a9db0bc5cfd7')):
        data = json.loads((HERE / ('pr' + str(number) + '-ci.json')).read_bytes())
        require(data['number'] == number and data['headRefOid'] == expected, 'reviewed head')
        checks = data['statusCheckRollup']
        require(len(checks) == 48 and all(c['status'] == 'COMPLETED' for c in checks), 'complete CI snapshot')
        require(sum(c['conclusion'] == 'SUCCESS' for c in checks) == 46, 'successful CI jobs')
        require(sum(c['conclusion'] == 'SKIPPED' and c['name'] == 'strict-security' for c in checks) == 2,
                'expected manual jobs')
    checks = json.loads((HERE / 'pr66-check.json').read_bytes())
    require(checks['status'] == 'passed' and checks['checks'] == 182
            and checks['new_cryptographic_runs'] == 0, 'report structural checks')
    xml = ET.fromstring((HERE / 'pr67-original.xml').read_bytes())
    tests = list(xml.iter('testcase'))
    require(len(tests) == 4, 'four actual small tests')
    require(all(not any(t.find(k) is not None for k in ('failure', 'error', 'skipped')) for t in tests),
            'no test failure or skip')
    require(all('hostname' not in node.attrib for node in xml.iter()), 'redacted hostname')
    controls = json.loads((HERE / 'native-controls.json').read_bytes())
    require(controls['native_function_replaced'] is True and controls['unsafe_native_execution'] is False,
            'safe native controls')
    require(len(controls['cases']) == 5 and all(not r['rejected_before_native'] and r['native_entry_reached']
                                             for r in controls['cases']), 'five reproduced missing guards')
    require(record['fooli_table']['reported_d'] == 390208
            and record['fooli_table']['source_dimensions'] == [390160, 390176], 'dimension mismatch')
    frozen_report = subprocess.check_output([
        'git', 'show', '6c0e2d23bc39cc27378b65fb38b0acd4b93c30eb:'
        'docs/reports/2026-10-19-research-draft/研究报告初稿.md'], cwd=ROOT).decode()
    frozen_data = json.loads(subprocess.check_output([
        'git', 'show', '6c0e2d23bc39cc27378b65fb38b0acd4b93c30eb:'
        'docs/research/2026-10-19-parameters/fooli-improvement-search.json'], cwd=ROOT))
    points = frozen_data['target_search']['all_cases']
    dimensions = sorted({r['d'] for r in points if r['n'] == 1024 and r['q'] == 2**127 - 1})
    require(dimensions == [390160, 390176] and not any(r['d'] == 390208 for r in points),
            'recompute missing source dimension')
    require('| 1024 | 390,208 |' in frozen_report, 'original report row')
    evidence = json.loads(subprocess.check_output([
        'git', 'show', 'cbbfd442cd3992369570f4d32004a9db0bc5cfd7:'
        'experiments/research/wang_pw_numeric/evidence/n512-s0-2.json'], cwd=ROOT))
    beta = evidence['measured']['sigma_sign'] * math.sqrt(evidence['parameters']['M'])
    require(abs(beta - record['narrow_profile_arithmetic']['beta']) < 1e-6,
            'recompute script beta')
    require(evidence['measured']['sign_norm'] > beta and 16.96 < math.log2(beta) < 16.97,
            'measured norm and bound distinction')
    print(json.dumps(dict(status='passed', reviewed_prs=[66, 67], merged_prs=[], small_tests=4,
                          native_control_omissions=5, report_structural_checks=182,
                          private_state_read=False, target_n512_or_estimator_rerun=False)))


if __name__ == '__main__':
    main()
