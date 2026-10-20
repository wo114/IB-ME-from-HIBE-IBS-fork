"""Check the report content revision while preserving its failed layout gate."""
import hashlib
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
    record = json.loads((HERE / 'record.json').read_bytes())
    source = record['source_commit']
    require(source == 'b34257654684592d446eca59109abe707c5e49a1', 'fixed content version')
    require(record['decision'] == 'hold_for_page_review' and record['fresh_cryptographic_runs'] == 0,
            'uncompleted gate and scope')
    for name, digest in record['artifacts'].items():
        path = (HERE / name).resolve()
        require(path.is_relative_to(HERE), 'unsafe artifact path')
        require(hashlib.sha256(path.read_bytes()).hexdigest() == digest, 'changed artifact')
    for name, digest in record['source_sha256'].items():
        require(not Path(name).is_absolute() and '..' not in Path(name).parts, 'unsafe source path')
        raw = subprocess.check_output(['git', 'show', source + ':' + name], cwd=ROOT)
        require(hashlib.sha256(raw).hexdigest() == digest, 'changed frozen report source')
    prefix = 'docs/reports/2026-10-19-research-draft/'
    def frozen(name):
        return subprocess.check_output(['git', 'show', source + ':' + prefix + name], cwd=ROOT)
    validation = json.loads(frozen('validation.json'))
    require(validation['status'] == 'passed' and validation['checks'] == 197, 'structural validation')
    require(validation['new_cryptographic_runs'] == 0, 'no fresh crypto run')
    for name, digest in validation['files'].items():
        require(hashlib.sha256(frozen(name)).hexdigest() == digest, 'validated artifact binding')
    render = json.loads((HERE / 'render.json').read_bytes())
    require(render['attempted'] is True and render['returncode'] == 1
            and render['page_review_completed'] is False and render['page_images'] == 0,
            'render was not completed')
    require(render['message'] == 'LibreOffice soffice.exe was not found on PATH', 'actual renderer error')
    require(render['docx_sha256'] == validation['files']['研究报告初稿.docx'], 'rendered input binding')
    xml = ET.fromstring((HERE / 'source-binding-tests.xml').read_bytes())
    cases = list(xml.iter('testcase'))
    require(len(cases) == 5 and all(not any(r.find(k) is not None for k in ('failure', 'error', 'skipped'))
                                   for r in cases), 'five passed source regressions')
    require(all('hostname' not in row.attrib for row in xml.iter()), 'hostname redaction')
    print(json.dumps(dict(status='passed', document_checks=197, source_tests=5,
                          word_page_review_completed=False, decision=record['decision'],
                          experiments_rerun=False)))


if __name__ == '__main__':
    main()
