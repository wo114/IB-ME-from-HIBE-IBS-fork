"""Recompute public certificates, candidate receipts, screens and manifest."""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

from audit_luo_candidate_probe import audit
from luo_robust_abort_certificate import certificate, profile, require

ROOT=Path(__file__).resolve().parents[2]
PACKAGE=ROOT/'docs/research/2026-10-11-luo-abort-bound'
EXTRA=('experiments/research/luo_robust_abort_certificate.py',
       'experiments/research/luo_candidate_probe.py',
       'experiments/research/audit_luo_candidate_probe.py',
       'experiments/research/audit_luo_abort_delivery.py',
       'tests/test_luo_robust_abort_certificate.py',
       'tests/test_luo_candidate_probe.py','tests/test_luo_candidate_evidence.py')


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def hashes():
    files=[p for p in PACKAGE.rglob('*') if p.is_file() and p.name!='MANIFEST.json']
    require(not any('__pycache__' in p.parts for p in files),'unexpected bytecode')
    files += [ROOT/name for name in EXTRA]
    return {p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}


def check():
    evidence=PACKAGE/'evidence'
    cases=[('current-certificate.json','current',1,1,0),
           ('k49-certificate.json','availability-candidate',1,1,0),
           ('k64-certificate.json','availability-k64',1,1,0),
           ('k64-lifetime-certificate.json','availability-k64',64,65536,2**64)]
    for filename,name,extracts,signs,queries in cases:
        expected=certificate(profile(name),extracts=extracts,signs=signs,oracle_queries=queries)
        expected['profile']=name
        require(load(evidence/filename)==expected,'certificate differs: '+filename)
    probes=[audit(evidence/directory/'probe.json') for directory in ('candidate-probe','candidate-k64-probe')]
    c64=load(evidence/'parameter-screen/C64B-screen.json')
    require(c64['parameters']==asdict(profile('availability-k64')),'screen profile mismatch')
    require(c64['availability_certificate']==certificate(profile('availability-k64'),extracts=64,signs=65536,
                                                         oracle_queries=2**64),'screen certificate mismatch')
    require(c64['source_sha256_before']==c64['source_sha256_after'],'screen source drift')
    for name,sha in c64['source_sha256_before'].items():
        require(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==sha,'screen source mismatch: '+name)
    require(len(c64['jobs'])==2 and {j['mode'] for j in c64['jobs']}=={'classical','quantum'},'screen modes')
    require(all(j['exit_code']==0 and j['status']=='completed' for j in c64['jobs']),'screen failure')
    require(all(c64['constructor_checks'].values()),'screen arithmetic failure')
    original=load(evidence/'parameter-screen/current-profile-rerun.json')
    require(len(original['jobs'])==5 and all(j['status']=='completed' and j['exit_code']==0
                                           for j in original['jobs']),'baseline screen failure')
    suites=ET.parse(evidence/'final-regression.xml').getroot().findall('testsuite')
    counts={k:sum(int(s.attrib[k]) for s in suites) for k in ('tests','failures','errors','skipped')}
    require(counts==dict(tests=269,failures=0,errors=0,skipped=0),'regression counts')
    integration=load(evidence/'integration-check/main-review/summary.json')
    require(integration['sidecar_validation_passed'] is True and integration['smoke_executed'] is False
            and integration['first_blocker']=='CHKP_PUBLIC_BACKEND_MISSING'
            and integration['actual_exit_codes']=={'preflight':2,'tests':0,'public-contract':0},
            'integration blocker misreported')
    return dict(certificates_recomputed=4,candidate_receipts=probes,
                selected_regression=counts,estimator_completed_tasks=7,
                actual_chkp_integration=False,security_claim='none',backend_admitted=False,
                scope='consistency verification; no estimator or crypto rerun')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--create-manifest',action='store_true')
    args=parser.parse_args()
    result=check()
    manifest=PACKAGE/'MANIFEST.json'
    current=hashes()
    if args.create_manifest:
        with manifest.open('x',encoding='utf-8',newline='\n') as f:
            json.dump(dict(schema='IBME/LUO-ABORT-DELIVERY/1',base_commit='f079ce10fb6b3d2877465b308caaa30276d9e6f9',
                           self_hash_excluded=True,files=current,checks=result),f,ensure_ascii=False,indent=2)
            f.write('\n')
    else:
        expected=load(manifest)
        require(expected['files']==current and expected['checks']==result,'manifest or evidence drift')
    print(json.dumps(dict(files_verified=len(current),**result),ensure_ascii=False,indent=2))
