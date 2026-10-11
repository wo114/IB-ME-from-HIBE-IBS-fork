"""Audit real public receipts and injected corruptions; do not rerun crypto."""
import copy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'experiments/research'))
from audit_luo_candidate_probe import audit

ROOT=Path(__file__).resolve().parents[1]
EVIDENCE=ROOT/'docs/research/2026-10-11-luo-abort-bound/evidence'


@pytest.mark.parametrize('directory,attempts,compact', [('candidate-probe',293,16062),('candidate-k64-probe',315,16383)])
def test_real_run_is_complete_and_source_bound(directory,attempts,compact):
    result=audit(EVIDENCE/directory/'probe.json')
    assert result['sign_attempts']==attempts and result['compact_bytes']==[compact]
    assert result['successful_calls']==54 and result['codec_verifications']==108


@pytest.mark.parametrize('mutation', ['missing_call','duplicate_call','missing_stage','untimed','bad_attempt',
                                    'failed_verify','claim','profile','changed_source','missing_sizes'])
def test_corrupt_public_evidence_rejected(tmp_path,mutation):
    data=json.loads((EVIDENCE/'candidate-k64-probe/probe.json').read_text())
    if mutation=='missing_call': data['calls'].pop()
    if mutation=='duplicate_call': data['calls'][1]=copy.deepcopy(data['calls'][0])
    if mutation=='missing_stage': data['stages'].pop()
    if mutation=='untimed': data['calls'][0]['sign_seconds']=None
    if mutation=='bad_attempt': data['calls'][0]['sign_attempts']=True
    if mutation=='failed_verify': data['calls'][0]['compact_verify']=False
    if mutation=='claim': data['metadata']['backend_admitted']=True
    if mutation=='profile': data['metadata']['parameters']['kappa']=49
    if mutation=='changed_source': data['metadata']['source_sha256_final']['src/ibme/ibs/luo_module.py']='0'*64
    if mutation=='missing_sizes': data['metadata']['system_sizes'].pop()
    path=tmp_path/'probe.json'
    path.write_text(json.dumps(data),encoding='utf-8')
    with pytest.raises(ValueError): audit(path)
