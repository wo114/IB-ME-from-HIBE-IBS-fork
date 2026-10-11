"""Check complete public evidence and source versions, not cryptographic security."""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path

from luo_candidate_probe import SOURCES, units
from luo_robust_abort_certificate import profile, require

ROOT = Path(__file__).resolve().parents[2]


def audit(path, *, repo=ROOT):
    path=Path(path)
    data=json.loads(path.read_text(encoding='utf-8'))
    meta,calls,stages=data['metadata'],data['calls'],data['stages']
    require(meta['completed'] is True and meta['failure_type'] is None, 'incomplete run')
    require(meta['security_claim']=='none' and meta['backend_admitted'] is False
            and meta['parameters_are_formal'] is False, 'unexpected admission')
    require(meta['parameters']==asdict(profile(meta['profile'])), 'profile mismatch')
    key=lambda c:tuple(c[x] for x in ('system','identity_len','message_len','repetition'))
    require([key(c) for c in calls]==[key(c) for c in units()], 'missing, duplicate or reordered calls')
    require(meta['expected_sign_calls']==meta['attempted_sign_calls']==meta['successful_sign_calls']==54,
            'call denominator mismatch')
    require(len(stages)==30, 'missing lifecycle stages')
    expected={(s,'setup',0) for s in range(3)} | {
        (s,kind,i) for s in range(3) for kind in ('extract','cache','master_restore') for i in (1,5,64)}
    require({(r['system'],r['stage'],r['identity_len']) for r in stages}==expected, 'stage coverage')
    for r in stages:
        require(r['status']=='ok' and r['error_type'] is None and isinstance(r['seconds'],(int,float))
                and r['seconds']>=0, 'failed or untimed stage')
    for c in calls:
        require(c['called'] is True and c['status']=='ok' and c['error_type'] is None, 'failed call')
        require(type(c['sign_attempts']) is int and 1<=c['sign_attempts']<=meta['parameters']['max_sign_attempts'],
                'attempt counter')
        require(isinstance(c['sign_seconds'],(int,float)) and c['sign_seconds']>=0, 'missing call timing')
        require(all(c[f'{fmt}_verify'] is True and type(c[f'{fmt}_bytes']) is int and c[f'{fmt}_bytes']>0
                    for fmt in ('reference','compact')), 'codec check missing')
    require(len(meta['system_sizes'])==3 and {s['system'] for s in meta['system_sizes']}=={0,1,2}, 'size systems')
    require(meta['source_sha256']==meta['source_sha256_final'] and set(meta['source_sha256'])==set(SOURCES),
            'source version changed during run')
    origins={}
    for name,expected_hash in meta['source_sha256'].items():
        current=repo/name
        saved=path.parent/'source-snapshot'/Path(name).name
        # Only these two experiment helpers changed after the original C49 run.
        allow_saved=name in ('experiments/research/luo_candidate_probe.py',
                            'experiments/research/luo_robust_abort_certificate.py')
        matched=next((p for p in [current]+([saved] if allow_saved else [])
                      if p.is_file() and hashlib.sha256(p.read_bytes()).hexdigest()==expected_hash),None)
        require(matched is not None, 'source fingerprint mismatch: '+name)
        origins[name]='current' if matched==current else 'preserved-run-snapshot'
    return dict(profile=meta['profile'],planned_calls=54,successful_calls=54,
                sign_attempts=sum(c['sign_attempts'] for c in calls),stage_rows=30,
                reference_bytes=sorted({c['reference_bytes'] for c in calls}),
                compact_bytes=sorted({c['compact_bytes'] for c in calls}),
                codec_verifications=108,elapsed_seconds=meta['elapsed_seconds'],
                source_versions=origins,security_claim='none',backend_admitted=False,
                scope='public evidence consistency; no new crypto execution')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('probe',type=Path)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    result=audit(args.probe)
    raw=json.dumps(result,ensure_ascii=False,indent=2)+'\n'
    if args.output:
        with args.output.open('x',encoding='utf-8',newline='\n') as f:
            f.write(raw)
    else:
        print(raw,end='')
