"""Explicit-profile functional probe; no default/backend admission changes."""
import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import time

from ibme.core.randomness import DeterministicRandom
from ibme.ibs.luo_module import LuoModuleIBSBackend, LuoModuleMasterSecret, LuoModuleSamplingAbort
from ibme.ibs.luo_module_codec import LuoModuleCompactIBSBackend, LuoModuleCompactSignature
from luo_robust_abort_certificate import profile, require

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ('src/ibme/ibs/luo_module.py', 'src/ibme/ibs/luo_module_math.py',
           'src/ibme/ibs/luo_module_codec.py', 'src/ibme/core/randomness.py',
           'src/ibme/core/hashing.py', 'src/ibme/core/encoding.py',
           'experiments/research/luo_robust_abort_certificate.py',
           'experiments/research/luo_candidate_probe.py')


class NoEntropy:
    def read(self, count):
        raise RuntimeError('cache/verify must not request entropy')


def hashes():
    return {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in SOURCES}


def units():
    return [dict(system=s, identity_len=i, message_len=m, repetition=r,
                 called=False, status='not_run', error_type=None,
                 sign_attempts=None, sign_seconds=None)
            for s in range(3) for i in (1,5,64) for m in (0,256,4096) for r in range(2)]


def run(output, name):
    output.mkdir(parents=True, exist_ok=False)
    p, calls, stages = profile(name), units(), []
    start = time.monotonic()
    meta = dict(schema='IBME/LUO-CANDIDATE-PROBE/1', profile=name, parameters=asdict(p),
                base_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                started_utc=datetime.now(timezone.utc).isoformat(), python=platform.python_version(),
                platform=platform.platform(), source_sha256=hashes(), completed=False,
                security_claim='none', backend_admitted=False, parameters_are_formal=False,
                expected_sign_calls=54, failure_type=None,
                rng='public deterministic test labels, not production',
                scope='functional parameter probe, not comparative benchmark or CHKP test')
    def backend(role):
        return LuoModuleIBSBackend(rng=DeterministicRandom(('LUO-CANDIDATE/1:'+name+':'+role).encode()))
    def stage(kind, system, function, identity_len=0, engine=None):
        row=dict(stage=kind,system=system,identity_len=identity_len,status='error',error_type=None)
        stages.append(row)
        t=time.perf_counter_ns()
        try:
            value=function()
            row['status']='ok'
            return value
        except BaseException as exc:
            row['error_type']=type(exc).__name__
            raise
        finally:
            row['seconds']=(time.perf_counter_ns()-t)/1e9
            if engine is not None:
                row['extract_attempts']=engine.last_extract_attempts or None
    try:
        check = LuoModuleIBSBackend(rng=NoEntropy())
        compact_check = LuoModuleCompactIBSBackend(rng=NoEntropy())
        for s in range(3):
            engine=backend(f'{s}:setup')
            pk,master=stage('setup',s,lambda:engine.setup(p))
            sizes=dict(public_bytes=len(pk.to_bytes()), master_empty_bytes=len(master.to_bytes()))
            keys={}
            for length in (1,5,64):
                identity=b'i'*length
                issuer=backend(f'{s}:{length}:extract')
                key=stage('extract',s,lambda:issuer.key_extract(master,identity),length,issuer)
                cached=stage('cache',s,lambda:check.key_extract(master,identity),length)
                require(cached.to_bytes()==key.to_bytes() and check.last_extract_attempts==0,'cache mismatch')
                restored=stage('master_restore',s,lambda:LuoModuleMasterSecret.from_bytes(master.to_bytes()),length)
                after=check.key_extract(restored,identity)
                require(after.to_bytes()==key.to_bytes() and check.last_extract_attempts==0,'restore mismatch')
                keys[length]=(key,after)
            sizes['master_three_bytes']=len(master.to_bytes())
            meta.setdefault('system_sizes',[]).append(dict(system=s,**sizes))
            for call in (row for row in calls if row['system']==s):
                require(time.monotonic()-start < 600,'probe timeout')
                i,m,r=call['identity_len'],call['message_len'],call['repetition']
                message=bytes(j%251 for j in range(m))
                signer=backend(f'{s}:{i}:{m}:{r}:sign')
                call.update(called=True,status='error')
                t=time.perf_counter_ns()
                try:
                    signature=signer.sign(keys[i][r],message)
                    call['sign_seconds']=(time.perf_counter_ns()-t)/1e9
                    for fmt,checker,obj in [('reference',check,signature),
                                            ('compact',compact_check,LuoModuleCompactSignature(signature))]:
                        wire=obj.to_bytes()
                        loaded=checker.load_signature(pk,wire)
                        require(loaded.to_bytes()==wire,'wire mismatch')
                        mathematical=loaded if fmt=='reference' else loaded.signature
                        require(all(getattr(mathematical,f)==getattr(signature,f) for f in ('z','c','w1','h')),
                                'mathematical signature mismatch')
                        valid=checker.verify(pk,b'i'*i,message,loaded)
                        require(valid is True,'verification failed')
                        call[f'{fmt}_bytes']=len(wire)
                        call[f'{fmt}_verify']=valid
                    call['status']='ok'
                except BaseException as exc:
                    call['error_type']=type(exc).__name__
                    if not isinstance(exc,LuoModuleSamplingAbort):
                        raise
                finally:
                    if call['sign_seconds'] is None:
                        call['sign_seconds']=(time.perf_counter_ns()-t)/1e9
                    call['sign_attempts']=signer.last_sign_attempts or None
            print(f'candidate system {s+1}/3 finished',flush=True)
        require(all(c['called'] and c['status']=='ok' for c in calls),'some candidate calls failed')
        require(hashes()==meta['source_sha256'],'sources changed during run')
        meta['completed']=True
    except BaseException as exc:
        meta['failure_type']=type(exc).__name__
        raise
    finally:
        meta.update(elapsed_seconds=time.monotonic()-start,source_sha256_final=hashes(),
                    attempted_sign_calls=sum(c['called'] for c in calls),
                    successful_sign_calls=sum(c['status']=='ok' for c in calls))
        result=dict(metadata=meta,calls=calls,stages=stages)
        with (output/'probe.json').open('x',encoding='utf-8',newline='\n') as f:
            json.dump(result,f,ensure_ascii=False,indent=2)
            f.write('\n')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--profile',choices=('availability-candidate','k49-cap4096','availability-k64'),default='availability-candidate')
    args=parser.parse_args()
    r=run(args.output,args.profile)
    print(json.dumps(dict(completed=r['metadata']['completed'],calls=len(r['calls']),
                          attempts=sum(c['sign_attempts'] for c in r['calls']))))
