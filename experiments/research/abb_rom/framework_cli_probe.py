"""Real default ABB CLI execution; all private objects stay in a new local directory.

Fresh mode executes genuine CLI Setup and issuance. Import mode wraps an
already completed 2x2 ABB tree through public object constructors, without
new HIBE keys. Restore still uses 256 FRESH SamplePre calls: it is not a
zero-entropy decryption. Only key issuance is forbidden during replay.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

CHILD=r'''
import contextlib,hashlib,io,json,sys,time
from pathlib import Path
from ibme.core.randomness import SecureRandom
from ibme.hibe.abb_rom.backend import ABBROMHIBE
from ibme.lattice.matrix_sampling import MatrixFiniteGPV
restore=sys.argv[1]=='restore';entropy=0;reads=0;preimages=0;decrypting=False;roots=0
original_read=SecureRandom.read
def counted(self,n):
    global entropy,reads
    value=original_read(self,n);entropy+=len(value);reads+=1;return value
SecureRandom.read=counted
class NoIssuance:
    def read(self,n):raise AssertionError('restoration attempted new HIBE issuance')
setup=ABBROMHIBE.setup
def setup_guard(self,*args,**kwargs):
    global roots
    if restore:raise AssertionError('restoration attempted Setup')
    roots+=1;return setup(self,*args,**kwargs)
ABBROMHIBE.setup=setup_guard
def guard_issue(function):
    def issue(self,*args,**kwargs):
        if restore:kwargs['rng']=NoIssuance()
        return function(self,*args,**kwargs)
    return issue
ABBROMHIBE.extract=guard_issue(ABBROMHIBE.extract);ABBROMHIBE.derive=guard_issue(ABBROMHIBE.derive)
sample=MatrixFiniteGPV.sample
def sample_count(self,*args,**kwargs):
    global preimages
    if decrypting:preimages+=1
    return sample(self,*args,**kwargs)
MatrixFiniteGPV.sample=sample_count
decrypt=ABBROMHIBE.decrypt
def decrypt_count(self,*args,**kwargs):
    global decrypting
    decrypting=True
    try:return decrypt(self,*args,**kwargs)
    finally:decrypting=False
ABBROMHIBE.decrypt=decrypt_count
from ibme.cli import main
out=io.StringIO();err=io.StringIO();started=time.perf_counter();exception=None
with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
    try:code=main(sys.argv[2:])
    except BaseException as exc:code=99;exception=type(exc).__name__
providers={}
for name,module in list(sys.modules.items()):
    path=getattr(module,'__file__',None)
    if path and path.endswith('.py') and (name.startswith('ibme.') or name.startswith('experiments.research.')):
        providers[name]=dict(path=str(Path(path).resolve()),sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest())
print(json.dumps(dict(code=code,exception=exception,stdout=out.getvalue(),stderr=err.getvalue(),
    entropy_bytes=entropy,entropy_reads=reads,fresh_decrypt_preimages=preimages,new_hibe_roots=roots,
    issuance_forbidden=restore,seconds=time.perf_counter()-started,providers=providers)))
'''


def snapshot(state):
    return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in state.iterdir()
            if p.is_file() and p.suffix in ('.bin','.json')}


def command(directory,name,arguments,*,restore=False,expected=0):
    result=subprocess.run([sys.executable,'-c',CHILD,'restore' if restore else 'fresh',*map(str,arguments)],
        capture_output=True,text=True,timeout=1800,check=False)
    if result.returncode:raise RuntimeError(name+' child interpreter failed')
    record=json.loads(result.stdout)
    (directory/(name+'.private-log.json')).write_text(json.dumps(record,indent=2),encoding='utf-8')
    record.pop('stdout');record.pop('stderr');record.update(name=name,expected_code=expected)
    if record['code']!=expected:raise RuntimeError(name+': CLI exit '+str(record['code']))
    return record


def imported_state(directory,source,route,preset,signature_format):
    from ibme.assembly import make_suite,validate_suite,build_runtime
    from ibme.hibe.abb_rom.objects import ABBPublicKey,ABBMasterSecret
    from ibme.protocol.hybrid_hibe import HybridPublicKey,HybridMasterSecret
    from ibme.protocol.baseline import PublicKey,MasterSecret
    from ibme.cli import _selected_metadata,_state_object,_atomic_write_state
    if not (source/'completed').is_file() or json.loads((source/'receipt.json').read_bytes())['status']!='passed':
        raise ValueError('completed genuine ABB tree required')
    before={name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in ('public.bin','master.bin')}
    raw_public=ABBPublicKey.from_bytes((source/'public.bin').read_bytes())
    raw_master=ABBMasterSecret.from_bytes((source/'master.bin').read_bytes())
    selected=json.loads(Path(preset).read_bytes()) if Path(preset).is_file() else preset
    suite=make_suite(hibe='abb-rom',hibe_params=raw_public.params,ibs=route,ibs_params=selected,
        transport='hybrid',signature_format=signature_format)
    report=validate_suite(suite)
    if not report.ok:raise ValueError(report.errors)
    runtime=build_runtime(suite)
    ipk,imsk=runtime.proto.ibs_backend.setup(runtime.ibs_params)
    hpk=HybridPublicKey(runtime.hibe_params.limits,raw_public)
    public=PublicKey(hpk,ipk);master=MasterSecret(HybridMasterSecret(hpk,raw_master),imsk)
    assert raw_master.public_key==raw_public
    state=directory/'state';state.mkdir()
    meta=_selected_metadata(suite,report,hashlib.sha256(public.to_bytes()).hexdigest())
    for name,kind,raw in [('mpk.bin','mpk',public.to_bytes()),('msk.bin','msk',master.to_bytes())]:
        _atomic_write_state(state/name,_state_object(raw,meta,kind))
    _atomic_write_state(state/'state.json',(json.dumps(meta,indent=2,sort_keys=True)+'\n').encode())
    assert before=={name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in before}
    return dict(source_files_sha256=before,source_unchanged=True,new_hibe_roots=0,new_hibe_issuance=False)


def replay(directory):
    state=directory/'state';before=snapshot(state)
    row=command(directory,'restored-decrypt',['decrypt','--state',state,'--sender','Alice','--receiver','Bob',
        '--in',directory/'cipher.bin','--out',directory/'restored.bin'],restore=True)
    assert (directory/'restored.bin').read_bytes()==(directory/'message.bin').read_bytes()
    assert row['fresh_decrypt_preimages']==256 and row['entropy_bytes']>0
    assert before==snapshot(state) and not list(state.glob('*.pending'))
    return dict(status='passed',original_state_unchanged=True,new_hibe_keys=False,command=row)


def generate(directory,route,preset,signature_format,source,commit):
    directory.mkdir(parents=True,exist_ok=False);state=directory/'state';records=[];started=time.perf_counter();stage='start'
    try:
        def run(name,args,*,restore=False,expected=0):
            nonlocal stage
            stage=name;(directory/'progress.json').write_text(json.dumps(dict(stage=stage,commands=len(records))))
            row=command(directory,name,args,restore=restore,expected=expected);records.append(row);return row
        imported=imported_state(directory,source,route,preset,signature_format) if source else None
        if not source:
            run('setup',['setup','--state',state,'--hibe','abb-rom','--ibs',route,'--ibs-params',preset,
                '--transport','hybrid','--signature-format',signature_format])
        for name,identity in [('sender','Alice'),('other-sender','Charlie')]:
            run(name,['issue-sender-key',identity,'--state',state])
        receivers=['Bob','Carol'] if source else ['Bob']
        for identity in receivers:run('receiver-'+identity,['issue-receiver-key',identity,'--state',state],restore=bool(source))
        message=bytes(range(32));(directory/'message.bin').write_bytes(message)
        run('encrypt',['encrypt','--state',state,'--sender','Alice','--receiver','Bob',
            '--in',directory/'message.bin','--out',directory/'cipher.bin'])
        row=run('decrypt',['decrypt','--state',state,'--sender','Alice','--receiver','Bob',
            '--in',directory/'cipher.bin','--out',directory/'recovered.bin'],restore=bool(source))
        assert row['fresh_decrypt_preimages']==256 and (directory/'recovered.bin').read_bytes()==message
        before=snapshot(state)
        run('same-sender',['issue-sender-key','Alice','--state',state])
        run('same-receiver-after-leaf',['issue-receiver-key','Bob','--state',state],restore=True)
        assert before==snapshot(state)
        if source:
            for name,sender,receiver in [('wrong-sender','Charlie','Bob'),('wrong-receiver','Alice','Carol'),('both-wrong','Charlie','Carol')]:
                output=directory/(name+'.output')
                run(name,['decrypt','--state',state,'--sender',sender,'--receiver',receiver,
                    '--in',directory/'cipher.bin','--out',output],restore=True,expected=1)
                assert not output.exists()
        wire=(directory/'cipher.bin').read_bytes()
        for name,raw in [('truncated',wire[:-1]),('appended',wire+b'x'),('duplicate',wire+wire),
                         ('changed',wire[:-1]+bytes([wire[-1]^1]))]:
            input_path=directory/(name+'.input');input_path.write_bytes(raw);output=directory/(name+'.output')
            row=run(name,['decrypt','--state',state,'--sender','Alice','--receiver','Bob','--in',input_path,'--out',output],restore=True,expected=1)
            assert not output.exists() and row['fresh_decrypt_preimages']==row['entropy_bytes']==0
        stage='restoration';restored=replay(directory)
        providers={}
        for row in records+[restored['command']]:
            for name,value in row.pop('providers').items():
                if name in providers:assert providers[name]==value
                providers[name]=value
        receipt=dict(schema='ABB-DEFAULT-FRAMEWORK-CLI/1',status='passed',source_commit=commit,
            commands=records,restore=restored,providers=providers,imported_hibe=imported,
            new_hibe_roots=sum(r['new_hibe_roots'] for r in records),
            system_randomness=True,private_algorithms_unchanged=True,parameters=json.loads((state/'state.json').read_bytes())['suite'],
            identities=dict(sender_bytes=5,receiver_bytes=3,inner_identity_bytes=86),message_bytes=32,repetitions=1,
            ciphertext_bytes=len(wire),seconds=time.perf_counter()-started,
            security_claim='none',backend_admitted=False,parameters_are_formal=False)
        (directory/'receipt.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
        return dict(status='passed',commands=len(records),new_hibe_roots=receipt['new_hibe_roots'],seconds=receipt['seconds'])
    except BaseException as exc:
        (directory/'failure.json').write_text(json.dumps(dict(status='failed',stage=stage,exception=type(exc).__name__,
            detail=str(exc),partial_public_records=records,private_state_preserved=True,no_outer_retry=True),indent=2)+'\n')
        raise


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-directory',type=Path,required=True)
    parser.add_argument('--import-hibe',type=Path)
    parser.add_argument('--ibs',default='cert-ml-dsa')
    parser.add_argument('--ibs-params',default='ml-dsa-44')
    parser.add_argument('--signature-format',default='reference')
    parser.add_argument('--restore-only',action='store_true')
    parser.add_argument('--source-commit',default='development')
    args=parser.parse_args();directory=args.private_directory.resolve()
    result=replay(directory) if args.restore_only else generate(directory,args.ibs,args.ibs_params,args.signature_format,
        args.import_hibe.resolve() if args.import_hibe else None,args.source_commit)
    print(json.dumps(result))


if __name__=='__main__':main()
