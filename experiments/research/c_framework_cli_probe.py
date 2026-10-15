"""Exercise the existing CLI with fresh CSPRNG; keep private state local.

Every command runs in a new interpreter. --restore-only reuses the original
state, forbids entropy and native generation/signing, and decrypts it again.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

PROFILES=("ml-dsa-44","ml-dsa-65","ml-dsa-87","falcon-padded-512","falcon-padded-1024")
ALICE,BOB,CAROL,EVE=(c*64 for c in "ABCE")
CHILD=r'''
import contextlib,hashlib,io,json,sys,time
from pathlib import Path
from ibme.core.randomness import SecureRandom
from ibme.hibe.latte.engine import Native
from ibme.ibs.certified.mldsa import MLDSA
from ibme.ibs.certified.falcon import Falcon
forbid=sys.argv[1]=='zero';reads=0;entropy=0;calls={}
original=SecureRandom.read
def counted(self,n):
    global reads,entropy
    reads+=1;entropy+=n
    if forbid:raise AssertionError('restore requested entropy')
    return original(self,n)
SecureRandom.read=counted
def guarded(label,function):
    def call(self,operation,*args,**kwargs):
        key=label+':'+operation;calls[key]=calls.get(key,0)+1
        # 'signature' only checks canonical signature encoding in both bridges;
        # fresh signature generation is the distinct 'sign' opcode.
        allowed=('meta','decrypt') if label=='latte' else ('meta','public','verify','signature')
        if forbid and operation not in allowed:raise AssertionError('restore requested native generation')
        return function(self,operation,*args,**kwargs)
    return call
Native.call=guarded('latte',Native.call)
MLDSA._run=guarded('mldsa',MLDSA._run);Falcon._run=guarded('falcon',Falcon._run)
from ibme.cli import main
out=io.StringIO();err=io.StringIO();started=time.perf_counter();exception=None
with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
    try:code=main(sys.argv[2:])
    except BaseException as exc:code=99;exception=type(exc).__name__
providers={}
for name,module in list(sys.modules.items()):
    path=getattr(module,'__file__',None)
    if (name.startswith('ibme.') or name.startswith('experiments.research.')) and path and path.endswith('.py'):
        providers[name]=dict(path=str(Path(path).resolve()),sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest())
print(json.dumps(dict(code=code,seconds=time.perf_counter()-started,entropy_reads=reads,entropy_bytes=entropy,
    native_calls=calls,exception=exception,stdout=out.getvalue(),stderr=err.getvalue(),providers=providers)))
'''


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(state):
    return {p.name:digest(p) for p in state.iterdir() if p.is_file() and p.suffix in (".bin",".json")}


def command(directory,label,args,*,zero=False,expected=0):
    result=subprocess.run([sys.executable,"-c",CHILD,"zero" if zero else "system",*map(str,args)],
        capture_output=True,text=True,timeout=300,check=False)
    if result.returncode:raise RuntimeError(label+" child interpreter failed")
    record=json.loads(result.stdout)
    # Full diagnostics stay with the private state; the public receipt has no
    # exception text, serialized objects or command output.
    (directory/(label+".private-log.json")).write_text(json.dumps(record,indent=2),encoding="utf-8")
    record.pop("stdout");record.pop("stderr");record.update(name=label,expected_code=expected)
    if record["code"]!=expected:raise RuntimeError(label+": unexpected CLI exit "+str(record["code"]))
    return record


def replay(directory):
    state=directory/"state";before=snapshot(state);out=directory/"restored.bin"
    record=command(directory,"zero-entropy-restore",["decrypt","--state",state,"--sender",ALICE,
        "--receiver",BOB,"--in",directory/"cipher.bin","--out",out],zero=True)
    assert out.read_bytes()==(directory/"message.bin").read_bytes()
    assert before==snapshot(state) and record["entropy_reads"]==record["entropy_bytes"]==0
    assert not list(state.glob("*.pending"))
    return dict(status="passed",new_root_or_keys_or_signature=False,entropy_bytes=0,
        original_state_unchanged=True,command=record)


def generate(directory,profile,source_commit):
    directory.mkdir(parents=True,exist_ok=False);state=directory/"state";records=[];stage="setup"
    started=time.perf_counter()
    try:
        route="cert-ml-dsa" if profile.startswith("ml-dsa-") else "cert-falcon"
        message=hashlib.sha256(b"C framework system-random CLI message").digest()
        (directory/"message.bin").write_bytes(message)
        def run(name,args,expected=0):
            nonlocal stage
            stage=name;row=command(directory,name,args,expected=expected);records.append(row)
        run("setup",["setup","--state",state,"--hibe","latte","--ibs",route,
            "--ibs-params",profile,"--transport","hybrid"])
        run("sender",["issue-sender-key",ALICE,"--state",state])
        for name,identity in (("receiver",BOB),("other-receiver",CAROL)):
            run(name,["issue-receiver-key",identity,"--state",state])
        before=snapshot(state)
        run("same-sender",["issue-sender-key",ALICE,"--state",state])
        run("same-receiver",["issue-receiver-key",BOB,"--state",state])
        assert before==snapshot(state)
        run("encrypt",["encrypt","--state",state,"--sender",ALICE,"--receiver",BOB,
            "--in",directory/"message.bin","--out",directory/"cipher.bin"])
        run("decrypt",["decrypt","--state",state,"--sender",ALICE,"--receiver",BOB,
            "--in",directory/"cipher.bin","--out",directory/"recovered.bin"])
        assert (directory/"recovered.bin").read_bytes()==message
        for name,sender,receiver in (("wrong-sender",EVE,BOB),("wrong-receiver",ALICE,CAROL),("both-wrong",EVE,CAROL)):
            output=directory/(name+".bin")
            run(name,["decrypt","--state",state,"--sender",sender,"--receiver",receiver,
                "--in",directory/"cipher.bin","--out",output],expected=1)
            assert not output.exists()
        wire=(directory/"cipher.bin").read_bytes()
        bads={"truncated":wire[:-1],"appended":wire+b"!","duplicate":wire+wire,
              "changed":wire[:-1]+bytes([wire[-1]^1])}
        for name,raw in bads.items():
            path=directory/(name+".input");path.write_bytes(raw);output=directory/(name+".output")
            run(name,["decrypt","--state",state,"--sender",ALICE,"--receiver",BOB,
                "--in",path,"--out",output],expected=1)
            assert not output.exists()
        stage="zero-entropy-restore";restore=replay(directory)
        meta=json.loads((state/"state.json").read_bytes())
        providers={}
        for row in records+[restore["command"]]:
            for name,value in row.pop("providers").items():
                if name in providers:assert providers[name]==value,"provider changed during CLI run"
                providers[name]=value
        receipt=dict(status="passed",schema="C-FRAMEWORK-CLI/1",profile=profile,route=route,
            source_commit=source_commit,commands=records,restore=restore,providers=providers,
            parameters=meta["suite"],state_version=meta["version"],identity_bytes=64,message_bytes=32,
            ciphertext_bytes=len(wire),public_key_bytes=(state/"mpk.bin").stat().st_size,
            entropy_bytes=sum(row["entropy_bytes"] for row in records),
            total_seconds=time.perf_counter()-started,repetitions=1,
            randomness="default CLI system CSPRNG; no deterministic injection or outer retry",
            safety="Research composition; LATTE anonymity/conversion model and formal parameters unadmitted",
            security_claim="none",backend_admitted=False,parameters_are_formal=False)
        (directory/"receipt.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        return dict(status="passed",profile=profile,commands=len(records),zero_entropy_restore=True,
                    seconds=receipt["total_seconds"])
    except BaseException as exc:
        (directory/"failure.json").write_text(json.dumps(dict(status="failed",stage=stage,
            exception=type(exc).__name__,detail=str(exc),private_outputs_preserved=True,
            no_outer_retry=True,partial_public_records=records),indent=2)+"\n",encoding="utf-8")
        raise


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-directory",type=Path,required=True)
    parser.add_argument("--profile",choices=PROFILES,default="ml-dsa-44")
    parser.add_argument("--restore-only",action="store_true")
    parser.add_argument("--source-commit",default="development")
    args=parser.parse_args();directory=args.private_directory.resolve()
    result=replay(directory) if args.restore_only else generate(directory,args.profile,args.source_commit)
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":main()
