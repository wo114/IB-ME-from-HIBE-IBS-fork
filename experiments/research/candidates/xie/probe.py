"""Fresh system-entropy study instances; private outputs stay in a local directory.

Use --restore-only for zero-entropy/no-Sage replay of the original artifacts.
This probe is not a persistent issuer or a benchmark at a claimed security level.
"""
import argparse
import hashlib
import importlib.abc
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time


PREFIX="experiments.research.candidates.xie"


def write_json(path,value):
    with path.open("x",encoding="utf-8",newline="\n") as stream:
        json.dump(value,stream,indent=2,sort_keys=True);stream.write("\n")


def digest(raw):return hashlib.sha256(raw).hexdigest()


def source_fingerprints():
    """Fingerprint executed providers, including shared Gaussian dependencies."""
    result={}
    for name,module in sorted(sys.modules.items()):
        if name=="__main__" and getattr(getattr(module,"__spec__",None),"name",None)==PREFIX+".probe":
            name=PREFIX+".probe"
        if not (name.startswith("ibme.") or name.startswith("experiments.research.")):continue
        path=getattr(module,"__file__",None)
        if path and path.endswith(".py"):
            result[name]=dict(path=str(Path(path).resolve()),sha256=digest(Path(path).read_bytes()))
    return result


def source_snapshot():
    import ibme
    roots=(Path(ibme.__file__).resolve().parent,Path(__file__).resolve().parents[2])
    return {str(path.resolve()):digest(path.read_bytes()) for root in roots for path in root.rglob("*.py")}


class CountedRandom:
    def __init__(self):self.reads=0;self.bytes=0
    def read(self,n):
        self.reads+=1;self.bytes+=n
        return os.urandom(n)


def replay(directory):
    """Must be called in a fresh interpreter, with all Sage work forbidden."""
    from ibme.core.randomness import SecureRandom
    class ForbiddenImports(importlib.abc.MetaPathFinder):
        def find_spec(self,fullname,path=None,target=None):
            if fullname=="sage" or fullname.startswith("sage.") or fullname==PREFIX+".runtime":
                raise AssertionError("restore imported private/Sage execution: "+fullname)
    sys.meta_path.insert(0,ForbiddenImports())
    entropy_calls=0
    def forbidden_entropy(*args,**kwargs):
        nonlocal entropy_calls
        entropy_calls+=1;raise AssertionError("restore consumed fresh entropy")
    SecureRandom.read=forbidden_entropy;os.urandom=forbidden_entropy
    from .objects import Public,Master,IdentitySecret,Signature
    from .verification import load_signature,verify
    manifest=json.loads((directory/"cases.json").read_bytes())
    public_raw=(directory/"public.bin").read_bytes();public=Public.from_bytes(public_raw)
    master_raw=(directory/"master-users.bin").read_bytes();master=Master.from_bytes(master_raw)
    assert public.to_bytes()==public_raw and master.to_bytes()==master_raw and master.public==public
    keys=[]
    for i,identity in enumerate(manifest["identities_hex"]):
        raw=(directory/f"user-{i}.bin").read_bytes();key=IdentitySecret.from_bytes(raw)
        assert key.to_bytes()==raw and key.public==public and key.identity==bytes.fromhex(identity)
        assert master.extract(key.identity).to_bytes()==raw
        keys.append(key)
    verified=0
    for i,case in enumerate(manifest["cases"]):
        raw=(directory/f"signature-{i:03}.bin").read_bytes();signature=load_signature(public,raw)
        assert signature.to_bytes()==raw
        assert verify(public,keys[case["user"]].identity,bytes.fromhex(case["message_hex"]),signature)
        verified+=1
    assert master.to_bytes()==master_raw
    assert not any(name=="sage" or name.startswith("sage.") or name==PREFIX+".runtime" for name in sys.modules)
    return dict(status="passed",verified=verified,cached_keys=len(keys),entropy_calls=entropy_calls,
        private_runtime_imported=False,sage_imported=False,new_root_or_signatures=False,
        master_snapshot_unchanged=True,public_sha256=digest(public_raw),providers=source_fingerprints())


def sign_restored(directory):
    from .objects import Public,IdentitySecret,Master
    from . import runtime
    from .verification import verify
    def forbidden(*args,**kwargs):raise AssertionError("restored signing generated a root or extracted")
    runtime.setup=forbidden;runtime.preimage_sampler=forbidden;Master.extract=forbidden
    public=Public.from_bytes((directory/"public.bin").read_bytes());source=CountedRandom();records=[]
    for i in range(2):
        key=IdentitySecret.from_bytes((directory/f"user-{i}.bin").read_bytes())
        message=hashlib.sha256(b"XIE-STUDY fresh restored-key message/"+bytes([i])).digest()
        stats={};signature=runtime.sign(key,message,rng=source,stats=stats)
        assert verify(public,key.identity,message,signature)
        with (directory/f"restored-signature-{i}.bin").open("xb") as stream:stream.write(signature.to_bytes())
        records.append(dict(identity_hex=key.identity.hex(),message_hex=message.hex(),
            signature_hex=signature.to_bytes().hex(),stats=stats))
    return dict(status="passed",restored_keys=2,new_signatures=2,new_roots=0,new_extractions=0,
        entropy_bytes=source.bytes,entropy_reads=source.reads,records=records,providers=source_fingerprints())


def subprocess_mode(directory,mode):
    result=subprocess.run([sys.executable,"-m",PREFIX+".probe","--private-directory",str(directory),mode],
        capture_output=True,text=True,timeout=300,check=False)
    if result.returncode:
        raise RuntimeError(mode+" failed: "+result.stderr[-4000:])
    return json.loads(result.stdout)


def generate(directory,n,source_commit):
    # Import private execution only in the generation/signing modes.
    from . import runtime
    from .params import StudyParams
    from .objects import Public,Master,IdentitySecret,Signature
    from .verification import verify
    from .negative_controls import modulus_shift,zero_challenge_forgery
    from .qualification import report
    from ibme.core.errors import SerializationError
    import resource
    from sage.version import version as sage_version
    directory.mkdir(parents=True,exist_ok=False)
    started=time.perf_counter();source=CountedRandom();before=source_snapshot();receipt={}
    stage="setup"
    try:
        p=StudyParams(n=n);stats={};tick=time.perf_counter()
        public,master=runtime.setup(p,rng=source,stats=stats)
        receipt["setup"]=dict(seconds=time.perf_counter()-tick,**stats)
        (directory/"public.bin").write_bytes(public.to_bytes())
        (directory/"master-initial.bin").write_bytes(master.to_bytes())
        identities=[hashlib.sha512(b"XIE-STUDY independent user/"+bytes([i])).digest() for i in range(2)]
        keys=[];stage="extract";tick=time.perf_counter()
        try:
            for i,identity in enumerate(identities):
                key=master.extract(identity,rng=source);keys.append(key)
                (directory/f"user-{i}.bin").write_bytes(key.to_bytes())
        finally:
            # A failed extraction also preserves its pending mark; never retry it.
            (directory/"master-users.bin").write_bytes(master.to_bytes())
        receipt["extract"]=dict(seconds=time.perf_counter()-tick,identities=2,identity_bytes=64)
        stage="sign";tick=time.perf_counter();cases=[];signatures=[];sign_stats=[]
        negative=dict(wrong_identity_accepted=0,changed_message_accepted=0,changed_signature_accepted=0)
        for i in range(32):
            user=i%2;message=hashlib.sha256(b"XIE-STUDY independent message/"+i.to_bytes(4,"big")).digest()
            stats={};signature=runtime.sign(keys[user],message,rng=source,stats=stats)
            assert verify(public,identities[user],message,signature)
            raw=signature.to_bytes();(directory/f"signature-{i:03}.bin").write_bytes(raw)
            from dataclasses import replace
            changed=replace(signature,z1=(signature.z1[0]+1,)+signature.z1[1:])
            negative["wrong_identity_accepted"]+=int(verify(public,identities[1-user],message,signature))
            negative["changed_message_accepted"]+=int(verify(public,identities[user],bytes([message[0]^1])+message[1:],signature))
            negative["changed_signature_accepted"]+=int(verify(public,identities[user],message,changed))
            cases.append(dict(user=user,message_hex=message.hex()));signatures.append(signature);sign_stats.append(stats)
        manifest=dict(identities_hex=[x.hex() for x in identities],cases=cases)
        write_json(directory/"cases.json",manifest)
        receipt["sign"]=dict(seconds=time.perf_counter()-tick,signatures=32,message_bytes=32,
            signature_bytes=[len(s.to_bytes()) for s in signatures],stats=sign_stats,
            raw_negative_observations=negative,each_negative_trials=32)
        stage="strict_objects";strict_count=0
        for obj,decoder in ((public,Public.from_bytes),(master,Master.from_bytes),
                            (keys[0],IdentitySecret.from_bytes),(signatures[0],Signature.from_bytes)):
            raw=obj.to_bytes();assert decoder(raw).to_bytes()==raw
            for changed in (raw[:-1],raw+b"!",raw+b" ",
                            raw.replace(b'"kind":',b'"kind":"duplicate","kind":'),
                            raw.replace(b'"fields":',b'"extra":0,"fields":')):
                try:decoder(changed)
                except SerializationError:strict_count+=1
                else:raise AssertionError("strict malformed object accepted")
        receipt["strict_objects"]=dict(types=4,malformed_rejected=strict_count)
        stage="public_attacks";tick=time.perf_counter()
        shifted=modulus_shift(public,identities[0],bytes.fromhex(cases[0]["message_hex"]),signatures[0])
        receipt["public_attacks"]=dict(seconds=0,
            modulus_shift=dict(status="witness_found" if shifted else "no_witness",
                identity_hex=identities[0].hex(),message_hex=cases[0]["message_hex"],
                original_signature_hex=signatures[0].to_bytes().hex(),
                alternative_signature_hex=shifted.to_bytes().hex() if shifted else None,private_material_used=False),
            zero_challenge=zero_challenge_forgery(public,max_trials=2**22))
        receipt["public_attacks"]["seconds"]=time.perf_counter()-tick
        stage="fresh_process_restore";receipt["restore"]=subprocess_mode(directory,"--restore-only")
        stage="fresh_restored_key_sign";receipt["restored_sign"]=subprocess_mode(directory,"--sign-restored")
        after=source_fingerprints()
        assert before==source_snapshot(),"research/package source files changed during the run"
        assert all(before.get(item["path"])==item["sha256"] for item in after.values()),"unbound provider"
        cpu=next((line.split(":",1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                  if line.startswith("model name")),platform.processor())
        receipt.update(schema="XIE-CORRECTED-EQUATION-STUDY-RUN/1",status="passed",
            source_commit=source_commit,providers=after,source_unchanged=True,params=p.record(),
            public_hex=public.to_bytes().hex(),public_sha256=digest(public.to_bytes()),
            algorithm=report(),entropy_bytes=source.bytes,entropy_reads=source.reads,
            total_seconds=time.perf_counter()-started,peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            environment=dict(python=sys.version,platform=platform.platform(),cpu=cpu,sage=sage_version),
            repetitions=1,ROM_instantiation="domain-separated SHAKE256; no QROM admission",
            literal_source_reproduction=False,common_IBSBackend=False,
            safety_statement="Teaching/research parameters; functional tests do not replace a security proof",
            security_claim="none",backend_admitted=False,parameters_are_formal=False)
        write_json(directory/"receipt.json",receipt)
        return dict(status="passed",n=n,signatures=32,restored=receipt["restore"]["verified"],
            restored_new_signatures=2,seconds=receipt["total_seconds"],
            modulus_shift=receipt["public_attacks"]["modulus_shift"]["status"],
            zero_challenge=receipt["public_attacks"]["zero_challenge"]["status"])
    except BaseException as exc:
        write_json(directory/"failure.json",dict(status="failed",stage=stage,error=type(exc).__name__,
            detail=str(exc),seconds=time.perf_counter()-started,partial_public_receipt=receipt,
            private_outputs_preserved=True,no_outer_retry=True))
        raise


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-directory",type=Path,required=True)
    modes=parser.add_mutually_exclusive_group()
    modes.add_argument("--restore-only",action="store_true");modes.add_argument("--sign-restored",action="store_true")
    parser.add_argument("--n",type=int,choices=(16,32),default=16)
    parser.add_argument("--source-commit",default="unrecorded")
    args=parser.parse_args();directory=args.private_directory.resolve()
    if args.restore_only:result=replay(directory)
    elif args.sign_restored:result=sign_restored(directory)
    else:result=generate(directory,args.n,args.source_commit)
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":main()
