"""Actual Table 6 RSIS lifecycle; public receipts only, private state separate."""
import argparse
import gc
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import resource
import sys
from time import perf_counter
import numpy as np
from ibme.core.randomness import SecureRandom
from .backend import RingBackend
from .params import published,small
from .objects import PublicKey,Signature
from .issuer import FixedIssuer,_read
from . import codec

IDENTITY=b"Sageloli target Alice"
MESSAGE=b"Sageloli full parameter message!!"


def require(condition,message):
    if not condition:raise AssertionError(message)


def negative_checks(backend,pk,sig):
    p=pk.params;checks={}
    checks["wrong_identity"]=not backend.verify(pk,b"Sageloli target Bob",MESSAGE,sig)
    checks["wrong_message"]=not backend.verify(pk,IDENTITY,b"different message",sig)
    z=sig.z.copy();z[0,0]+=1
    altered=Signature(pk.context,sig.identity_salt,sig.message_salt,z,p)
    checks["changed_response"]=not backend.verify(pk,IDENTITY,MESSAGE,altered)
    for name,identity_salt,message_salt,context in (
            ("identity_salt",bytes([sig.identity_salt[0]^1])+sig.identity_salt[1:],sig.message_salt,pk.context),
            ("message_salt",sig.identity_salt,bytes([sig.message_salt[0]^1])+sig.message_salt[1:],pk.context),
            ("public_context",sig.identity_salt,sig.message_salt,b"x"*32)):
        other=Signature(context,identity_salt,message_salt,sig.z,p)
        checks[name]=not backend.verify(pk,IDENTITY,MESSAGE,other)
    zero=Signature(pk.context,sig.identity_salt,sig.message_salt,np.zeros_like(sig.z),p)
    checks["zero_response"]=not backend.verify(pk,IDENTITY,MESSAGE,zero)
    raw=sig.to_bytes()
    for name,data in (("truncated",raw[:-1]),("appended",raw+b"x"),
                      ("duplicate_field",codec.frame(b"signature",[pk.context,sig.identity_salt,
                       sig.message_salt,codec.tensor(sig.z,sig.z.shape,64,signed=True),b"duplicate"]))):
        try:backend.load_signature(pk,data)
        except (ValueError,TypeError):checks[name]=True
        else:checks[name]=False
    if not all(checks.values()):raise AssertionError("negative control failed")
    return checks


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile",choices=["I","II","small"],required=True)
    parser.add_argument("--mode",choices=["fresh","recover"],required=True)
    parser.add_argument("--private-directory",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--native",type=Path,required=True)
    parser.add_argument("--source-commit",required=True)
    parser.add_argument("--max-seconds",type=int,default=14400)
    parser.add_argument("--max-peak-bytes",type=int,default=12<<30)
    args=parser.parse_args()
    if args.output.exists():raise ValueError("receipt exists; preserve it and choose a fresh output")
    args.output.parent.mkdir(parents=True,exist_ok=True)
    params=small() if args.profile=="small" else published(args.profile)
    start=perf_counter();timings={};report=dict(status="running",profile=args.profile,mode=args.mode,
        source_commit=args.source_commit,parameters=params.record(),modulus=str(params.q),
        identity_bytes=len(IDENTITY),message_bytes=len(MESSAGE),repetitions=1,
        randomness="operating-system SecureRandom; no seed persisted",ROM="SHAKE256 implementation of paper hash interfaces",
        security_claim="none",backend_admitted=False,parameters_are_formal=False,
        limits=dict(seconds=args.max_seconds,peak_bytes=args.max_peak_bytes,entropy_bytes=256<<30),
        timings=timings,source_sha256={p.name:sha256(p.read_bytes()).hexdigest()
            for p in sorted(Path(__file__).parent.glob("*")) if p.suffix in (".py",".cpp")},
        environment=dict(python=sys.version,platform=platform.platform(),numpy=np.__version__,
            threads={k:os.environ.get(k) for k in ("OMP_NUM_THREADS","OPENBLAS_NUM_THREADS")}))

    def save():
        report["elapsed_seconds"]=perf_counter()-start
        report["peak_rss_bytes"]=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024
        pending=args.output.with_suffix(".pending")
        pending.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
        pending.replace(args.output)

    def progress(stage,current,total):
        report["stage"]=stage;report["stage_current"]=current;report["stage_total"]=total
        if current==1 or current==total or current%8==0:
            save();print(json.dumps(dict(stage=stage,current=current,total=total,
                elapsed=round(perf_counter()-start,2),peak=report["peak_rss_bytes"])),flush=True)
        if perf_counter()-start>args.max_seconds or resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024>args.max_peak_bytes:
            raise RuntimeError("declared experiment resource guard reached")

    def timed(name,fn):
        report["stage"]=name;save();t=perf_counter();result=fn();timings[name]=perf_counter()-t;save()
        print(json.dumps(dict(completed=name,seconds=round(timings[name],3))),flush=True)
        return result

    class NoEntropy:
        def read(self,n):raise AssertionError("restore consumed fresh entropy")

    try:
        backend=RingBackend(SecureRandom() if args.mode=="fresh" else NoEntropy(),native_path=args.native,progress=progress)
        report["native"]=backend.library.metadata()
        issuer=FixedIssuer(args.private_directory,backend,expected_params=params)
        if args.mode=="fresh":
            if args.private_directory.exists():raise ValueError("fresh experiment needs a new private directory")
            pk=timed("setup",lambda:issuer.initialize(params))
            key=timed("extract",lambda:issuer.key_extract(IDENTITY))
            sig=timed("first_sign",lambda:backend.sign(key,MESSAGE))
            report["sampler"]=key._plan.certificate()
            require(timed("verify",lambda:backend.verify(pk,IDENTITY,MESSAGE,sig)),"honest signature rejected")
            report["negative_controls"]=timed("negative_controls",lambda:negative_checks(backend,pk,sig))
            second=timed("second_sign",lambda:backend.sign(key,MESSAGE+b"2"))
            require(backend.verify(pk,IDENTITY,MESSAGE+b"2",second),"second signature rejected")
            require(backend.verify(pk,IDENTITY,MESSAGE,backend.load_signature(pk,sig.to_bytes())),"signature recovery rejected")
            (args.private_directory/"public.bin").write_bytes(pk.to_bytes())
            signature_path=args.private_directory/"signature.bin"
            fd=os.open(signature_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,"wb") as f:f.write(sig.to_bytes())
            report["sizes_bytes"]=dict(public=len(pk.to_bytes()),master_state=(args.private_directory/"master.bin").stat().st_size,
                signing_key=len(key.to_bytes()),signature=len(sig.to_bytes()))
            report["signatures_verified"]=2;report["entropy_bytes_consumed"]=backend.source.used
        else:
            pk=PublicKey.from_bytes(_read(args.private_directory/"public.bin"))
            issuer.expected_public=pk
            key=timed("full_master_and_issued_key_recovery",lambda:issuer.key_extract(IDENTITY))
            require(backend.source.used==0,"restore consumed entropy")
            report["restore_entropy_bytes"]=backend.source.used
            sig=backend.load_signature(pk,_read(args.private_directory/"signature.bin"))
            require(timed("verify_saved_signature",lambda:backend.verify(pk,IDENTITY,MESSAGE,sig)),"saved signature rejected")
            backend=RingBackend(SecureRandom(),native_path=args.native,progress=progress)
            new=timed("sign_after_new_process_recovery",lambda:backend.sign(key,MESSAGE+b"recovered"))
            require(backend.verify(pk,IDENTITY,MESSAGE+b"recovered",new),"restored new signature rejected")
            report["signatures_verified"]=2;report["new_sign_entropy_bytes"]=backend.source.used
            report["sampler"]=key._plan.certificate()
        report["status"]="passed";report["stage"]="complete";save()
        print(json.dumps(dict(status="passed",mode=args.mode,profile=args.profile,
                              elapsed=report["elapsed_seconds"],peak=report["peak_rss_bytes"])),flush=True)
    except BaseException as error:
        report["status"]="failed";report["error_type"]=type(error).__name__
        # Messages here originate in this implementation, never serialize private objects.
        report["error"]=str(error)[:300];save();raise


if __name__=="__main__":main()
