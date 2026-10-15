"""Unconditioned, fixed-attempt Yu research audit; no secret material exported."""
from dataclasses import asdict, replace
import hashlib
import json
import platform
from pathlib import Path
import statistics
import time

from ibme.ibs.yu import YuIBS,YuParams,PublicKey,MasterSecret,SigningKey,Signature


class NoEntropy:
    def read(self,n): raise AssertionError("cache/verify must not request entropy")


def run(attempts=3):
    if type(attempts) is not int or not 1<=attempts<=20: raise ValueError("attempts in 1..20")
    from experiments.research.candidates.yu.standalone import Signature as RawSignature
    from sage.env import SAGE_VERSION
    repo=Path(__file__).resolve().parents[2]
    sources=sorted((repo/"src/ibme/ibs/yu").glob("*.py"))+sorted((repo/"experiments/research/candidates/yu").glob("*.py"))+[Path(__file__).resolve()]
    def hashes():
        return {p.relative_to(repo).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    before=hashes(); p=YuParams(); rows=[]
    timings={k:[] for k in ("setup","key_extract","cached_extract","sign","verify","restore_master","restore_key")}
    sizes={k:[] for k in ("public_key","master_secret","signing_key","signature")}
    counts=dict(roots=0,users=0,signatures=0,verifications=0,restored_key_signatures=0,
        wrong_identity_accepts=0,wrong_message_accepts=0,public_forgery_accepts=0,
        wrong_context_rejects=0,truncated_rejects=0)
    identities=(b"A",b"\xff"); messages=(b"",b"M",b"\0")
    def timed(name,fn):
        start=time.perf_counter()
        try: return fn()
        finally: timings[name].append(time.perf_counter()-start)
    for attempt in range(attempts):
        stage="setup"; completed=0
        try:
            b=YuIBS(); pk,master=timed(stage,lambda:b.setup(p)); counts["roots"]+=1
            sizes["public_key"].append(len(pk.to_bytes()))
            for identity in identities:
                stage="key_extract"; key=timed(stage,lambda:b.key_extract(master,identity)); counts["users"]+=1
                sizes["signing_key"].append(len(key.to_bytes()))
                stage="restore_key"; restored=timed(stage,lambda:SigningKey.from_bytes(key.to_bytes()))
                assert restored==key
                for message in messages:
                    stage="sign"; sig=timed(stage,lambda:b.sign(key,message)); counts["signatures"]+=1
                    sizes["signature"].append(len(sig.to_bytes()))
                    stage="verify"; assert timed(stage,lambda:YuIBS(NoEntropy()).verify(pk,identity,message,sig))
                    counts["verifications"]+=1; completed+=1
                    assert b.load_signature(pk,sig.to_bytes())==sig
                    assert b.verify(PublicKey.from_bytes(pk.to_bytes()),identity,message,sig)
                    stage="negative_checks"
                    counts["wrong_identity_accepts"]+=b.verify(pk,b"B",message,sig)
                    counts["wrong_message_accepts"]+=b.verify(pk,identity,b"N",sig)
                    assert not b.verify(pk,identity,message,replace(sig,context=bytes(32)))
                    counts["wrong_context_rejects"]+=1
                    from ibme.core.errors import SerializationError
                    try: b.load_signature(pk,sig.to_bytes()[:-1])
                    except SerializationError: counts["truncated_rejects"]+=1
                    else: raise AssertionError("truncated signature accepted")
                stage="restored_sign"
                restored_sig=b.sign(restored,b"M")
                assert b.verify(pk,identity,b"M",restored_sig)
                counts["restored_key_signatures"]+=1
            stage="restore_master"
            restored_master=timed(stage,lambda:MasterSecret.from_bytes(master.to_bytes()))
            sizes["master_secret"].append(len(master.to_bytes()))
            for identity in identities:
                stage="cached_extract"
                assert timed(stage,lambda:YuIBS(NoEntropy()).key_extract(restored_master,identity)).to_bytes()==master._keys[identity].to_bytes()
            stage="public_forgery"
            forged=Signature(pk.context,RawSignature((p.q,)+(0,)*(p.signature_dimension-1),
                (0,)*p.output_bits,(0,)*p.output_bits,(0,)*p.salt_bits))
            assert b.verify(pk,b"B",b"N",forged); counts["public_forgery_accepts"]+=1
            rows.append(dict(attempt=attempt+1,status="completed",honest_signatures=completed))
        except Exception as exc:
            # Keep failed attempts; never rerun until success, log exception
            # messages containing private sampler geometry, or export state.
            rows.append(dict(attempt=attempt+1,status="failed",stage=stage,
                exception_type=type(exc).__name__,honest_signatures=completed))
    if hashes()!=before: raise RuntimeError("source changed during evidence collection")
    return dict(schema="IBME/Yu-BYTE-BACKEND-AUDIT/1",parameters=asdict(p),attempts=rows,counts=counts,
        all_requested_attempts_completed=all(r["status"]=="completed" for r in rows),
        security_claim="none",backend_admitted=False,parameters_are_formal=False,
        randomness="OS CSPRNG; independent roots, no conditioning/retries; no ROM in Yu core",
        identity_bytes=[len(x) for x in identities],message_bytes=[len(x) for x in messages],
        sizes_bytes=sizes,timings={k:dict(samples=v,median=statistics.median(v) if v else None) for k,v in timings.items()},
        environment=dict(os=platform.platform(),machine=platform.machine(),processor=platform.processor(),
            python=platform.python_version(),sage=SAGE_VERSION,constant_time=False,
            acceleration="no backend acceleration requested; Sage exact integer implementation"),
        source_sha256=before,limitations=["q=3 is publicly forgeable; mutation acceptance is expected and reported",
            "New byte-domain PRF n=1 differs from legacy bit-domain PRF n=2; not a fair performance comparison",
            "Includes compilation and validation; no secure-parameter timing claim",
            "No private keys, seeds, state, witnesses or actual signatures exported",
            "No Wang combination, key-input NC1 family proof, Lemma7 mapping or security admission"])


if __name__=="__main__":
    import argparse
    parser=argparse.ArgumentParser(); parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--attempts",type=int,default=3); args=parser.parse_args()
    result=run(args.attempts); args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print(json.dumps({k:result[k] for k in ("all_requested_attempts_completed","counts","attempts")}))
    raise SystemExit(0 if result["all_requested_attempts_completed"] else 1)
