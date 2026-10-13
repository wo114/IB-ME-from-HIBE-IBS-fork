"""Full real SRGG IBS lifecycle, no private state/covariance output."""
import argparse
import json
from pathlib import Path
import platform
import sys
from time import perf_counter

from .backend import Backend
from .config import Config
from .objects import MasterSecret, SigningKey


def audit_report(*,repetitions=16,rng=None):
    if type(repetitions) is not int or not 1<=repetitions<=64: raise ValueError("repetitions must be 1..64")
    c,b=Config(),Backend(rng=rng)
    start=perf_counter(); pk,master=b.setup(c); setup_time=perf_counter()-start
    start=perf_counter(); key=b.key_extract(master,b"Alice"); extract_time=perf_counter()-start
    samples=[]; sign_times=[]; verify_times=[]
    for i in range(repetitions):
        msg=b"SRGG-full-research:"+i.to_bytes(4,"big")
        start=perf_counter(); sig=b.sign(key,msg); sign_times.append(perf_counter()-start)
        start=perf_counter(); ok=b.verify(pk,key.identity,msg,sig); verify_times.append(perf_counter()-start)
        samples.append({"message_bytes":len(msg),"signature_bytes":len(sig.to_bytes()),"norm_squared":sum(v*v for poly in sig.z for v in poly),"verified":ok})
    restored_master=MasterSecret.from_bytes(master.to_bytes())
    cached=b.key_extract(restored_master,b"Alice")
    restored_key=SigningKey.from_bytes(key.to_bytes())
    sig=b.sign(restored_key,b"restored")
    return {"schema":"IBME/SRGG-FULL-RESEARCH-IBS/1","parameters":c.record(),
            "implementation":{"algorithms":"SRGG1-8; continuous SampleF+fixed-r rounding; cached identity service",
                              "signature_shape_interpretation":"zeta-consistent factor2; differs from literal Table3 factor1",
                              "wire":"canonical JSON reference, no ANS claim","continuous_stage_total_TV_certified":False},
            "environment":{"python":sys.version.split()[0],"platform":platform.platform(),"rng":"SecureRandom" if rng is None else type(rng).__name__},
            "samples":samples,"wire_bytes":{"public_key":len(pk.to_bytes()),"master_secret_with_one_cached_user":len(master.to_bytes()),
                                             "signing_key":len(key.to_bytes()),"signature_min":min(x["signature_bytes"] for x in samples),
                                             "signature_max":max(x["signature_bytes"] for x in samples)},
            "timings_seconds":{"setup":setup_time,"key_extract":extract_time,"sign":sign_times,"verify":verify_times},
            "honest_verified":sum(x["verified"] for x in samples),"restored_key_verified":b.verify(pk,key.identity,b"restored",sig),
            "restored_cache_same_key":cached.to_bytes()==key.to_bytes(),"Q_gt_2gamma_exact":c.algebra.modulus**2>4*c.signature_bound_squared,
            "full_IBS_implemented":True,"security_claim":"none","backend_admitted":False,
            "limitations":["manual n8 research profile; 8-bit challenge is publicly forgeable by fixed-point enumeration",
                           "floating continuous stage/fixed tickets have no complete total-TV certificate",
                           "HNF key distribution and zeta/Table3 difference not certified as author theorem",
                           "variable time; trusted plaintext cache; no cross-process issuance transaction or rollback protection",
                           "functional complete implementation, not a formal security grade or secure-parameter performance ranking"]}


def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("--repetitions",type=int,default=16); p.add_argument("--output",type=Path)
    args=p.parse_args(); report=audit_report(repetitions=args.repetitions)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
    print(json.dumps({k:report[k] for k in ("honest_verified","restored_key_verified","restored_cache_same_key","wire_bytes","Q_gt_2gamma_exact","security_claim")},ensure_ascii=False))


if __name__=="__main__": main()
