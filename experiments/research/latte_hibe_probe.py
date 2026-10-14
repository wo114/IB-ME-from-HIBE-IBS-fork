"""Same-instance LATTE-3 HIBE lifecycle, 2x2 identities and fresh-process reuse.

All keys/ciphertexts stay in an exclusive ignored private directory. Public
receipts contain counters, source fingerprints and stage results, never secrets.
This is an independent HIBE experiment, not a HIBE+IBS combination.
"""
import argparse
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import sys
import tempfile
import time
import traceback
from unittest.mock import patch

from ibme.core.randomness import SecureRandom
from ibme.core.errors import SerializationError
from ibme.hibe.latte import (LATTEHIBE,LATTEParams,LATTEPublicKey,LATTEMasterSecret,
    LATTELevel1SecretKey,LATTELevel2SecretKey,LATTECiphertext)
from ibme.hibe.latte.engine import Native
from ibme.hibe.latte.params import Q

RECEIVERS=(b"R"*85+b"0",b"R"*85+b"1")
SENDERS=(b"S"*85+b"0",b"S"*85+b"1")
MESSAGE=hashlib.sha256(b"LATTE-3 independent honest-noise HIBE lifecycle").digest()


class CountedSystem:
    def __init__(self): self.source=SecureRandom(); self.bytes=0
    def read(self,n):
        value=self.source.read(n); self.bytes+=len(value); return value


def save(path,value):
    data=value if type(value) is bytes else (json.dumps(value,indent=2)+"\n").encode()
    with tempfile.NamedTemporaryFile(dir=path.parent,prefix=".latte-",delete=False) as stream:
        temporary=Path(stream.name); stream.write(data)
    os.replace(temporary,path)


def sources():
    root=Path(__file__).resolve().parents[2]
    paths=[Path(__file__).resolve()]
    paths.extend(p for p in (root/"src/ibme/hibe/latte").rglob("*")
        if p.suffix in (".py",".c",".h",".json") or p.name=="LICENSE")
    paths.extend(root/"src/ibme/core"/name for name in ("encoding.py","types.py","randomness.py","errors.py"))
    return {str(p.relative_to(root)).replace("\\","/"):hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(paths)}


def restore(directory):
    calls=[]; entropy=0
    original=Native.call
    def no_entropy(*args,**kwargs):
        nonlocal entropy
        entropy+=1
        raise AssertionError("restore consumed private entropy")
    def checked(self,operation,data):
        calls.append(operation)
        if operation in ("setup","delegate","extract","encrypt"):
            raise AssertionError("restore regenerated a key/ciphertext")
        return original(self,operation,data)
    with patch.object(SecureRandom,"read",no_entropy),patch.object(Native,"call",checked):
        b=LATTEHIBE()
        pk=LATTEPublicKey.from_bytes((directory/"public.bin").read_bytes())
        mraw=(directory/"master.bin").read_bytes(); master=LATTEMasterSecret.from_bytes(mraw)
        for i,rcv in enumerate(RECEIVERS):
            parent=b.extract(master,rcv)
            if parent.to_bytes()!=(directory/f"parent-{i}.bin").read_bytes():
                raise ValueError("restored receiver differs")
            for j,snd in enumerate(SENDERS):
                leaf=b.derive(parent,snd)
                if leaf.to_bytes()!=(directory/f"leaf-{i}-{j}.bin").read_bytes():
                    raise ValueError("restored leaf differs")
                ct=b.load_ciphertext((directory/f"cipher-{i}-{j}.bin").read_bytes())
                if b.decrypt(leaf,ct)!=MESSAGE:
                    raise ValueError("restored ciphertext did not recover message")
        if master.to_bytes()!=mraw or master.public_key.to_bytes()!=pk.to_bytes():
            raise ValueError("restore changed fixed private state")
    return dict(status="passed",fresh_process=True,external_entropy_calls=entropy,
        key_or_ciphertext_generations=0,matched_decryptions=4,
        native_operations=calls,reencryption_check_uses_original_deterministic_binomial_sampler=True)


def run(args):
    directory=args.private_directory
    if args.restore_only:
        print(json.dumps(restore(directory)));return 0
    os.umask(0o077)
    directory.mkdir(parents=True,mode=0o700)  # Existing attempts are never restarted/overwritten.
    p=LATTEParams(); source=CountedSystem()
    report=dict(schema="LATTE3-HIBE-REAL/1",status="started",source_commit=args.source_commit,
        parameters=p.record(),repetitions=1,identity_bytes_per_level=86,message_bytes=32,
        root_generations=0,parent_delegations=0,terminal_extracts=0,stages=[],
        external_entropy="system CSPRNG seeds; leaf Extract retains original public-target seeded AES sampler",
        internal_AES_expansion_bytes_measured=None,source_sha256_before=sources(),
        independent_HIBE=True,HIBE_IBS_combination=False,anonymous_security_verified=False,
        finite_sampler_total_TV_or_RD=None,whole_failure_bound=None,
        security_claim="none",backend_admitted=False,parameters_are_formal=False,
        environment=dict(python=sys.version.split()[0],platform=platform.platform()))
    started=time.monotonic()
    master=None
    def pending(owner):
        # Shared tree RLock makes whole-tree pending persistence safe under a
        # receiver's lock. This probe is one writer, not an anti-rollback store.
        save(directory/"master.bin",master.to_bytes())
    backend=LATTEHIBE(persist_pending=pending)
    def stage(name,operation):
        report["current_stage"]=name; save(directory/"receipt.json",report)
        start=time.monotonic(); before=source.bytes
        result=operation()
        entry=dict(name=name,seconds=time.monotonic()-start,external_seed_bytes=source.bytes-before)
        report["stages"].append(entry); save(directory/"receipt.json",report)
        print(json.dumps(entry),flush=True)
        return result
    try:
        engine=Native(p)
        report["native_binary_sha256_before"]=engine.binary_sha256
        report["native_source_id"]=json.loads(engine.call("meta",b""))["source_id"]
        pk,master=stage("real-NTRU-root",lambda:backend.setup(p,rng=source))
        report["root_generations"]=1
        save(directory/"public.bin",pk.to_bytes()); save(directory/"master.bin",master.to_bytes())
        parents=[]; leaves={}; ciphertexts={}
        for i,rcv in enumerate(RECEIVERS):
            parent=stage(f"real-Delegate-receiver-{i}",lambda rcv=rcv:backend.extract(master,rcv,rng=source))
            parents.append(parent); report["parent_delegations"]+=1
            for j,snd in enumerate(SENDERS):
                leaf=stage(f"real-Extract-leaf-{i}-{j}",lambda parent=parent,snd=snd:backend.derive(parent,snd,rng=source))
                leaves[i,j]=leaf; report["terminal_extracts"]+=1
                save(directory/f"leaf-{i}-{j}.bin",leaf.to_bytes())
                save(directory/"master.bin",master.to_bytes())
            save(directory/f"parent-{i}.bin",parent.to_bytes())
        def encrypt_decrypt():
            matched=mismatched=tamper=parse_reject=0
            for (i,j),leaf in leaves.items():
                ct=backend.encrypt(pk,RECEIVERS[i],SENDERS[j],MESSAGE,rng=source)
                ciphertexts[i,j]=ct; save(directory/f"cipher-{i}-{j}.bin",ct.to_bytes())
                for path,key in leaves.items():
                    result=backend.decrypt(key,ct)
                    if path==(i,j):
                        if result!=MESSAGE: raise ValueError("matching HIBE decryption failed")
                        matched+=1
                    else:
                        if result is not None: raise ValueError("mismatched identity accepted")
                        mismatched+=1
                for index in range(4):
                    if index==0:
                        altered=replace(ct,z=bytes([ct.z[0]^1])+ct.z[1:])
                    else:
                        values=[list(row) for row in ct.c]
                        values[index-1][0]=(values[index-1][0]+1)%Q
                        altered=replace(ct,c=values)
                    if backend.decrypt(leaf,altered) is not None: raise ValueError("modified ciphertext accepted")
                    tamper+=1
                raw=ct.to_bytes()
                for bad in (raw[:-1],raw+b"x",b'{"schema":"duplicate",'+raw[1:]):
                    try: backend.load_ciphertext(bad)
                    except SerializationError: parse_reject+=1
                    else: raise ValueError("malformed wire accepted")
                if any(value in raw or value.hex().encode() in raw for value in (*RECEIVERS,*SENDERS)):
                    raise ValueError("clear identity present in ciphertext")
            report["checks"]=dict(matched=matched,identity_mismatch_rejected=mismatched,
                native_reencryption_tamper_rejected=tamper,malformed_ciphertext_rejected=parse_reject,
                ciphertext_has_no_clear_identity=True)
        stage("same-root-2x2-honest-noise-and-negative-checks",encrypt_decrypt)
        def objects():
            all_objects=[pk,master,*parents,*leaves.values(),*ciphertexts.values()]
            for obj in all_objects:
                if type(obj).from_bytes(obj.to_bytes()).to_bytes()!=obj.to_bytes():
                    raise ValueError("object roundtrip changed bytes")
            report["objects"]=dict(kinds=5,instances=len(all_objects),canonical_roundtrips=True,
                public_bytes=len(pk.to_bytes()),master_snapshot_bytes=len(master.to_bytes()),
                parent_snapshot_bytes=[len(v.to_bytes()) for v in parents],
                leaf_bytes=[len(v.to_bytes()) for v in leaves.values()],
                ciphertext_bytes=[len(v.to_bytes()) for v in ciphertexts.values()])
        stage("five-object-kinds-precise-math-and-roundtrips",objects)
        def fresh_restore():
            result=subprocess.run([sys.executable,"-m","experiments.research.latte_hibe_probe",
                "--private-directory",str(directory.resolve()),"--restore-only"],capture_output=True,timeout=60)
            if result.returncode:
                save(directory/"private-restore-error.txt",result.stderr)
                raise ValueError("fresh-process restore failed")
            report["restore"]=json.loads(result.stdout)
        stage("fresh-process-zero-entropy-and-fixed-keys",fresh_restore)
        report.update(status="passed",native_binary_sha256_after=Native(p).binary_sha256)
    except Exception as exc:
        report.update(status="failed",error_type=type(exc).__name__,automatic_retry=False)
        save(directory/"private-error.txt",traceback.format_exc().encode())
        raise
    finally:
        report.update(seconds=time.monotonic()-started,external_seed_bytes=source.bytes,
            parent_peak_RSS_KiB=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            maximum_observed_direct_child_RSS_KiB=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
            source_sha256_after=sources())
        report["source_unchanged"]=report["source_sha256_before"]==report["source_sha256_after"]
        save(directory/"receipt.json",report)
    if (not report["source_unchanged"] or report["native_binary_sha256_before"]!=report["native_binary_sha256_after"]):
        report.update(status="failed",error_type="SourceChanged"); save(directory/"receipt.json",report)
        raise RuntimeError("LATTE lifecycle source/binary changed during execution")
    save(directory/"completed",b"passed\n")
    print(json.dumps(dict(status="passed",seconds=report["seconds"],checks=report["checks"],restore=report["restore"])),flush=True)
    return 0


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--private-directory",type=Path,required=True)
    p.add_argument("--source-commit")
    p.add_argument("--restore-only",action="store_true")
    args=p.parse_args()
    if not args.restore_only and not args.source_commit:
        p.error("explicit frozen source commit required")
    return run(args)


if __name__=="__main__":
    raise SystemExit(main())
