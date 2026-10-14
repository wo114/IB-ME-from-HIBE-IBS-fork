"""Build pinned Falcon v1.2, fixed padded codecs and finite stream guards."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

HERE=Path(__file__).resolve().parent
PREFIX=Path.home()/".cache/ibme-native-tools/certified-falcon-v1"
DEFINES={"FALCON_FPEMU":1,"FALCON_FPNATIVE":0,"FALCON_AVX2":0,"FALCON_FMA":0,
         "FALCON_ASM_CORTEXM4":0,"FALCON_KG_CHACHA20":0,"FALCON_RAND_GETENTROPY":0,
         "FALCON_RAND_URANDOM":0,"FALCON_RAND_WIN32":0}


def source_id():
    manifest=json.loads((HERE/"upstream/UPSTREAM.json").read_text(encoding="utf-8"))
    hashes={}
    for name,info in manifest["files"].items():
        digest=hashlib.sha256((HERE/"upstream"/name).read_bytes()).hexdigest()
        if digest!=info["sha256"]:raise RuntimeError("Falcon vendor source mismatch")
        hashes[name]=digest
    for name in ("bridge.c","build.py","upstream/UPSTREAM.json"):
        hashes[name]=hashlib.sha256((HERE/name).read_bytes()).hexdigest()
    return hashlib.sha256(json.dumps(hashes,sort_keys=True,separators=(",",":")).encode()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix",type=Path,default=PREFIX)
    parser.add_argument("--selftest",action="store_true")
    args=parser.parse_args()
    if os.name!="posix":raise RuntimeError("Build Falcon in WSL; no fallback")
    fingerprint=source_id();args.prefix.mkdir(parents=True,exist_ok=True)
    sources=[str(HERE/"upstream"/name) for name in
             ("codec.c","common.c","falcon.c","fft.c","fpr.c","keygen.c","rng.c","shake.c","sign.c","vrfy.c")]
    flags=["gcc","-O2","-std=c99","-fwrapv",*[f"-D{k}={v}" for k,v in DEFINES.items()],
           '-DIBME_SOURCE_ID="'+fingerprint+'"',"-I"+str(HERE/"upstream")]
    records=[]
    with tempfile.TemporaryDirectory(prefix="falcon-build-",dir=args.prefix) as temporary:
        out=Path(temporary)
        for degree,logn in ((512,9),(1024,10)):
            for vector in (False,True):
                name=f"ibme-falcon{'-kat' if vector else ''}{degree}"
                target=out/name
                command=[*flags,f"-DIBME_LOGN={logn}",f"-DIBME_VECTOR_DRIVER={int(vector)}",
                    str(HERE/"bridge.c"),*sources,"-Wl,--wrap=falcon_inner_i_shake256_extract",
                    "-Wl,--wrap=falcon_inner_prng_refill","-o",str(target)]
                result=subprocess.run(command,capture_output=True,timeout=120)
                if result.returncode:
                    (args.prefix/f"compiler-{name}.log").write_bytes(result.stderr)
                    raise RuntimeError("Falcon compile failed; compiler log retained at prefix")
                meta=json.loads(subprocess.run([str(target),"meta"],input=b"",capture_output=True,check=True).stdout)
                if meta["source_id"]!=fingerprint or meta["logn"]!=logn or meta["vector_driver"]!=vector:
                    raise RuntimeError("Falcon build ABI mismatch")
                dest=args.prefix/"bin"/name;dest.parent.mkdir(exist_ok=True)
                shutil.copyfile(target,dest);dest.chmod(0o700)
                records.append(dict(name=name,binary_sha256=hashlib.sha256(dest.read_bytes()).hexdigest(),metadata=meta))
        if args.selftest:
            target=out/"test_falcon"
            result=subprocess.run([*flags,str(HERE/"upstream/test_falcon.c"),*sources,"-lm","-o",str(target)],
                                  capture_output=True,timeout=120)
            (args.prefix/"selftest-compiler.log").write_bytes(result.stderr)
            if result.returncode:raise RuntimeError("Falcon author selftest compile failed")
            dest=args.prefix/"bin/test_falcon";shutil.copyfile(target,dest);dest.chmod(0o700)
    report=dict(status="built",source_id=fingerprint,source_patch_count=0,defines=DEFINES,
        stream_limits=dict(shake_extract_bytes=16777216,prng_refills=65536,timeout_seconds="caller:1..300"),
        compiler=subprocess.run(["gcc","--version"],capture_output=True,text=True).stdout.splitlines()[0],
        binaries=records,author_selftest_built=args.selftest,security_claim="none",backend_admitted=False,
        parameters_are_formal=False)
    (args.prefix/"build.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(report))


if __name__=="__main__":main()
