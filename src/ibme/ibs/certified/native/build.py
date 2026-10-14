"""Build unchanged pinned ML-DSA reference C with explicit nonce-limit wrappers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

HERE=Path(__file__).resolve().parent
PREFIX=Path.home()/".cache/ibme-native-tools/certified-signatures-v1"
MODES={44:2,65:3,87:5}


def source_id():
    data=json.loads((HERE/"upstream/UPSTREAM.json").read_text(encoding="utf-8"))
    fingerprints={}
    for name,info in data["files"].items():
        raw=(HERE/"upstream"/name).read_bytes()
        digest=hashlib.sha256(raw).hexdigest()
        if digest!=info["sha256"]:raise RuntimeError("ML-DSA vendor source mismatch")
        fingerprints[name]=digest
    for name in ("bridge.c","build.py"):
        fingerprints[name]=hashlib.sha256((HERE/name).read_bytes()).hexdigest()
    return hashlib.sha256(json.dumps(fingerprints,sort_keys=True,separators=(",",":")).encode()).hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--prefix",type=Path,default=PREFIX)
    a=p.parse_args()
    if os.name!="posix":raise RuntimeError("Build ML-DSA using WSL; no compiler fallback")
    fingerprint=source_id();a.prefix.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mldsa-build-",dir=a.prefix) as tmp:
        output=Path(tmp);records=[]
        sources=sorted(str(f) for f in (HERE/"upstream/ref").glob("*.c") if f.name!="randombytes.c")
        for parameter,mode in MODES.items():
            binary=output/f"ibme-mldsa{parameter}"
            wrapper=f"pqcrystals_dilithium{mode}_ref_polyvecl_uniform_gamma1"
            command=["gcc","-O2","-std=c99","-fwrapv",f"-DDILITHIUM_MODE={mode}",
                '-DIBME_SOURCE_ID="'+fingerprint+'"',"-I"+str(HERE/"upstream/ref"),
                str(HERE/"bridge.c"),*sources,"-Wl,--wrap="+wrapper,"-o",str(binary)]
            result=subprocess.run(command,capture_output=True,timeout=120)
            if result.returncode:
                (a.prefix/f"compiler-{parameter}.log").write_bytes(result.stderr)
                raise RuntimeError("ML-DSA compile failed; compiler log retained at prefix")
            meta=json.loads(subprocess.run([str(binary),"meta"],input=b"",capture_output=True,check=True).stdout)
            if meta["source_id"]!=fingerprint or meta["mode"]!=mode:raise RuntimeError("ML-DSA build ABI mismatch")
            destination=a.prefix/"bin"/binary.name;destination.parent.mkdir(exist_ok=True)
            shutil.copyfile(binary,destination);destination.chmod(0o700)
            records.append(dict(parameter_set=f"ML-DSA-{parameter}",executable=str(destination),
                binary_sha256=hashlib.sha256(destination.read_bytes()).hexdigest(),metadata=meta))
    report=dict(status="built",source_id=fingerprint,source_patch_count=0,
        linker_wrapper="bounded 16-bit ExpandMask nonce, no seed retry",
        compiler=subprocess.run(["gcc","--version"],capture_output=True,text=True).stdout.splitlines()[0],
        binaries=records,security_claim="none",backend_admitted=False,parameters_are_formal=False)
    (a.prefix/"build.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(report))


if __name__=="__main__":main()
