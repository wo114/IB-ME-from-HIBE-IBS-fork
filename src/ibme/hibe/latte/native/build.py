"""Verify vendor snapshot, apply explicit fixes, build using the prescribed Sage prefix.

Run with WSL ~/miniconda3/envs/sage/bin/python -m ibme.hibe.latte.native.build.
The compiler executes in a new temporary directory; original vendor files stay unchanged.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent


def source_id():
    manifest = json.loads((HERE/"upstream/UPSTREAM.json").read_text())
    hashes = {}
    for name, data in manifest["files"].items():
        raw = (HERE/"upstream"/name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != data["sha256"]:
            raise ValueError("LATTE upstream source fingerprint mismatch")
        hashes["upstream/"+name] = data["sha256"]
    for name in ("bridge.c", "shake.c", "build.py", "compat/libXKCP.a.headers/SimpleFIPS202.h"):
        hashes[name] = hashlib.sha256((HERE/name).read_bytes()).hexdigest()
    return hashlib.sha256(json.dumps(hashes,sort_keys=True,separators=(",", ":")).encode()).hexdigest()


def patched(name, original):
    if name == "sample_z.c":
        for old, new in (("load_96(r) + 1", "load_96(r_bm) + 1"),
                         ("load_96(r + 12) + 1", "load_96(r_bm + 12) + 1")):
            if original.count(old) != 1:
                raise ValueError("LATTE exact COSAC patch context mismatch")
            original = original.replace(old, new)
    if name == "fastrandombytes.c":
        original = original.replace("static __m128i iv;", "static __m128i iv;\nstatic uint64_t ibme_ctr_blocks;")
        original = original.replace("iv = _mm_setzero_si128();", "iv = _mm_setzero_si128();\n\tibme_ctr_blocks = 0;")
        old = "\t__m128i tmp;"
        if original.count(old) != 1:
            raise ValueError("LATTE exact AES cap patch context mismatch")
        original = "#include <stdint.h>\n#include <stdlib.h>\n" + original.replace(old,
            old+"\n\tif (++ibme_ctr_blocks > ((uint64_t)1<<27)) _Exit(72);")
    return original


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, default=Path.home()/".cache/ibme-native-tools/latte3-bridge-v1")
    args=parser.parse_args()
    if os.name != "posix":
        raise RuntimeError("Build LATTE in the prescribed WSL Sage environment")
    fingerprint=source_id()
    sage=Path.home()/"miniconda3/envs/sage"
    for name in ("gmp.h", "mpc.h", "mpfr.h", "openssl/evp.h"):
        if not (sage/"include"/name).is_file():
            raise RuntimeError("Missing required Sage prefix development headers")
    args.prefix.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="latte3-build-",dir=args.prefix) as tmp:
        build=Path(tmp)
        for p in (HERE/"upstream").iterdir():
            if p.suffix in (".c", ".h"):
                (build/p.name).write_text(patched(p.name,p.read_text()))
        shutil.copytree(HERE/"compat",build/"compat")
        for name in ("bridge.c", "shake.c"):
            shutil.copyfile(HERE/name,build/name)
        sources=[str(p) for p in sorted(build.glob("*.c")) if p.name not in ("test.c","randombytes.c","cpucycles.c")]
        cmd=["gcc","-O2","-march=native","-fwrapv","-include","string.h",
            "-I"+str(build),"-I"+str(build/"compat"),"-I"+str(sage/"include"),
            '-DIBME_LATTE_SOURCE_ID="'+fingerprint+'"',*sources,"-L"+str(sage/"lib"),
            "-Wl,-rpath,"+str(sage/"lib"),"-lgmp","-lmpfr","-lmpc","-lcrypto","-lquadmath","-o",str(build/"ibme-latte3")]
        result=subprocess.run(cmd,capture_output=True,timeout=120)
        if result.returncode:
            (args.prefix/"compiler-error.log").write_bytes(result.stderr)
            raise RuntimeError("LATTE compile failed; compiler log retained at prefix")
        binary=args.prefix/"bin/ibme-latte3"
        binary.parent.mkdir(exist_ok=True)
        shutil.copyfile(build/"ibme-latte3",binary); binary.chmod(0o700)
        meta=json.loads(subprocess.run([str(binary),"meta"],input=b"",capture_output=True,check=True).stdout)
        if meta["source_id"] != fingerprint:
            raise RuntimeError("LATTE compiled source mismatch")
        receipt=dict(status="built",source_id=fingerprint,binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
            executable=str(binary),compiler=subprocess.run(["gcc","--version"],capture_output=True,text=True).stdout.splitlines()[0],
            flags=["-O2","-march=native","-fwrapv"],patches=["COSAC uses fresh 24-byte Box-Muller buffer","AES counter limited to 2^27 blocks per seed"],
            shake_provider="OpenSSL EVP SHAKE256; compatibility declaration only",security_claim="none",backend_admitted=False,parameters_are_formal=False)
        (args.prefix/"build.json").write_text(json.dumps(receipt,indent=2)+"\n")
        print(json.dumps(receipt))


if __name__ == "__main__":
    main()
