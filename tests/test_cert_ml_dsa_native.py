"""Strict C IPC, finite abort guard, and Python runtime failures."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from ibme.core.errors import RandomnessError
from ibme.ibs.certified import CertifiedIBS
from ibme.ibs.certified.mldsa import MLDSA, NativeFailure, PROFILES
from ibme.ibs.certified.native.build import HERE, source_id
from test_cert_ml_dsa_vectors import NATIVE, BIN


native = pytest.mark.skipif(not NATIVE, reason="requires explicitly built ML-DSA engines in WSL/Linux")


def test_vendor_fingerprints():
    data=json.loads((HERE/"upstream/UPSTREAM.json").read_text())
    assert data["commit"]=="d35ba3fe5449bee3e6d43e1f296c3ca818bd36be"
    for name,info in data["files"].items():
        assert hashlib.sha256((HERE/"upstream"/name).read_bytes()).hexdigest()==info["sha256"]
    assert len(source_id())==64


@native
@pytest.mark.parametrize("number,limit",[(44,16384),(65,13107),(87,9362)])
def test_native_strict_ipc_and_metadata(number,limit):
    binary=BIN/f"ibme-mldsa{number}"
    def run(operation,data):
        return subprocess.run([str(binary),operation],input=data,capture_output=True,timeout=10)
    metadata=json.loads(run("meta",b"").stdout)
    assert metadata["nonce_attempt_limit"]==limit
    assert metadata["source_id"]==source_id()
    for operation,data in (("unknown",b""),("meta",b"!"),("keypair",b"x"*31),
                           ("keypair",b"x"*33),("public",b""),("signature",b""),
                           ("sign",b""),("verify",b"")):
        result=run(operation,data)
        assert result.returncode==65
        assert result.stdout==b""
    engine=MLDSA(f"ml-dsa-{number}")
    public,secret=engine.keypair(bytes(32))
    assert run("public",secret+b"!").returncode==65
    # Untrusted context/message lengths are rejected before allocation/use.
    prefix=public+bytes(engine.profile.signature_bytes)
    assert run("verify",prefix+(256).to_bytes(4,"little")).returncode==65
    assert run("verify",prefix+bytes(4)+(2**32-1).to_bytes(4,"little")).returncode==65


@native
@pytest.mark.parametrize("number,mode,l",[(44,2,4),(65,3,5),(87,5,7)])
def test_actual_linker_wrapper_aborts_before_nonce_repetition(tmp_path,number,mode,l):
    # Include our bridge in this test TU so its private attempt counter can be
    # placed at the boundary without millions of improbable rejection attempts.
    # No production operation, algorithm seed, or vendor source is changed.
    bridge=str(HERE/"bridge.c")
    driver=tmp_path/"guard.c"
    driver.write_text('#define main ibme_bridge_main\n#include '+json.dumps(bridge)+
        '\n#undef main\nint main(int argc,char **argv) {\n'
        'polyvecl y; uint8_t seed[CRHBYTES]={0};\n'
        'if(argc>1) { attempts=65536u/L-1; WRAPPED(polyvecl_uniform_gamma1)(&y,seed,(uint16_t)attempts); }\n'
        'else { WRAPPED(polyvecl_uniform_gamma1)(&y,seed,0); }\n'
        'WRAPPED(polyvecl_uniform_gamma1)(&y,seed,argc>1?(uint16_t)attempts:0);return 99; }\n')
    binary=tmp_path/"guard"
    command=["gcc","-O2","-std=c99","-fwrapv",f"-DDILITHIUM_MODE={mode}",
        '-DIBME_SOURCE_ID="guard-test-only"',"-I"+str(HERE/"upstream/ref"),str(driver),
        *[str(p) for p in sorted((HERE/"upstream/ref").glob("*.c")) if p.name!="randombytes.c"],
        f"-Wl,--wrap=pqcrystals_dilithium{mode}_ref_polyvecl_uniform_gamma1","-o",str(binary)]
    result=subprocess.run(command,capture_output=True,timeout=120)
    assert result.returncode==0, result.stderr.decode()
    assert subprocess.run([str(binary)],capture_output=True,timeout=10).returncode==71
    assert subprocess.run([str(binary),"boundary"],capture_output=True,timeout=10).returncode==71


@native
def test_engine_change_timeout_and_invalid_secret(tmp_path,monkeypatch):
    for n in (44,65,87):
        shutil.copyfile(BIN/f"ibme-mldsa{n}",tmp_path/f"ibme-mldsa{n}")
        (tmp_path/f"ibme-mldsa{n}").chmod(0o700)
    monkeypatch.setenv("IBME_CERTIFIED_SIGNATURE_BIN_DIR",str(tmp_path))
    engine=MLDSA()
    public,secret=engine.keypair(bytes(32))
    invalid=bytearray(secret);invalid[64]^=1
    assert engine.public_from_secret(bytes(invalid)) is None
    with pytest.raises(NativeFailure,match="73"):
        engine.sign(bytes(invalid),b"test",bytes(32))
    for seed in (b"",b"a"*31,b"a"*33,bytearray(32),None):
        with pytest.raises(ValueError):
            engine.keypair(seed)
    with pytest.raises(ValueError):
        engine.sign(secret,b"",bytes(32),context=bytes(256))
    engine.binary.write_bytes(engine.binary.read_bytes()+b"!")
    with pytest.raises(NativeFailure,match="changed"):
        engine.keypair(bytes(32))
    shutil.copyfile(BIN/"ibme-mldsa44",engine.binary)
    def timeout(*args,**kwargs):
        raise subprocess.TimeoutExpired("public operation only",1)
    monkeypatch.setattr(subprocess,"run",timeout)
    with pytest.raises(NativeFailure,match="timed out"):
        engine.keypair(bytes(32))


def test_rng_protocol_type_rejection():
    with pytest.raises(RandomnessError):
        CertifiedIBS(object())
