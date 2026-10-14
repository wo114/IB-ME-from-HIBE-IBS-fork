"""Actual native boundary, bounded aborts, independent equation and sampler."""
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess

import pytest

from ibme.ibs.certified.falcon import Falcon, PROFILES, MAX_MESSAGE
from ibme.ibs.certified.mldsa import NativeFailure
from ibme.ibs.certified.falcon_native.build import HERE, DEFINES, source_id
from test_cert_falcon_vectors import native, BIN, DATA, kat


@native
def test_unchanged_author_selftest_including_gaussian_statistics():
    binary=BIN/"test_falcon"
    assert binary.is_file(), "build with --selftest; this check may not skip"
    result=subprocess.run([str(binary)],capture_output=True,timeout=300)
    assert result.returncode==0,result.stderr.decode()
    log=result.stdout.decode()
    assert "skipped" not in log.lower()
    for text in ("Test half-Gaussian sampler:","Test sampler:","Test external API:",
                 "a57400cbaee7109358859a56c735a3cf048a9da2 done.",
                 "affdeb3aa83bf9a2039fa9c17d65fd3e3b9828e2 done."):
        assert text in log


@native
@pytest.mark.parametrize("degree",[512,1024])
def test_native_ipc_strict_format_context_and_seed_flip(degree):
    engine=Falcon(f"falcon-padded-{degree}");binary=engine.binary
    def run(op,data):return subprocess.run([str(binary),op],input=data,capture_output=True,timeout=30)
    assert engine.metadata["source_id"]==source_id() and not engine.metadata["vector_driver"]
    for op,data in (("unknown",b""),("meta",b"!"),("keypair",bytes(31)),("keypair",bytes(33)),
                    ("public",b""),("signature",b""),("sign",b""),("verify",b""),
                    ("kat-keypair",bytes(48)),("kat-sign",b"")):
        r=run(op,data);assert r.returncode==70 and r.stdout==b""
    public,secret=engine.keypair(bytes(32))
    assert engine.public_from_secret(secret)==public
    sigs=[engine.sign(secret,b"message",bytes([i])*32) for i in (0,1)]
    assert sigs[0]!=sigs[1]
    for i,sig in enumerate(sigs):
        # Regression of the authors' 2021-11-01 missing-SHAKE-flip fix.
        assert sig[1:41]==hashlib.shake_256(bytes([i])*32).digest(40)
        assert engine.verify(public,b"message",sig)
        assert not engine.verify(public,b"message",sig,context=b"wrong")
        assert engine.canonical_signature(sig)
        changed=bytearray(sig);changed[0]=0x50+engine.profile.logn
        assert not engine.canonical_signature(bytes(changed))
        changed=bytearray(sig);changed[-1]=0xff
        assert not engine.canonical_signature(bytes(changed))
        assert not engine.verify(public,b"message",bytes(changed))
    bad=bytearray(public);bad[0]^=1
    assert not engine.verify(bytes(bad),b"message",sigs[0])
    bad=bytearray(public);bad[1:3]=b"\xff\xff"  # coefficient >= q
    assert not engine.verify(bytes(bad),b"message",sigs[0])
    assert run("public",secret+b"!").returncode==70
    prefix=public+sigs[0]
    assert run("verify",prefix+struct.pack("<I",256)).returncode==70
    assert run("verify",prefix+bytes(4)+struct.pack("<I",MAX_MESSAGE+1)).returncode==70
    for seed in (None,bytes(31),bytes(33),bytearray(32)):
        with pytest.raises(ValueError):engine.keypair(seed)
    with pytest.raises(ValueError):engine.sign(secret,b"",bytes(32),context=bytes(256))
    with pytest.raises(ValueError):engine.verify(public,b"",sigs[0][:-1])


@native
@pytest.mark.parametrize("counter",["xof","refill"])
def test_actual_linker_stream_limit_boundary(tmp_path,counter):
    driver=tmp_path/"guard.c";binary=tmp_path/"guard"
    body=('inner_shake256_context sc; uint8_t out[2]; inner_shake256_init(&sc); inner_shake256_flip(&sc); '
          'xof_bytes=IBME_XOF_LIMIT-1; __wrap_falcon_inner_i_shake256_extract(&sc,out,1); '
          '__wrap_falcon_inner_i_shake256_extract(&sc,out,1);') if counter=="xof" else (
          'prng p; memset(&p,0,sizeof p); refills=IBME_REFILL_LIMIT-1; '
          '__wrap_falcon_inner_prng_refill(&p); __wrap_falcon_inner_prng_refill(&p);')
    driver.write_text('#define main ibme_bridge_main\n#include '+json.dumps(str(HERE/"bridge.c"))+
                      '\n#undef main\nint main(void) {'+body+'return 99;}\n')
    sources=[str(HERE/"upstream"/name) for name in
             ("codec.c","common.c","falcon.c","fft.c","fpr.c","keygen.c","rng.c","shake.c","sign.c","vrfy.c")]
    command=["gcc","-O2","-std=c99","-fwrapv",*[f"-D{k}={v}" for k,v in DEFINES.items()],
        "-DIBME_LOGN=9",'-DIBME_SOURCE_ID="guard-test-only"',"-I"+str(HERE/"upstream"),str(driver),*sources,
        "-Wl,--wrap=falcon_inner_i_shake256_extract","-Wl,--wrap=falcon_inner_prng_refill","-o",str(binary)]
    result=subprocess.run(command,capture_output=True,timeout=120)
    assert result.returncode==0,result.stderr.decode()
    assert subprocess.run([str(binary)],capture_output=True,timeout=10).returncode==70


@native
def test_executable_fingerprint_timeout_and_malformed_private_key(tmp_path,monkeypatch):
    source=BIN/"ibme-falcon512";dest=tmp_path/source.name
    shutil.copyfile(source,dest);dest.chmod(0o700)
    monkeypatch.setenv("IBME_CERTIFIED_FALCON_BIN_DIR",str(tmp_path))
    engine=Falcon("falcon-padded-512");_,secret=engine.keypair(bytes(32))
    bad=bytearray(secret);bad[0]^=1
    assert engine.public_from_secret(bytes(bad)) is None
    with pytest.raises(NativeFailure,match="70"):engine.sign(bytes(bad),b"m",bytes(32))
    dest.write_bytes(dest.read_bytes()+b"!")
    with pytest.raises(NativeFailure,match="changed"):engine.keypair(bytes(32))
    shutil.copyfile(source,dest)
    def timeout(*args,**kwargs):raise subprocess.TimeoutExpired("operation",1)
    monkeypatch.setattr(subprocess,"run",timeout)
    with pytest.raises(NativeFailure,match="timed out"):engine.keypair(bytes(32))


def decode_signature(raw,n):
    bits="".join(f"{x:08b}" for x in raw[41:]);pos=0;values=[]
    for _ in range(n):
        sign=int(bits[pos]);v=int(bits[pos+1:pos+8],2);pos+=8
        while bits[pos]=="0":v+=128;pos+=1
        pos+=1;values.append(-v if sign else v)
    return values


@native
@pytest.mark.parametrize("degree",[512,1024])
def test_independent_negacyclic_verification_equation_and_norm(degree):
    v=next(v for v in DATA["vectors"] if v["degree"]==degree)
    engine=Falcon(f"falcon-padded-{degree}")
    key=kat(degree,"kat-keypair",bytes.fromhex(v["key_seed"]))
    public,secret=key[:engine.profile.public_key_bytes],key[engine.profile.public_key_bytes:]
    message=bytes.fromhex(v["message"]);nonce=bytes.fromhex(v["nonce"])
    sig=kat(degree,"kat-sign",secret+nonce+bytes.fromhex(v["sign_seed"])+struct.pack("<I",len(message))+message)
    bits="".join(f"{x:08b}" for x in public[1:])
    h=[int(bits[i*14:(i+1)*14],2) for i in range(degree)]
    s2=decode_signature(sig,degree)
    stream=hashlib.shake_256(nonce+message).digest(8*degree)
    point=[int.from_bytes(stream[i:i+2],"big")%12289 for i in range(0,len(stream),2)
           if int.from_bytes(stream[i:i+2],"big")<61445][:degree]
    assert len(point)==degree
    product=[0]*degree
    for i,x in enumerate(s2):
        for j,y in enumerate(h):
            if i+j<degree:product[i+j]+=x*y
            else:product[i+j-degree]-=x*y
    s1=[((c-p+6144)%12289)-6144 for c,p in zip(point,product,strict=True)]
    assert all((a+b-c)%12289==0 for a,b,c in zip(s1,product,point,strict=True))
    assert sum(x*x+y*y for x,y in zip(s1,s2,strict=True))<=engine.profile.norm_squared_bound
