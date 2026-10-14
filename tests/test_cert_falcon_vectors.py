"""All 200 published Falcon TEST cases; no production deterministic RNG."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess

import pytest

from ibme.ibs.certified.falcon import Falcon
from ibme.ibs.certified.falcon_native.build import HERE, PREFIX, source_id

FIXTURE=Path(__file__).parent/"fixtures/cert_falcon/round3.json.gz"
DATA=json.loads(gzip.decompress(FIXTURE.read_bytes()))
BIN=Path(os.environ.get("IBME_CERTIFIED_FALCON_BIN_DIR",str(PREFIX/"bin")))
NATIVE=os.name=="posix" and all((BIN/f"ibme-falcon{tag}{n}").is_file() for tag in ("","-kat") for n in (512,1024))
native=pytest.mark.skipif(not NATIVE,reason="requires explicitly built Falcon v1.2 engines in WSL/Linux")


def test_pinned_sources_and_all_official_cases():
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest()=="4e70a06b5d74cdf9a93f0ca58dde6c009eac54d83e5ce5c42755195d1bb954b1"
    assert DATA["archive_sha256"]=="d625407dbda9e5835f610aaeba1147e029988a6610e0107dfd292033138e1d47"
    assert {n:sum(v["degree"]==n for v in DATA["vectors"]) for n in (512,1024)}=={512:100,1024:100}
    assert sum(v["padded_sha256"] is not None for v in DATA["vectors"])==199
    manifest=json.loads((HERE/"upstream/UPSTREAM.json").read_text())
    assert manifest["source_patch_count"]==0 and len(manifest["files"])==18
    assert manifest["archive_sha256"]=="d9f982bd825b9903b57b686d6d26018dac173a1dff09f224cc39302f9d85a595"
    for name,info in manifest["files"].items():
        raw=(HERE/"upstream"/name).read_bytes()
        assert len(raw)==info["bytes"] and hashlib.sha256(raw).hexdigest()==info["sha256"]
    assert len(source_id())==64


def kat(degree,op,data):
    result=subprocess.run([str(BIN/f"ibme-falcon-kat{degree}"),op],input=data,capture_output=True,timeout=30)
    assert result.returncode==0, result.stderr.decode()
    return result.stdout


@native
@pytest.mark.parametrize("vector",DATA["vectors"],ids=lambda v:f'{v["degree"]}-{v["count"]}')
def test_official_keys_and_exact_signature(vector):
    v=vector;n=v["degree"];engine=Falcon(f"falcon-padded-{n}")
    raw=lambda name:bytes.fromhex(v[name])
    keys=kat(n,"kat-keypair",raw("key_seed"));size=engine.profile.public_key_bytes
    public,secret=keys[:size],keys[size:]
    assert hashlib.sha256(public).hexdigest()==v["pk_sha256"]
    assert hashlib.sha256(secret).hexdigest()==v["sk_sha256"]
    assert engine.public_from_secret(secret)==public
    message=raw("message");inputs=secret+raw("nonce")+raw("sign_seed")+struct.pack("<I",len(message))+message
    signature=kat(n,"kat-sign",inputs)
    assert len(signature)==v["compressed_bytes"]
    assert hashlib.sha256(signature).hexdigest()==v["signature_sha256"]
    frame=lambda sig,msg:public+struct.pack("<I",len(sig))+sig+struct.pack("<I",len(msg))+msg
    assert kat(n,"kat-verify",frame(signature,message))==b"\1"
    assert kat(n,"kat-verify",frame(signature,message+b"!"))==b"\0"
    padded=kat(n,"kat-sign-padded",inputs)
    assert len(padded)==engine.profile.signature_bytes and padded[1:41]==raw("nonce")
    if v["padded_sha256"] is None:
        assert len(signature)>len(padded) and padded[41:]!=signature[41:41+len(padded)-41]
    else:
        assert hashlib.sha256(padded).hexdigest()==v["padded_sha256"]
    assert engine.canonical_signature(padded)
    assert kat(n,"kat-verify-padded",frame(padded,message))==b"\1"
