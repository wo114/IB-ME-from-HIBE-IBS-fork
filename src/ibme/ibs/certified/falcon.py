"""Falcon v1.2 ordinary signatures, fixed padded format; not FN-DSA/FIPS 206."""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess

from .falcon_native.build import PREFIX, source_id
from .mldsa import NativeFailure


@dataclass(frozen=True)
class FalconProfile:
    logn: int
    public_key_bytes: int
    secret_key_bytes: int
    signature_bytes: int
    norm_squared_bound: int
    modulus: int = 12289


PROFILES={"falcon-padded-512":FalconProfile(9,897,1281,666,34034726),
          "falcon-padded-1024":FalconProfile(10,1793,2305,1280,70265242)}
CONTEXT=b"IBME/CERTIBS/DIGSIG/1"
MAX_MESSAGE=2*1024*1024


def canonical_public(algorithm,public):
    profile=PROFILES[algorithm]
    if type(public) is not bytes or len(public)!=profile.public_key_bytes or public[0]!=profile.logn:
        return False
    packed=int.from_bytes(public[1:],"big")
    for _ in range(1<<profile.logn):
        if (packed&16383)>=12289:return False
        packed>>=14
    return packed==0


class Falcon:
    def __init__(self,algorithm="falcon-padded-1024",*,timeout=30):
        if algorithm not in PROFILES or type(timeout) is not int or not 1<=timeout<=300:
            raise ValueError("unsupported Falcon algorithm/timeout")
        self.algorithm=algorithm;self.profile=PROFILES[algorithm];self.timeout=timeout
        prefix=os.environ.get("IBME_CERTIFIED_FALCON_BIN_DIR")
        self.binary=(Path(prefix).expanduser() if prefix else PREFIX/"bin")/('ibme-falcon'+algorithm.rsplit('-',1)[1])
        if os.name!="posix" or not self.binary.is_file():raise NativeFailure("Falcon engine missing; build in WSL, no fallback")
        self.binary_sha256=hashlib.sha256(self.binary.read_bytes()).hexdigest()
        expected=dict(abi=1,source_id=source_id(),logn=self.profile.logn,pk=self.profile.public_key_bytes,
            sk=self.profile.secret_key_bytes,sig=self.profile.signature_bytes,fpemu=True,vector_driver=False,
            xof_limit=16777216,refill_limit=65536)
        try:meta=json.loads(self._run("meta",b""))
        except (ValueError,TypeError) as exc:raise NativeFailure("Falcon metadata malformed") from exc
        if type(meta) is not dict or any(type(meta.get(k)) is not type(v) or meta.get(k)!=v for k,v in expected.items()):
            raise NativeFailure("Falcon native source/parameter ABI mismatch")
        self.metadata=meta

    def _run(self,operation,data):
        try:
            if hashlib.sha256(self.binary.read_bytes()).hexdigest()!=self.binary_sha256:
                raise NativeFailure("Falcon executable changed")
            result=subprocess.run([str(self.binary),operation],input=data,capture_output=True,timeout=self.timeout)
        except (OSError,subprocess.TimeoutExpired) as exc:
            raise NativeFailure("Falcon native operation unavailable or timed out") from exc
        if result.returncode:raise NativeFailure(f"Falcon native operation aborted ({result.returncode})")
        return result.stdout

    @staticmethod
    def _bytes(value,size=None):
        if type(value) is not bytes or (size is not None and len(value)!=size):
            raise ValueError("Falcon input type/size mismatch")
        return value

    def keypair(self,seed):
        raw=self._run("keypair",self._bytes(seed,32));p=self.profile
        if len(raw)!=p.public_key_bytes+p.secret_key_bytes:raise NativeFailure("Falcon key output length")
        return raw[:p.public_key_bytes],raw[p.public_key_bytes:]

    def public_from_secret(self,secret):
        raw=self._run("public",self._bytes(secret,self.profile.secret_key_bytes))
        if raw==b"\0":return None
        if len(raw)!=1+self.profile.public_key_bytes or raw[:1]!=b"\1":raise NativeFailure("Falcon public reconstruction output")
        return raw[1:]

    def _message(self,message,context):
        self._bytes(message);self._bytes(context)
        if len(message)>MAX_MESSAGE or len(context)>255:raise ValueError("Falcon message/context limit")
        return struct.pack("<I",len(context))+context+struct.pack("<I",len(message))+message

    def sign(self,secret,message,seed,*,context=CONTEXT):
        raw=self._run("sign",self._bytes(secret,self.profile.secret_key_bytes)+self._bytes(seed,32)+self._message(message,context))
        if len(raw)!=self.profile.signature_bytes:raise NativeFailure("Falcon signature output length")
        return raw

    def verify(self,public,message,signature,*,context=CONTEXT):
        raw=self._run("verify",self._bytes(public,self.profile.public_key_bytes)+
            self._bytes(signature,self.profile.signature_bytes)+self._message(message,context))
        if raw not in (b"\0",b"\1"):raise NativeFailure("Falcon verification output")
        return raw==b"\1"

    def canonical_signature(self,signature):
        raw=self._run("signature",self._bytes(signature,self.profile.signature_bytes))
        if raw not in (b"\0",b"\1"):raise NativeFailure("Falcon signature decoder output")
        return raw==b"\1"
