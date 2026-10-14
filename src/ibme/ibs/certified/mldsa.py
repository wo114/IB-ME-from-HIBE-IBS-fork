"""Ordinary pure ML-DSA adapter; the certification construction lives elsewhere."""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess

from .native.build import source_id,PREFIX


@dataclass(frozen=True)
class MLDSAProfile:
    mode:int
    public_key_bytes:int
    secret_key_bytes:int
    signature_bytes:int


PROFILES={"ml-dsa-44":MLDSAProfile(2,1312,2560,2420),
          "ml-dsa-65":MLDSAProfile(3,1952,4032,3309),
          "ml-dsa-87":MLDSAProfile(5,2592,4896,4627)}
CONTEXT=b"IBME/CERTIBS/DIGSIG/1"
MAX_MESSAGE=2*1024*1024


class NativeFailure(RuntimeError):
    """Environment/ABI/abort failure, distinct from a false signature equation."""


class MLDSA:
    def __init__(self,algorithm="ml-dsa-44",*,timeout=30):
        if algorithm not in PROFILES or type(timeout) is not int or not 1<=timeout<=300:
            raise ValueError("unsupported ML-DSA algorithm/timeout")
        self.algorithm=algorithm;self.profile=PROFILES[algorithm];self.timeout=timeout
        prefix=os.environ.get("IBME_CERTIFIED_SIGNATURE_BIN_DIR")
        self.binary=(Path(prefix).expanduser() if prefix else PREFIX/"bin")/('ibme-mldsa'+algorithm.rsplit('-',1)[1])
        if os.name!="posix" or not self.binary.is_file():raise NativeFailure("ML-DSA native engine missing; build in WSL, no fallback")
        self.binary_sha256=hashlib.sha256(self.binary.read_bytes()).hexdigest()
        expected=dict(abi=1,source_id=source_id(),mode=self.profile.mode,
            pk=self.profile.public_key_bytes,sk=self.profile.secret_key_bytes,sig=self.profile.signature_bytes)
        try:meta=json.loads(self._run("meta",b""))
        except (ValueError,TypeError) as exc:raise NativeFailure("ML-DSA metadata malformed") from exc
        if type(meta) is not dict or any(meta.get(k)!=v for k,v in expected.items()):raise NativeFailure("ML-DSA native source/parameter ABI mismatch")
        self.metadata=meta

    def _run(self,operation,data):
        try:
            if hashlib.sha256(self.binary.read_bytes()).hexdigest()!=self.binary_sha256:
                raise NativeFailure("ML-DSA executable changed")
            result=subprocess.run([str(self.binary),operation],input=data,capture_output=True,timeout=self.timeout)
        except (OSError,subprocess.TimeoutExpired) as exc:
            raise NativeFailure("ML-DSA native operation unavailable or timed out") from exc
        if result.returncode:raise NativeFailure(f"ML-DSA native operation aborted ({result.returncode})")
        return result.stdout

    @staticmethod
    def _bytes(value,size=None):
        if type(value) is not bytes or (size is not None and len(value)!=size):
            raise ValueError("ML-DSA input type/size mismatch")
        return value

    def keypair(self,seed):
        raw=self._run("keypair",self._bytes(seed,32));p=self.profile
        if len(raw)!=p.public_key_bytes+p.secret_key_bytes:raise NativeFailure("ML-DSA key output length")
        return raw[:p.public_key_bytes],raw[p.public_key_bytes:]

    def public_from_secret(self,secret):
        raw=self._run("public",self._bytes(secret,self.profile.secret_key_bytes))
        if raw==b"\0":return None
        if len(raw)!=1+self.profile.public_key_bytes or raw[:1]!=b"\1":raise NativeFailure("ML-DSA public reconstruction output")
        return raw[1:]

    def _message(self,message,context):
        self._bytes(message);self._bytes(context)
        if len(message)>MAX_MESSAGE or len(context)>255:raise ValueError("ML-DSA message/context limit")
        return struct.pack("<I",len(context))+context+struct.pack("<I",len(message))+message

    def sign(self,secret,message,seed,*,context=CONTEXT):
        raw=self._run("sign",self._bytes(secret,self.profile.secret_key_bytes)+self._bytes(seed,32)+self._message(message,context))
        if len(raw)!=self.profile.signature_bytes:raise NativeFailure("ML-DSA signature output length")
        return raw

    def verify(self,public,message,signature,*,context=CONTEXT):
        raw=self._run("verify",self._bytes(public,self.profile.public_key_bytes)+
            self._bytes(signature,self.profile.signature_bytes)+self._message(message,context))
        if raw not in (b"\0",b"\1"):raise NativeFailure("ML-DSA verification output")
        return raw==b"\1"

    def canonical_signature(self,signature):
        raw=self._run("signature",self._bytes(signature,self.profile.signature_bytes))
        if raw not in (b"\0",b"\1"):raise NativeFailure("ML-DSA signature decoder output")
        return raw==b"\1"
