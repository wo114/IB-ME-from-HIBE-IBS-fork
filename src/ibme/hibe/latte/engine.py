"""Isolated native operations with a checked source ABI; no automatic fallback."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
from ibme.core.errors import InvalidParameterError
from .params import N, Q


class NativeOperationError(RuntimeError):
    """Native failure/resource abort; caller must preserve an occupied address."""


def pack(polys):
    return b"".join(struct.pack("<1024q",*p) for p in polys)


def unpack(raw,count):
    if len(raw)!=count*N*8:
        raise NativeOperationError("LATTE native result length mismatch")
    return tuple(struct.unpack_from("<1024q",raw,i*N*8) for i in range(count))


class Native:
    def __init__(self,params):
        from .native.build import source_id
        self.params=params
        default=Path.home()/".cache/ibme-native-tools/latte3-bridge-v1/bin/ibme-latte3"
        self.path=Path(os.environ.get("IBME_LATTE3_EXECUTABLE",str(default))).expanduser().resolve()
        if os.name!="posix" or not self.path.is_file():
            raise InvalidParameterError("LATTE requires its explicit built WSL native bridge; no fallback")
        expected=dict(abi="IBME-LATTE3-COEFF-1",source_id=source_id(),n=N,q=Q)
        try:
            meta=json.loads(self.call("meta",b""))
        except (ValueError,NativeOperationError):
            raise InvalidParameterError("LATTE native bridge metadata unavailable") from None
        if meta!=expected:
            raise InvalidParameterError("LATTE native bridge differs from current frozen source")
        self.binary_sha256=hashlib.sha256(self.path.read_bytes()).hexdigest()

    def call(self,operation,data):
        try:
            result=subprocess.run([str(self.path),operation],input=data,capture_output=True,
                timeout=self.params.native_timeout_seconds)
        except (OSError,subprocess.TimeoutExpired):
            raise NativeOperationError("LATTE native operation failed or timed out; no retry") from None
        if result.returncode:
            # Never include stdout (key material) or private native diagnostics.
            raise NativeOperationError("LATTE native operation aborted (exit %d)"%result.returncode)
        return result.stdout
