"""Independent two-level LATTE-3 research HIBE, not a composition implementation."""
from ibme.core.randomness import SecureRandom
from ibme.core.types import validate_bytes
from ibme.core.errors import InvalidParameterError
from .params import LATTEParams, VERSION
from .objects import (LATTEPublicKey,LATTEMasterSecret,LATTELevel1SecretKey,
    LATTELevel2SecretKey,LATTECiphertext,identity)
from .math import vector_hash,check_basis,check_leaf,rings
from .engine import Native,NativeOperationError,pack,unpack


def seed(rng):
    source=SecureRandom() if rng is None else rng
    value=source.read(32)
    if not isinstance(value,(bytes,bytearray,memoryview)):
        raise ValueError("LATTE random source must return bytes")
    value=bytes(value)
    if len(value)!=32:
        raise ValueError("LATTE random source returned a short seed")
    return value


class LATTEHIBE:
    BACKEND_ID="latte3-research"
    VERSION=VERSION
    security_claim="none"
    backend_admitted=False
    parameters_are_formal=False

    def __init__(self,*,persist_pending=None):
        if persist_pending is not None and not callable(persist_pending):
            raise TypeError("LATTE pending persister must be callable")
        self.persist_pending=persist_pending

    def setup(self,params,*,rng=None):
        if type(params) is not LATTEParams:
            raise TypeError("LATTEParams required")
        rings()  # Dependency gate before requesting private entropy.
        engine=Native(params)
        values=unpack(engine.call("setup",seed(rng)),5)
        public=LATTEPublicKey(params,values[0])
        return public,LATTEMasterSecret(public,values[1:])

    def _issue(self,owner,address,limit,generate):
        with owner._lock:
            if address in owner._entries:
                key=owner._entries[address]
                if key is None:
                    raise NativeOperationError("LATTE address pending/failed; reissue forbidden")
                return key
            if len(owner._entries)>=limit:
                raise InvalidParameterError("LATTE fixed issuance capacity exhausted")
            owner._entries[address]=None
            if self.persist_pending is not None:
                self.persist_pending(owner)
            key=generate()  # Every failure keeps None, including callback failure.
            if type(owner) is LATTEMasterSecret:
                object.__setattr__(key,"_lock",owner._lock)
            owner._entries[address]=key
            try:
                owner.to_bytes()
            except Exception:
                owner._entries[address]=None
                raise
            return key

    def extract(self,master,parent_id,*,rng=None):
        if type(master) is not LATTEMasterSecret:
            raise TypeError("LATTE master secret required")
        address=identity(parent_id,master.params)
        def generate():
            engine=Native(master.params)
            a1=vector_hash(master.public_key,address)
            data=pack(master.basis)+pack((a1,))+seed(rng)
            basis=unpack(engine.call("delegate",data),9)
            return LATTELevel1SecretKey(master.public_key,address,basis)
        return self._issue(master,address,master.params.max_receivers,generate)

    def derive(self,parent,child_id,*,rng=None):
        if type(parent) is not LATTELevel1SecretKey:
            raise TypeError("LATTE receiver secret required")
        address=identity(child_id,parent.params)
        def generate():
            # Original LATTE Extract derives its AES sampler seed from the
            # target polynomial. No fresh external random seed is substituted.
            engine=Native(parent.params)
            a2=vector_hash(parent.public_key,parent.identity,address)
            secret=unpack(engine.call("extract",pack(parent.basis)+pack((a2,))),2)
            return LATTELevel2SecretKey(parent.public_key,parent.identity,address,secret)
        return self._issue(parent,address,parent.params.max_children,generate)

    def encrypt(self,public,parent_id,child_id,payload,*,rng=None):
        if type(public) is not LATTEPublicKey:
            raise TypeError("LATTE public key required")
        p=public.params
        parent_id=identity(parent_id,p); child_id=identity(child_id,p)
        payload=validate_bytes(payload,name="LATTE plaintext")
        if p.message_mode=="seed32":
            if len(payload)!=32:
                raise InvalidParameterError("LATTE seed32 requires exactly 32 plaintext bytes")
            encoded=payload
        else:
            if len(payload)>28:
                raise InvalidParameterError("LATTE framed32 supports at most 28 plaintext bytes")
            encoded=len(payload).to_bytes(4,"big")+payload+bytes(28-len(payload))
        engine=Native(p)
        a=(public.h,vector_hash(public,parent_id),vector_hash(public,parent_id,child_id))
        raw=engine.call("encrypt",pack(a)+encoded+seed(rng))
        if len(raw)!=32+3*8192:
            raise NativeOperationError("LATTE emitted malformed ciphertext")
        return LATTECiphertext(p,public.digest,raw[:32],unpack(raw[32:],3))

    def decrypt(self,child,ciphertext,*,rng=None):
        if type(child) is not LATTELevel2SecretKey or type(ciphertext) is not LATTECiphertext:
            raise TypeError("LATTE leaf key and ciphertext required")
        if ciphertext.params!=child.params or ciphertext.public_digest!=child.public_key.digest:
            return None
        a=(child.public_key.h,vector_hash(child.public_key,child.parent_identity),
            vector_hash(child.public_key,child.parent_identity,child.child_identity))
        raw=Native(child.params).call("decrypt",pack(a)+pack(child.secret)+ciphertext.z+pack(ciphertext.c))
        if raw==b"\x01":
            return None
        if len(raw)!=33 or raw[:1]!=b"\x00":
            raise NativeOperationError("LATTE emitted malformed decrypt status")
        value=raw[1:]
        if child.params.message_mode=="seed32":
            return value
        length=int.from_bytes(value[:4],"big")
        if length>28 or value[4+length:]!=bytes(28-length):
            return None
        return value[4:4+length]

    def load_ciphertext(self,data):
        return LATTECiphertext.from_bytes(data)

    def validate_key_binding(self,public_key,secret_key):
        if type(public_key) is not LATTEPublicKey or type(secret_key) not in (
                LATTEMasterSecret,LATTELevel1SecretKey,LATTELevel2SecretKey):
            return False
        if secret_key.public_key.to_bytes()!=public_key.to_bytes():
            return False
        try:
            if type(secret_key) is LATTEMasterSecret:
                check_basis(public_key,secret_key.basis)
            elif type(secret_key) is LATTELevel1SecretKey:
                check_basis(public_key,secret_key.basis,secret_key.identity)
            else:
                check_leaf(public_key,secret_key.parent_identity,secret_key.child_identity,secret_key.secret)
        except (ValueError,TypeError,InvalidParameterError):
            return False
        return True
