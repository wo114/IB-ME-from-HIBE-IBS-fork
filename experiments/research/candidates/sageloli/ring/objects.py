"""Ring-coefficient v3 objects. Private arrays and sampler plans are redacted."""
from hashlib import sha256
import threading
import numpy as np
from . import codec
from .native import _i64


def _identity(p,value):
    if type(value) is not bytes or not 1<=len(value)<=p.identity_max_bytes:
        raise ValueError("identity outside configured byte domain")
    return value


def _readonly(a):
    a.setflags(write=False);return a


class PublicKey:
    route="rsis-structured-v3"
    def __init__(self,params,a):
        from .params import RingParams
        if not isinstance(params,RingParams): raise TypeError("RingParams required")
        a=np.asarray(a,dtype=object)
        if a.shape!=(params.l,params.d) or any(type(v) is not int or not 0<=v<params.q for v in a.flat):
            raise ValueError("canonical public polynomial row required")
        self.params=params;self.a=_readonly(a);self._wire=None;self._context=None

    def to_bytes(self):
        if self._wire is None:
            self._wire=codec.frame(b"public",[codec.params_bytes(self.params),
                codec.tensor(self.a,self.a.shape,self.params.q.bit_length())])
        return self._wire

    @property
    def context(self):
        if self._context is None:self._context=sha256(self.to_bytes()).digest()
        return self._context

    @classmethod
    def from_bytes(cls,raw):
        fields=codec.unframe(raw,b"public",2);p=codec.params_from(fields[0])
        a=codec.tensor_from(fields[1],(p.l,p.d),p.q.bit_length(),modulus=p.q)
        result=cls(p,a);result._wire=raw
        return result

    def __repr__(self):return "SageloliRingPublicKey(v3)"


class SigningKey:
    def __init__(self,public_key,identity,identity_salt,trapdoor):
        self.public_key=public_key;p=public_key.params
        self.identity=_identity(p,identity)
        if type(identity_salt) is not bytes or len(identity_salt)!=p.salt_bytes:
            raise ValueError("identity salt length")
        self.identity_salt=identity_salt
        self.trapdoor=_readonly(_i64(trapdoor,(p.l,p.k,p.d)))
        self._plan=None;self._native=None

    def to_bytes(self):
        return codec.frame(b"signing",[self.public_key.to_bytes(),self.identity,self.identity_salt,
            codec.tensor(self.trapdoor,self.trapdoor.shape,64,signed=True)])

    @classmethod
    def from_bytes(cls,raw,public_key=None):
        fields=codec.unframe(raw,b"signing",4);pk=PublicKey.from_bytes(fields[0]);p=pk.params
        if public_key is not None:
            if pk.context!=public_key.context: raise ValueError("signing key public context mismatch")
            pk=public_key
        return cls(pk,fields[1],fields[2],codec.tensor_from(fields[3],(p.l,p.k,p.d),64,signed=True))

    def __repr__(self):return "SageloliRingSigningKey(private=<redacted>)"


class MasterSecret:
    def __init__(self,public_key,root,states=None):
        self.public_key=public_key;p=public_key.params
        self.root=_readonly(_i64(root,(p.l-p.k,p.k,p.d)))
        scale=np.ones(p.d,dtype=np.int64);scale[:p.d//4]=scale[3*p.d//4:]=4
        if np.any(np.abs(self.root)>scale) or np.any(self.root%scale):
            raise ValueError("root outside paper four-block distribution support")
        self.states={} if states is None else states
        if type(self.states) is not dict or len(self.states)>p.max_users: raise ValueError("issuer ledger capacity")
        for identity,(status,key) in self.states.items():
            _identity(p,identity)
            if status not in ("issued","pending","failed"): raise ValueError("invalid ledger state")
            if status=="issued":
                if not isinstance(key,SigningKey) or key.identity!=identity or key.public_key.context!=public_key.context:
                    raise ValueError("issued key binding mismatch")
            elif key is not None: raise ValueError("unexpected key in unfinished state")
        self._lock=threading.RLock();self._plan=None;self._native=None

    def to_bytes(self):
        entries=[]
        for identity,(status,key) in sorted(self.states.items()):
            entries.append(codec.frame(b"entry",[identity,status.encode(),key.to_bytes() if key else b""]))
        return codec.frame(b"master",[self.public_key.to_bytes(),
            codec.tensor(self.root,self.root.shape,8,signed=True),codec.frame(b"ledger",entries)])

    @classmethod
    def from_bytes(cls,raw):
        fields=codec.unframe(raw,b"master",3);pk=PublicKey.from_bytes(fields[0]);p=pk.params
        # Read the bounded ledger count, then let the strict frame parser own it.
        ledger=fields[2];prefix=len(codec.MAGIC)
        if not ledger.startswith(codec.MAGIC) or len(ledger)<prefix+1:
            raise ValueError("invalid ledger")
        end=prefix+1+ledger[prefix]
        if len(ledger)<end+4: raise ValueError("truncated ledger")
        count=int.from_bytes(ledger[end:end+4],"big")
        if count>p.max_users: raise ValueError("issuer ledger capacity")
        states={};previous=None
        for item in codec.unframe(ledger,b"ledger",count):
            identity,status,key=codec.unframe(item,b"entry",3)
            if previous is not None and identity<=previous: raise ValueError("unordered/duplicate identity")
            previous=identity
            status=status.decode("ascii")
            states[identity]=(status,SigningKey.from_bytes(key,pk) if status=="issued" else None)
            if status!="issued" and key: raise ValueError("unfinished state contains key")
        root=codec.tensor_from(fields[1],(p.l-p.k,p.k,p.d),8,signed=True)
        return cls(pk,root,states)

    def __repr__(self):return "SageloliRingMasterSecret(private=<redacted>)"


class Signature:
    def __init__(self,context,identity_salt,message_salt,z,params):
        if type(context) is not bytes or len(context)!=32: raise ValueError("public context")
        if any(type(v) is not bytes or len(v)!=params.salt_bytes for v in (identity_salt,message_salt)):
            raise ValueError("signature salt length")
        self.context=context;self.identity_salt=identity_salt;self.message_salt=message_salt
        self.z=_readonly(_i64(z,(params.l+params.k,params.d)));self.params=params

    def to_bytes(self):
        return codec.frame(b"signature",[self.context,self.identity_salt,self.message_salt,
            codec.tensor(self.z,self.z.shape,64,signed=True)])

    @classmethod
    def from_bytes(cls,raw,public_key):
        f=codec.unframe(raw,b"signature",4);p=public_key.params
        if f[0]!=public_key.context: raise ValueError("signature context mismatch")
        return cls(f[0],f[1],f[2],codec.tensor_from(f[3],(p.l+p.k,p.d),64,signed=True),p)

    def __repr__(self):return "SageloliRingSignature(v3)"
