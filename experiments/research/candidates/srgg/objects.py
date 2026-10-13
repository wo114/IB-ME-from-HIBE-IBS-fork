"""Complete SRGG research wire and persistent issuer cache; trusted plaintext state."""
from dataclasses import dataclass, field
import json

from ibme.core.errors import EncodingError, SerializationError
from ibme.core.hashing import hash_identity
from ibme.core.types import validate_identity
from ibme.ibs.api import IBSPublicKey, IBSMasterSecret, IBSSigningKey, IBSSignature
from ..wang_pw.codec import canonical, unhex
from .algebra import Params, PublicRelation, matrix, vector, reconstruct_vector, trapdoor_relation
from .config import Config
from .hashing import public_matrix, identity_target, context

PREFIX=b"IBME-SRGG-IBS-v1:"
MAX_WIRE=2**21


def encode(kind,record):
    result=PREFIX+kind.encode()+b"\0"+canonical(record)
    if len(result)>MAX_WIRE: raise ValueError("SRGG research wire exceeds 2 MiB")
    return result


def decode(kind,data,fields):
    try:
        if not isinstance(data,(bytes,bytearray,memoryview)): raise ValueError("bytes required")
        size=data.nbytes if isinstance(data,memoryview) else len(data)
        if size>MAX_WIRE: raise ValueError("wire budget exceeded")
        raw=bytes(data); prefix=PREFIX+kind.encode()+b"\0"
        if not raw.startswith(prefix): raise ValueError("object/version mismatch")
        def unique(pairs):
            result={}
            for k,v in pairs:
                if k in result: raise ValueError("duplicate field")
                result[k]=v
            return result
        record=json.loads(raw[len(prefix):],object_pairs_hook=unique)
        if not isinstance(record,dict) or set(record)!=set(fields) or encode(kind,record)!=raw:
            raise ValueError("noncanonical/unknown/missing fields")
        return record
    except (ValueError,TypeError,OverflowError,RecursionError) as e: raise SerializationError("invalid SRGG object") from e


def restore(cls,kind,data,fields,convert):
    try:
        result=cls(**convert(decode(kind,data,fields)))
        if result.to_bytes()!=bytes(data): raise ValueError("noncanonical reconstructed object")
        return result
    except (ValueError,TypeError,EncodingError,SerializationError,RecursionError) as e:
        raise SerializationError("SRGG object parameters/binding invalid") from e


@dataclass(frozen=True,eq=False)
class PublicKey(IBSPublicKey):
    config: Config
    seed: bytes
    b: tuple
    def __post_init__(self):
        if not isinstance(self.config,Config) or type(self.seed) is not bytes or len(self.seed)!=32: raise ValueError("config/seed invalid")
        p=self.config.algebra
        object.__setattr__(self,"b",matrix(p,self.b,p.rank,p.rank*p.digits,p.modulus))
    @property
    def public(self): return PublicRelation(self.config.algebra,public_matrix(self.config,self.seed),self.b)
    @property
    def context(self): return context(self)
    def to_bytes(self): return encode("PK",{"config":self.config.record(),"seed":self.seed.hex(),"b":self.b})
    @classmethod
    def from_bytes(cls,data):
        return restore(cls,"PK",data,("config","seed","b"),lambda r:{"config":Config.from_record(r["config"]),"seed":unhex(r["seed"]),"b":r["b"]})


@dataclass(frozen=True,eq=False,repr=False)
class SigningKey(IBSSigningKey):
    public_key: PublicKey
    _identity: bytes
    tail: tuple
    def __post_init__(self):
        if not isinstance(self.public_key,PublicKey): raise ValueError("public key required")
        c,p=self.public_key.config,self.public_key.config.algebra
        identity=validate_identity(self._identity)
        if len(identity)>c.identity_max_bytes: raise ValueError("identity capacity exceeded")
        object.__setattr__(self,"_identity",identity)
        object.__setattr__(self,"tail",vector(p,self.tail,(1+p.digits)*p.rank))
        if sum(x*x for poly in self.full_vector for x in poly)>c.user_norm_squared: raise ValueError("identity/key quality binding failed")
    @property
    def identity(self): return self._identity
    @property
    def identity_digest(self): return hash_identity(self.identity,32)
    @property
    def full_vector(self): return reconstruct_vector(self.public_key.public,identity_target(self.public_key,self.identity),self.tail)
    def __repr__(self): return "SrggSigningKey(private=<redacted>)"
    def to_bytes(self): return encode("SK",{"pk":self.public_key.to_bytes().hex(),"identity":self.identity.hex(),"tail":self.tail})
    @classmethod
    def from_bytes(cls,data):
        return restore(cls,"SK",data,("pk","identity","tail"),lambda r:{"public_key":PublicKey.from_bytes(unhex(r["pk"])),"_identity":unhex(r["identity"]),"tail":r["tail"]})


@dataclass(eq=False,repr=False)
class MasterSecret(IBSMasterSecret):
    public_key: PublicKey
    r: tuple
    states: dict=field(default_factory=dict,repr=False)
    __hash__=None
    def __post_init__(self):
        if not isinstance(self.public_key,PublicKey): raise ValueError("public key required")
        p=self.public_key.config.algebra
        self.r=matrix(p,self.r,2*p.rank,p.rank*p.digits)
        if any(v not in (-1,0,1) for row in self.r for poly in row for v in poly): raise ValueError("CBD1 support required")
        if not trapdoor_relation(self.public_key.public,self.r): raise ValueError("master public/secret relation mismatch")
        if not isinstance(self.states,dict) or len(self.states)>self.public_key.config.max_users: raise ValueError("issuer cache budget exceeded")
        for identity,entry in self.states.items():
            validate_identity(identity)
            if len(identity)>self.public_key.config.identity_max_bytes or not isinstance(entry,tuple) or len(entry)!=2:
                raise ValueError("invalid issuer cache entry")
            status,key=entry
            if status not in ("issued","pending","failed"): raise ValueError("unknown issuance state")
            if status=="issued":
                if not isinstance(key,SigningKey) or key.identity!=identity or key.public_key!=self.public_key: raise ValueError("cached key binding failed")
            elif key is not None: raise ValueError("unissued identity cannot hold a key")
    def __repr__(self): return f"SrggMasterSecret(private=<redacted>, identities={len(self.states)})"
    def to_bytes(self):
        return encode("MSK",{"pk":self.public_key.to_bytes().hex(),"r":self.r,
            "states":{identity.hex():{"status":state,"key":key.to_bytes().hex() if key else None} for identity,(state,key) in self.states.items()}})
    @classmethod
    def from_bytes(cls,data):
        def convert(r):
            if not isinstance(r["states"],dict): raise ValueError("issuer cache required")
            states={}
            for identity,entry in r["states"].items():
                if not isinstance(entry,dict) or set(entry)!={"status","key"}: raise ValueError("issuer cache schema invalid")
                states[unhex(identity)]=(entry["status"],SigningKey.from_bytes(unhex(entry["key"])) if entry["key"] is not None else None)
            return {"public_key":PublicKey.from_bytes(unhex(r["pk"])),"r":r["r"],"states":states}
        return restore(cls,"MSK",data,("pk","r","states"),convert)


@dataclass(frozen=True,eq=False)
class Signature(IBSSignature):
    context: bytes
    z: tuple
    challenge: tuple
    def __post_init__(self):
        if type(self.context) is not bytes or len(self.context)!=32: raise ValueError("context digest required")
        if not isinstance(self.z,(tuple,list)) or not 1<=len(self.z)<=32: raise ValueError("bounded response dimension required")
        n=len(self.challenge) if isinstance(self.challenge,(tuple,list)) else 0
        if n not in (2,4,8) or any(type(x) is not int or x not in (0,1) for x in self.challenge): raise ValueError("binary challenge required")
        p=Params(degree=n)
        object.__setattr__(self,"z",vector(p,self.z,len(self.z)))
        object.__setattr__(self,"challenge",tuple(self.challenge))
    def to_bytes(self): return encode("SIG",{"context":self.context.hex(),"z":self.z,"challenge":self.challenge})
    @classmethod
    def from_bytes(cls,data):
        return restore(cls,"SIG",data,("context","z","challenge"),lambda r:{"context":unhex(r["context"]),"z":r["z"],"challenge":r["challenge"]})
