"""Strict objects for an explicitly corrected Xie equation study, not IBSBackend."""
from dataclasses import dataclass,field
import hashlib
import threading

from ibme.core.types import validate_identity
from ibme.core.errors import SerializationError,EncodingError
from .codec import encode,decode,fields,octets
from .params import StudyParams,VERSION
from .ring import coefficients,add,mul,neg,inverse


def parsed(function):
    def loader(*args,**kwargs):
        try:return function(*args,**kwargs)
        except (ValueError,TypeError,KeyError,OverflowError,EncodingError) as exc:raise SerializationError("invalid Xie study object") from exc
    return loader


@dataclass(frozen=True)
class Public:
    params:StudyParams
    h:tuple

    def __post_init__(self):
        if type(self.params) is not StudyParams:raise ValueError("study parameter type")
        object.__setattr__(self,"h",coefficients(self.h,self.params.n,modulus=self.params.q))
        inverse(self.h,self.params.q)

    def record(self):return dict(version=VERSION,params=self.params.record(),h=list(self.h))
    def to_bytes(self):return encode("XIE-STUDY-PUBLIC",self.record())

    @property
    def context(self):return hashlib.shake_256(b"XIE-STUDY/PUBLIC/1\0"+self.to_bytes()).digest(32)

    @classmethod
    @parsed
    def from_record(cls,value):
        fields(value,("version","params","h"))
        if value["version"]!=VERSION:raise ValueError("study version")
        fields(value["params"],StudyParams.__dataclass_fields__)
        return cls(StudyParams(**value["params"]),value["h"])

    @classmethod
    def from_bytes(cls,raw):return cls.from_record(decode(raw,"XIE-STUDY-PUBLIC",limit=16384))


@dataclass(frozen=True)
class IdentitySecret:
    public:Public
    identity:bytes
    s1:tuple=field(repr=False)
    s2:tuple=field(repr=False)

    def __post_init__(self):
        if type(self.public) is not Public or type(self.identity) is not bytes:raise ValueError("study key context")
        validate_identity(self.identity,max_bytes=self.public.params.identity_bytes)
        p=self.public.params
        object.__setattr__(self,"s1",coefficients(self.s1,p.n))
        object.__setattr__(self,"s2",coefficients(self.s2,p.n))
        from .hashing import identity_hash
        if add(self.s1,mul(self.public.h,self.s2,p.q),p.q)!=identity_hash(self.public,self.identity):
            raise ValueError("Xie study identity preimage equation")

    def record(self):return dict(public=self.public.record(),identity=self.identity.hex(),s1=list(self.s1),s2=list(self.s2))
    def to_bytes(self):return encode("XIE-STUDY-IDENTITY-SECRET",self.record())

    @classmethod
    @parsed
    def from_record(cls,value):
        fields(value,("public","identity","s1","s2"))
        public=Public.from_record(value["public"])
        return cls(public,octets(value["identity"],public.params.identity_bytes),value["s1"],value["s2"])

    @classmethod
    def from_bytes(cls,raw):return cls.from_record(decode(raw,"XIE-STUDY-IDENTITY-SECRET",limit=32768))


@dataclass(frozen=True)
class Signature:
    context:bytes
    z1:tuple
    z2:tuple
    u:tuple

    def __post_init__(self):
        if type(self.context) is not bytes or len(self.context)!=32:raise ValueError("study signature context")
        if type(self.u) not in (tuple,list) or len(self.u) not in (16,32):raise ValueError("study signature dimension")
        n=len(self.u)
        for name in ("z1","z2","u"):object.__setattr__(self,name,coefficients(getattr(self,name),n))
        if any(x not in (-1,0,1) for x in self.u):raise ValueError("study challenge coefficients")

    def to_bytes(self):return encode("XIE-STUDY-SIGNATURE",dict(context=self.context.hex(),z1=list(self.z1),z2=list(self.z2),u=list(self.u)))

    @classmethod
    @parsed
    def from_bytes(cls,raw):
        value=decode(raw,"XIE-STUDY-SIGNATURE",limit=16384)
        fields(value,("context","z1","z2","u"))
        return cls(octets(value["context"],32),value["z1"],value["z2"],value["u"])


class PendingIdentity(RuntimeError):pass


class Master:
    """Plaintext study snapshots, in-process single issuance, no disk service."""
    __slots__=("public","_f","_g","_F","_G","_cache","_lock","_sampler")

    def __init__(self,public,f,g,F,G):
        if type(public) is not Public:raise ValueError("study master context")
        self.public=public;p=public.params
        self._f,self._g,self._F,self._G=(coefficients(a,p.n) for a in (f,g,F,G))
        unit=(p.q,)+(0,)*(p.n-1)
        if add(mul(self._f,self._G),neg(mul(self._g,self._F)))!=unit:raise ValueError("integer NTRU equation")
        if any(sum(x*x for x in a)>p.n*p.key_width**2 for a in (self._f,self._g)):
            raise ValueError("NTRU f/g norm")
        if sum(x*x for a in (self._F,self._G) for x in a)>p.n**2*p.key_width**2:raise ValueError("NTRU F/G norm")
        if mul(self._g,inverse(self._f,p.q),p.q)!=public.h:raise ValueError("master/public mismatch")
        self._cache={};self._lock=threading.RLock();self._sampler=None

    def __repr__(self):return "<Xie equation study private master>"

    def extract(self,identity,*,rng=None):
        identity=validate_identity(identity,max_bytes=self.public.params.identity_bytes)
        with self._lock:
            if identity in self._cache:
                if self._cache[identity] is None:raise PendingIdentity("failed identity; automatic reissue forbidden")
                return self._cache[identity]
            if len(self._cache)>=self.public.params.max_identities:raise ValueError("identity capacity")
            from .execution import require_main_thread
            require_main_thread("fresh identity extraction")
            from .runtime import preimage_sampler,BudgetRandom
            from .hashing import identity_hash
            if self._sampler is None:self._sampler=preimage_sampler(self)
            self._cache[identity]=None
            # Any entropy/sample/validation exception leaves the tombstone.
            result=self._sampler.sample(identity_hash(self.public,identity),rng=BudgetRandom(self.public.params,rng))
            key=IdentitySecret(self.public,identity,result[:self.public.params.n],result[self.public.params.n:])
            self._cache[identity]=key
            return key

    def to_bytes(self):
        with self._lock:
            return encode("XIE-STUDY-MASTER",dict(public=self.public.record(),
                f=list(self._f),g=list(self._g),F=list(self._F),G=list(self._G),
                cache=[[identity.hex(),key.record() if key is not None else None]
                       for identity,key in sorted(self._cache.items())]))

    @classmethod
    @parsed
    def from_bytes(cls,raw):
        v=decode(raw,"XIE-STUDY-MASTER");fields(v,("public","f","g","F","G","cache"))
        result=cls(Public.from_record(v["public"]),v["f"],v["g"],v["F"],v["G"])
        if type(v["cache"]) is not list or len(v["cache"])>result.public.params.max_identities:raise ValueError("study cache size")
        previous=None
        for entry in v["cache"]:
            if type(entry) is not list or len(entry)!=2:raise ValueError("study cache entry")
            identity=octets(entry[0],result.public.params.identity_bytes)
            validate_identity(identity,max_bytes=result.public.params.identity_bytes)
            if previous is not None and identity<=previous:raise ValueError("duplicate/unsorted identity")
            previous=identity;key=IdentitySecret.from_record(entry[1]) if entry[1] is not None else None
            if key is not None and (key.identity!=identity or key.public!=result.public):raise ValueError("study cache context")
            result._cache[identity]=key
        return result
