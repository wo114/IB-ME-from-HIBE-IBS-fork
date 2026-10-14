"""Five strict LATTE objects and opaque fixed-issuance snapshots.

Secret records contain real ring bases/short vectors. They are not public audit
records. Restore validates exact public/path equations without native sampling.
"""
from dataclasses import dataclass, field
from hashlib import sha256
from threading import RLock
from ibme.core.types import validate_identity,constant_time_equal
from . import codec
from .params import LATTEParams, VERSION
from .math import check_basis, check_leaf


def identity(value, p):
    return validate_identity(value, max_bytes=p.identity_bytes)


def _id_record(value, p):
    if type(value) is not str or len(value) > 2*p.identity_bytes:
        raise ValueError("LATTE bounded identity encoding")
    return identity(codec.hexadecimal(value, len(value)//2), p)


@dataclass(frozen=True, repr=False)
class LATTEPublicKey:
    params: LATTEParams
    h: tuple

    def __post_init__(self):
        if type(self.params) is not LATTEParams:
            raise ValueError("LATTE parameters required")
        object.__setattr__(self, "h", codec.poly(self.h))

    @property
    def digest(self):
        return sha256(self.to_bytes()).digest()

    def record(self):
        return dict(schema=VERSION+"/PUBLIC", params=self.params.record(), h=self.h)

    def to_bytes(self):
        return codec.write(self.record())

    @classmethod
    def from_record(cls, value):
        codec.fields(value, "PUBLIC", ("params", "h"))
        return cls(LATTEParams.from_record(value["params"]), value["h"])

    @classmethod
    def from_bytes(cls, raw):
        return codec.decode(raw, cls.from_record)


@dataclass(frozen=True, repr=False)
class LATTELevel2SecretKey:
    public_key: LATTEPublicKey
    parent_identity: bytes
    child_identity: bytes
    secret: tuple = field(repr=False)

    def __post_init__(self):
        if type(self.public_key) is not LATTEPublicKey:
            raise ValueError("LATTE public context required")
        p=self.public_key.params
        object.__setattr__(self,"parent_identity",identity(self.parent_identity,p))
        object.__setattr__(self,"child_identity",identity(self.child_identity,p))
        object.__setattr__(self,"secret",codec.polynomials(self.secret,2,private=True))
        check_leaf(self.public_key,self.parent_identity,self.child_identity,self.secret)

    @property
    def params(self):
        return self.public_key.params

    def record(self):
        return dict(schema=VERSION+"/LEAF", public=self.public_key.record(),
            parent=self.parent_identity.hex(),child=self.child_identity.hex(),secret=self.secret)

    def to_bytes(self):
        return codec.write(self.record())

    @classmethod
    def from_record(cls,value):
        codec.fields(value,"LEAF",("public","parent","child","secret"))
        public=LATTEPublicKey.from_record(value["public"])
        return cls(public,_id_record(value["parent"],public.params),
            _id_record(value["child"],public.params),value["secret"])

    @classmethod
    def from_bytes(cls,raw):
        return codec.decode(raw,cls.from_record)


@dataclass(frozen=True, repr=False)
class LATTELevel1SecretKey:
    public_key: LATTEPublicKey
    identity: bytes
    basis: tuple = field(repr=False)
    _entries: dict = field(default_factory=dict,init=False,repr=False,compare=False)
    _lock: object = field(default_factory=RLock,init=False,repr=False,compare=False)

    def __post_init__(self):
        if type(self.public_key) is not LATTEPublicKey:
            raise ValueError("LATTE public context required")
        object.__setattr__(self,"identity",identity(self.identity,self.public_key.params))
        object.__setattr__(self,"basis",codec.polynomials(self.basis,9,private=True))
        check_basis(self.public_key,self.basis,self.identity)

    @property
    def params(self):
        return self.public_key.params

    def record(self):
        with self._lock:
            return dict(schema=VERSION+"/PARENT",public=self.public_key.record(),
                identity=self.identity.hex(),basis=self.basis,
                entries=[dict(identity=k.hex(),key=None if v is None else v.record())
                         for k,v in sorted(self._entries.items())])

    def to_bytes(self):
        return codec.write(self.record())

    @classmethod
    def from_record(cls,value):
        codec.fields(value,"PARENT",("public","identity","basis","entries"))
        public=LATTEPublicKey.from_record(value["public"])
        result=cls(public,_id_record(value["identity"],public.params),value["basis"])
        restore_entries(result,value["entries"],public.params.max_children,LATTELevel2SecretKey)
        return result

    @classmethod
    def from_bytes(cls,raw):
        return codec.decode(raw,cls.from_record)


@dataclass(frozen=True, repr=False)
class LATTEMasterSecret:
    public_key: LATTEPublicKey
    basis: tuple = field(repr=False)
    _entries: dict = field(default_factory=dict,init=False,repr=False,compare=False)
    _lock: object = field(default_factory=RLock,init=False,repr=False,compare=False)

    def __post_init__(self):
        if type(self.public_key) is not LATTEPublicKey:
            raise ValueError("LATTE public context required")
        object.__setattr__(self,"basis",codec.polynomials(self.basis,4,private=True))
        check_basis(self.public_key,self.basis)

    @property
    def params(self):
        return self.public_key.params

    def record(self):
        # Issued/restored tree nodes share this reentrant lock, so a parent
        # pending callback can safely persist the whole root snapshot.
        with self._lock:
            return dict(schema=VERSION+"/MASTER",public=self.public_key.record(),basis=self.basis,
                entries=[dict(identity=k.hex(),key=None if v is None else v.record())
                         for k,v in sorted(self._entries.items())])

    def to_bytes(self):
        return codec.write(self.record())

    @classmethod
    def from_record(cls,value):
        codec.fields(value,"MASTER",("public","basis","entries"))
        result=cls(LATTEPublicKey.from_record(value["public"]),value["basis"])
        restore_entries(result,value["entries"],result.params.max_receivers,LATTELevel1SecretKey)
        return result

    @classmethod
    def from_bytes(cls,raw):
        return codec.decode(raw,cls.from_record)


def restore_entries(owner,entries,capacity,key_type):
    if type(entries) is not list or len(entries)>capacity:
        raise ValueError("LATTE snapshot issuance capacity")
    previous=None
    for entry in entries:
        if type(entry) is not dict or set(entry)!={"identity","key"}:
            raise ValueError("LATTE issuance entry fields")
        address=_id_record(entry["identity"],owner.params)
        if previous is not None and address<=previous:
            raise ValueError("LATTE duplicate or unordered issuance address")
        previous=address
        key=None if entry["key"] is None else key_type.from_record(entry["key"])
        if key is not None:
            if key.public_key.to_bytes()!=owner.public_key.to_bytes():
                raise ValueError("LATTE cached public context mismatch")
            if key_type is LATTELevel1SecretKey:
                if not constant_time_equal(key.identity,address):
                    raise ValueError("LATTE cached receiver mismatch")
                object.__setattr__(key,"_lock",owner._lock)
            elif (not constant_time_equal(key.child_identity,address) or
                    not constant_time_equal(key.parent_identity,owner.identity)):
                raise ValueError("LATTE cached identity path mismatch")
        owner._entries[address]=key


@dataclass(frozen=True, repr=False)
class LATTECiphertext:
    params: LATTEParams
    public_digest: bytes
    z: bytes
    c: tuple

    def __post_init__(self):
        if type(self.params) is not LATTEParams:
            raise ValueError("LATTE ciphertext parameters")
        if type(self.public_digest) is not bytes or len(self.public_digest)!=32 or type(self.z) is not bytes or len(self.z)!=32:
            raise ValueError("LATTE ciphertext fixed fields")
        object.__setattr__(self,"c",codec.polynomials(self.c,3))

    def record(self):
        return dict(schema=VERSION+"/CIPHERTEXT",params=self.params.record(),
            public_digest=self.public_digest.hex(),z=self.z.hex(),c=self.c)

    def to_bytes(self):
        return codec.write(self.record())

    @classmethod
    def from_record(cls,value):
        codec.fields(value,"CIPHERTEXT",("params","public_digest","z","c"))
        return cls(LATTEParams.from_record(value["params"]),codec.hexadecimal(value["public_digest"],32),
            codec.hexadecimal(value["z"],32),value["c"])

    @classmethod
    def from_bytes(cls,raw):
        return codec.decode(raw,cls.from_record)
