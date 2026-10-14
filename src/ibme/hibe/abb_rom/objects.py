"""Strict ABB object framing, bounded signed integers and fixed address state.

Ciphertexts contain profile/public context and bit blocks, no identity labels.
Private restores additionally validate complete lattice/identity equations in
the primitive's own Sage validator; parsing never certifies provenance.
"""

from dataclasses import dataclass, field
from hashlib import shake_256
from threading import RLock

from ibme.core.encoding import encode_bytes
from ibme.core.errors import SerializationError, EncodingError
from ibme.core.types import validate_identity
from .params import ABBROMParams

MAGIC = b"ABRF1"
MAX_PRIVATE_INTEGER_BITS = 4096


class Reader:
    def __init__(self, data, role):
        if not isinstance(data, bytes) or not 1 <= len(data) <= 128*2**20:
            raise SerializationError("bounded ABB object bytes required")
        self.data, self.position = data, 0
        if self.take(len(MAGIC)) != MAGIC or self.lp(16) != role:
            raise SerializationError("unknown ABB object/version")
        self.params = ABBROMParams.from_bytes(self.lp(16384))
        if len(data) > self.params.max_blob_bytes:
            raise SerializationError("ABB object exceeds selected profile budget")

    def take(self, count):
        if type(count) is not int or not 0 <= count <= len(self.data)-self.position:
            raise SerializationError("truncated ABB object")
        result = self.data[self.position:self.position+count]
        self.position += count
        return result

    def u32(self):
        return int.from_bytes(self.take(4),"big")

    def lp(self, maximum):
        size = self.u32()
        if size > maximum:
            raise SerializationError("ABB length field exceeds budget")
        return self.take(size)

    def finish(self):
        if self.position != len(self.data):
            raise SerializationError("appended/duplicate ABB fields")


def header(role, params):
    if not isinstance(params, ABBROMParams):
        raise TypeError("ABBROMParams required")
    return MAGIC+encode_bytes(role)+encode_bytes(params.to_bytes())


def residues(values, height, width, q):
    if not isinstance(values,(tuple,list)) or len(values) != height:
        raise SerializationError("ABB public matrix height")
    result = []
    for row in values:
        if not isinstance(row,(tuple,list)) or len(row) != width:
            raise SerializationError("ABB public matrix width")
        if any(type(x) is not int or not 0 <= x < q for x in row):
            raise SerializationError("noncanonical ABB residue")
        result.append(tuple(row))
    return tuple(result)


def private_rows(values, dimension):
    if not isinstance(values,(tuple,list)) or len(values) != dimension:
        raise SerializationError("ABB private matrix height")
    output = []
    for row in values:
        if not isinstance(row,(tuple,list)) or len(row) != dimension:
            raise SerializationError("ABB private matrix width")
        if any(type(x) is not int or abs(x).bit_length()>MAX_PRIVATE_INTEGER_BITS for x in row):
            raise SerializationError("ABB signed private coefficient outside budget")
        output.append(tuple(row))
    return tuple(output)


def encode_signed_rows(rows):
    result = bytearray()
    for row in rows:
        for value in row:
            magnitude = abs(value)
            raw = magnitude.to_bytes(max(1,(magnitude.bit_length()+7)//8),"big")
            result.append(int(value<0))
            result.extend(encode_bytes(raw))
    return bytes(result)


def decode_signed_rows(reader, dimension):
    count = dimension**2
    if len(reader.data)-reader.position < count*6:
        raise SerializationError("truncated ABB integer matrix")
    output = []
    for _ in range(dimension):
        row = []
        for _ in range(dimension):
            sign = reader.take(1)[0]
            raw = reader.lp((MAX_PRIVATE_INTEGER_BITS+7)//8)
            if sign not in (0,1) or not raw or len(raw)>1 and raw[0]==0:
                raise SerializationError("noncanonical ABB signed integer")
            value = int.from_bytes(raw,"big")
            if sign and value==0:
                raise SerializationError("negative zero in ABB integer matrix")
            row.append(-value if sign else value)
        output.append(tuple(row))
    return tuple(output)


@dataclass(frozen=True)
class ABBPublicKey:
    params: ABBROMParams
    a: tuple
    u0: tuple

    def __post_init__(self):
        if not isinstance(self.params,ABBROMParams):
            raise TypeError("ABBROMParams required")
        p = self.params
        if len(header(b"PK",p))+4+(p.n*p.dimension+p.n)*((p.q.bit_length()+7)//8)>p.max_blob_bytes:
            raise SerializationError("ABB public wire exceeds selected profile budget")
        object.__setattr__(self,"a",residues(self.a,p.n,p.dimension,p.q))
        if not isinstance(self.u0,(tuple,list)) or len(self.u0)!=p.n or any(type(x) is not int or not 0<=x<p.q for x in self.u0):
            raise SerializationError("noncanonical ABB u0")
        object.__setattr__(self,"u0",tuple(self.u0))

    @property
    def context(self):
        return shake_256(b"IBME:ABB-ROM:PUBLIC-CONTEXT:v1"+encode_bytes(self.to_bytes())).digest(64)

    def to_bytes(self):
        width = (self.params.q.bit_length()+7)//8
        raw = b"".join(x.to_bytes(width,"big") for row in self.a for x in row)
        raw += b"".join(x.to_bytes(width,"big") for x in self.u0)
        return header(b"PK",self.params)+encode_bytes(raw)

    @classmethod
    def from_bytes(cls,data):
        r = Reader(data,b"PK"); p = r.params
        width = (p.q.bit_length()+7)//8
        raw = r.lp((p.n*p.dimension+p.n)*width)
        if len(raw)!=(p.n*p.dimension+p.n)*width:
            raise SerializationError("ABB public dimensions mismatch")
        values = tuple(int.from_bytes(raw[i:i+width],"big") for i in range(0,len(raw),width))
        a = tuple(values[i*p.dimension:(i+1)*p.dimension] for i in range(p.n))
        result = cls(p,a,values[p.n*p.dimension:])
        r.finish()
        if result.to_bytes()!=data:
            raise SerializationError("noncanonical ABB public wire")
        return result


def secret_prefix(role, public, path):
    body = header(role,public.params)+encode_bytes(public.to_bytes())+public.context
    for identity in path:
        body += encode_bytes(identity)
    return body


def read_secret_prefix(data,role,depth):
    r = Reader(data,role)
    pk = ABBPublicKey.from_bytes(r.lp(r.params.max_blob_bytes))
    if pk.params != r.params or r.take(64)!=pk.context:
        raise SerializationError("ABB private/public context mismatch")
    path = tuple(read_identity(r,pk.params.identity_max_bytes) for _ in range(depth))
    return r,pk,path


def read_identity(reader,maximum):
    try:
        return validate_identity(reader.lp(maximum),max_bytes=maximum)
    except EncodingError as exc:
        raise SerializationError("invalid ABB identity field") from exc


def validate_secret(public,path,rows):
    from .key_validation import validate_basis
    try:
        validate_basis(public,path,rows)
    except Exception as exc:
        raise SerializationError("ABB private lattice/identity binding failed") from exc


@dataclass(repr=False)
class ABBLevel2Key:
    public_key: ABBPublicKey
    parent_identity: bytes
    child_identity: bytes
    basis: tuple = field(repr=False)

    def __post_init__(self):
        p = self.public_key.params
        self.parent_identity = validate_identity(self.parent_identity,max_bytes=p.identity_max_bytes)
        self.child_identity = validate_identity(self.child_identity,max_bytes=p.identity_max_bytes)
        self.basis = private_rows(self.basis,p.dimension)

    def to_bytes(self):
        body = secret_prefix(b"SK2",self.public_key,(self.parent_identity,self.child_identity))
        result = body+encode_signed_rows(self.basis)
        if len(result)>self.public_key.params.max_blob_bytes:
            raise SerializationError("ABB leaf wire budget exceeded")
        return result

    @classmethod
    def from_bytes(cls,data):
        r,pk,path = read_secret_prefix(data,b"SK2",2)
        rows = decode_signed_rows(r,pk.params.dimension); r.finish()
        validate_secret(pk,path,rows)
        return cls(pk,*path,rows)


def encode_cache(cache, maximum, encode_key):
    if type(cache) is not dict or len(cache)>maximum:
        raise SerializationError("ABB fixed-address cache budget")
    out = bytearray(len(cache).to_bytes(4,"big"))
    for identity in sorted(cache):
        out.extend(encode_bytes(identity))
        value = cache[identity]
        out.append(int(value is None))
        if value is not None:
            out.extend(encode_bytes(encode_key(value)))
    return bytes(out)


def read_cache(r,maximum,decode_key,identity_max,blob_max):
    count = r.u32()
    if count>maximum:
        raise SerializationError("ABB fixed-address count exceeded")
    result = {}; previous = None
    for _ in range(count):
        identity = read_identity(r,identity_max)
        if previous is not None and identity<=previous:
            raise SerializationError("duplicate/noncanonical ABB address order")
        previous = identity
        failed = r.take(1)
        if failed not in (b"\x00",b"\x01"):
            raise SerializationError("ABB address state flag")
        result[identity] = None if failed==b"\x01" else decode_key(r.lp(blob_max))
    return result


@dataclass(repr=False)
class ABBLevel1Key:
    public_key: ABBPublicKey
    identity: bytes
    basis: tuple = field(repr=False)
    children: dict = field(default_factory=dict,repr=False)
    lock: object = field(default_factory=RLock,repr=False,compare=False)

    def __post_init__(self):
        self.identity = validate_identity(self.identity,max_bytes=self.public_key.params.identity_max_bytes)
        self.basis = private_rows(self.basis,self.public_key.params.dimension)
        if type(self.children) is not dict or len(self.children)>self.public_key.params.max_children_per_parent:
            raise SerializationError("ABB child cache shape")
        for identity,value in self.children.items():
            validate_identity(identity,max_bytes=self.public_key.params.identity_max_bytes)
            if value is not None and (not isinstance(value,ABBLevel2Key) or value.public_key!=self.public_key or
                    value.parent_identity!=self.identity or value.child_identity!=identity):
                raise SerializationError("ABB child cache binding mismatch")

    def to_bytes(self):
        with self.lock:
            # State is mutable: re-check current addresses at every write,
            # rather than trusting only the initial constructor.
            self.__post_init__()
            result = secret_prefix(b"SK1",self.public_key,(self.identity,))+encode_signed_rows(self.basis)
            result += encode_cache(self.children,self.public_key.params.max_children_per_parent,lambda x:x.to_bytes())
            if len(result)>self.public_key.params.max_blob_bytes:
                raise SerializationError("ABB receiver wire budget exceeded")
            return result

    @classmethod
    def from_bytes(cls,data):
        r,pk,path = read_secret_prefix(data,b"SK1",1)
        rows = decode_signed_rows(r,pk.params.dimension)
        children = read_cache(r,pk.params.max_children_per_parent,ABBLevel2Key.from_bytes,
            pk.params.identity_max_bytes,pk.params.max_blob_bytes)
        r.finish(); validate_secret(pk,path,rows)
        return cls(pk,path[0],rows,children)


@dataclass(repr=False)
class ABBMasterSecret:
    public_key: ABBPublicKey
    basis: tuple = field(repr=False)
    parents: dict = field(default_factory=dict,repr=False)
    lock: object = field(default_factory=RLock,repr=False,compare=False)

    def __post_init__(self):
        self.basis = private_rows(self.basis,self.public_key.params.dimension)
        if type(self.parents) is not dict or len(self.parents)>self.public_key.params.max_parents:
            raise SerializationError("ABB parent cache shape")
        for identity,value in self.parents.items():
            validate_identity(identity,max_bytes=self.public_key.params.identity_max_bytes)
            if value is not None and (not isinstance(value,ABBLevel1Key) or value.public_key!=self.public_key or value.identity!=identity):
                raise SerializationError("ABB parent cache binding mismatch")

    def to_bytes(self):
        with self.lock:
            self.__post_init__()
            result = secret_prefix(b"MSK",self.public_key,())+encode_signed_rows(self.basis)
            result += encode_cache(self.parents,self.public_key.params.max_parents,lambda x:x.to_bytes())
            if len(result)>self.public_key.params.max_blob_bytes:
                raise SerializationError("ABB master state wire budget exceeded")
            return result

    @classmethod
    def from_bytes(cls,data):
        r,pk,path = read_secret_prefix(data,b"MSK",0)
        rows = decode_signed_rows(r,pk.params.dimension)
        parents = read_cache(r,pk.params.max_parents,ABBLevel1Key.from_bytes,
            pk.params.identity_max_bytes,pk.params.max_blob_bytes)
        r.finish(); validate_secret(pk,path,rows)
        return cls(pk,rows,parents)


@dataclass(frozen=True)
class ABBCiphertext:
    params: ABBROMParams
    context: bytes
    payload_bytes: int
    blocks: tuple

    def __post_init__(self):
        if not isinstance(self.params,ABBROMParams) or not isinstance(self.context,bytes) or len(self.context)!=64:
            raise SerializationError("ABB ciphertext context/profile shape")
        if type(self.payload_bytes) is not int or not 0<=self.payload_bytes<=self.params.payload_max_bytes:
            raise SerializationError("ABB raw payload capacity")
        p=self.params
        if len(header(b"CT",p))+64+4+8*self.payload_bytes*(p.dimension+1)*((p.q.bit_length()+7)//8)>p.max_blob_bytes:
            raise SerializationError("ABB ciphertext wire exceeds selected profile budget")
        object.__setattr__(self,"blocks",residues(self.blocks,8*self.payload_bytes,self.params.dimension+1,self.params.q))

    def to_bytes(self):
        width = (self.params.q.bit_length()+7)//8
        return header(b"CT",self.params)+self.context+self.payload_bytes.to_bytes(4,"big")+b"".join(
            x.to_bytes(width,"big") for row in self.blocks for x in row)

    @classmethod
    def from_bytes(cls,data):
        r = Reader(data,b"CT"); p = r.params
        ctx,count = r.take(64),r.u32()
        if count>p.payload_max_bytes:
            raise SerializationError("ABB ciphertext payload length")
        width = (p.q.bit_length()+7)//8
        raw = r.take(count*8*(p.dimension+1)*width)
        values = tuple(int.from_bytes(raw[i:i+width],"big") for i in range(0,len(raw),width))
        blocks = tuple(values[i*(p.dimension+1):(i+1)*(p.dimension+1)] for i in range(8*count))
        result = cls(p,ctx,count,blocks); r.finish()
        return result
