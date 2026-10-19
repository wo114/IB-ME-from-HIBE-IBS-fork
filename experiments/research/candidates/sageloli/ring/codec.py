"""Canonical bounded big-integer tensors. No pickle or implicit v2 migration."""
import json
import struct

MAGIC=b"IBME:SAGELOLI-RSIS:v3\0"
MAX_BYTES=2**31
MAX_ELEMENTS=2**27
MAX_BITS=512


def integer(value, low=0, high=2**64-1):
    if type(value) is not int or not low<=value<=high:
        raise ValueError("bounded exact integer required")
    return value


def frame(kind, fields):
    if type(kind) is not bytes or not 1<=len(kind)<=32 or len(fields)>32:
        raise ValueError("invalid frame header")
    parts=[MAGIC,bytes([len(kind)]),kind,struct.pack(">I",len(fields))]
    for data in fields:
        if type(data) is not bytes or len(data)>MAX_BYTES:
            raise ValueError("invalid frame field")
        parts.extend((struct.pack(">Q",len(data)),data))
    if sum(map(len,parts))>MAX_BYTES: raise ValueError("frame capacity exceeded")
    return b"".join(parts)


def unframe(raw,kind,count):
    if type(raw) is not bytes or len(raw)>MAX_BYTES or not raw.startswith(MAGIC):
        raise ValueError("invalid v3 wire")
    p=len(MAGIC)
    def take(n):
        nonlocal p
        if n<0 or n>len(raw)-p: raise ValueError("truncated wire")
        out=raw[p:p+n]; p+=n; return out
    if take(take(1)[0])!=kind or int.from_bytes(take(4),"big")!=count:
        raise ValueError("wrong object kind/field count")
    fields=[]
    for _ in range(count):
        size=int.from_bytes(take(8),"big")
        if size>MAX_BYTES: raise ValueError("field capacity exceeded")
        fields.append(take(size))
    if p!=len(raw): raise ValueError("trailing wire")
    return tuple(fields)


def params_bytes(params):
    return json.dumps(params.record(),sort_keys=True,separators=(",",":")).encode()


def params_from(raw):
    from .params import RingParams
    if len(raw)>8192: raise ValueError("oversized parameter record")
    def pairs(items):
        d={}
        for k,v in items:
            if k in d: raise ValueError("duplicate parameter field")
            d[k]=v
        return d
    p=RingParams.from_record(json.loads(raw,object_pairs_hook=pairs))
    if params_bytes(p)!=raw: raise ValueError("noncanonical parameter record")
    return p


def tensor(values,shape,bits,*,signed=False):
    """Fixed byte slots; explicit bit width rejects spare high-bit aliases."""
    import numpy as np
    integer(bits,1,MAX_BITS)
    if not 1<=len(shape)<=3: raise ValueError("bad tensor rank")
    count=1
    for n in shape: count*=integer(n,1,2**20)
    if count>MAX_ELEMENTS: raise ValueError("tensor element limit")
    width=(bits+7)//8
    if count*width>MAX_BYTES: raise ValueError("tensor byte limit")
    a=np.asarray(values)
    if a.shape!=tuple(shape): raise ValueError("tensor shape mismatch")
    low=-(1<<(bits-1)) if signed else 0
    high=(1<<(bits-1))-1 if signed else (1<<bits)-1
    header=bytes([len(shape),int(signed)])+struct.pack(">H",bits)+b"".join(struct.pack(">I",n) for n in shape)
    if a.dtype.kind not in "iuO": raise ValueError("exact integer tensor required")
    if signed and bits in (8,16,32,64) and a.dtype.kind in "iu":
        if a.size and (int(a.min())<low or int(a.max())>high):
            raise ValueError("coefficient outside declared width")
        return header+a.astype(">i"+str(width),copy=False).tobytes()
    out=bytearray(count*width)
    for i,v in enumerate(a.flat):
        if not isinstance(v,(int,np.integer)) or isinstance(v,(bool,np.bool_)):
            raise ValueError("exact integer tensor required")
        v=int(v)
        if not low<=v<=high: raise ValueError("coefficient outside declared width")
        out[i*width:(i+1)*width]=v.to_bytes(width,"big",signed=signed)
    return header+out


def tensor_from(raw,shape,bits,*,signed=False,modulus=None):
    import numpy as np
    header=bytes([len(shape),int(signed)])+struct.pack(">H",bits)+b"".join(struct.pack(">I",n) for n in shape)
    count=1
    for n in shape: count*=integer(n,1,2**20)
    if count>MAX_ELEMENTS or not 1<=bits<=MAX_BITS: raise ValueError("tensor limit")
    width=(bits+7)//8
    if len(raw)!=len(header)+count*width or not raw.startswith(header):
        raise ValueError("wrong tensor layout")
    data=memoryview(raw)[len(header):]
    if signed and bits in (8,16,32,64):
        return np.frombuffer(data,dtype=">i"+str(width)).astype(np.int64).reshape(shape)
    low=-(1<<(bits-1)) if signed else 0
    high=(1<<(bits-1))-1 if signed else (1<<bits)-1
    values=[]
    for i in range(count):
        v=int.from_bytes(data[i*width:(i+1)*width],"big",signed=signed)
        if not low<=v<=high or modulus is not None and v>=modulus:
            raise ValueError("noncanonical coefficient")
        values.append(v)
    return np.array(values,dtype=object).reshape(shape)
