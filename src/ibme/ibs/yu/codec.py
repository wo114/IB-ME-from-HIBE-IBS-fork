"""Strict bounded envelope and injective byte-to-fixed-bit domain encoding."""
import json
from ibme.core.errors import EncodingError, SerializationError

MAX_OBJECT = 16*1024*1024
MAX_INTEGER_BITS = 1024
MAGIC = b"IBME:Yu2026:v1:"


def bounded_bytes(data, cap=MAX_OBJECT, error=SerializationError):
    # Subclasses may override __len__ / __bytes__. Never call attacker-defined
    # Python methods before admission or while normalizing a cache identity.
    if type(data) not in (bytes,bytearray,memoryview):
        raise error("Yu expected a plain bytes/bytearray/memoryview")
    try:
        size=data.nbytes if type(data) is memoryview else len(data)
        if not 0 <= size <= cap: raise ValueError("byte budget")
        result=bytes(data)
        if len(result)>cap: raise ValueError("byte budget after copy")
        return result
    except (ValueError,TypeError,BufferError,OverflowError):
        raise error("Yu invalid or oversized byte buffer") from None


def input_bytes(value, maximum, *, identity=False):
    data=bounded_bytes(value,maximum,EncodingError)
    if identity and not data:
        raise EncodingError("Yu identity must be nonempty")
    return data


def input_bits(value, maximum, *, identity=False):
    data=input_bytes(value,maximum,identity=identity)
    # Canonical uint32 length prefix, then right zero padding to fixed width.
    # No hashing. Identity/message occupy distinct positions and PRF domains.
    encoded=len(data).to_bytes(4,"big")+data+bytes(maximum-len(data))
    return tuple((b >> i)&1 for b in encoded for i in range(7,-1,-1))


def fields(value, names):
    if type(value) is not dict or set(value) != set(names):
        raise SerializationError("Yu unknown or missing object field")
    return value


def exact_int(value, lo, hi):
    if type(value) is not int or not lo <= value <= hi:
        raise SerializationError("Yu integer outside canonical range")
    return value


def checked_matrix(value, rows, cols, *, modulus=None):
    if type(value) not in (tuple,list) or len(value) != rows:
        raise SerializationError("Yu matrix row mismatch")
    out=[]
    lo,hi=(0,modulus-1) if modulus else (-(1<<MAX_INTEGER_BITS)+1,(1<<MAX_INTEGER_BITS)-1)
    for row in value:
        if type(row) not in (tuple,list) or len(row) != cols:
            raise SerializationError("Yu matrix column mismatch")
        out.append(tuple(exact_int(x,lo,hi) for x in row))
    return tuple(out)


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")


def encode(kind, value):
    data=canonical(value)
    result=MAGIC+kind.encode("ascii")+b"\x00"+len(data).to_bytes(4,"big")+data
    if len(result)>MAX_OBJECT:
        raise SerializationError("Yu object exceeds byte budget")
    return result


def decode(kind, value):
    data=bounded_bytes(value)
    prefix=MAGIC+kind.encode("ascii")+b"\x00"
    offset=len(prefix)
    if not data.startswith(prefix) or len(data)<offset+4 or int.from_bytes(data[offset:offset+4],"big") != len(data)-offset-4:
        raise SerializationError("Yu invalid tag/length/trailing data")
    def pairs(items):
        out={}
        for key,val in items:
            if key in out: raise ValueError("duplicate field")
            out[key]=val
        return out
    def integer(text):
        if len(text)>310: raise ValueError("integer token budget")
        x=int(text)
        if x.bit_length()>MAX_INTEGER_BITS: raise ValueError("integer bit budget")
        return x
    def reject(value): raise ValueError("noninteger numeric token")
    try:
        obj=json.loads(data[offset+4:].decode("ascii"),object_pairs_hook=pairs,
                       parse_int=integer,parse_float=reject,parse_constant=reject)
        if encode(kind,obj)!=data: raise ValueError("noncanonical encoding")
        return obj
    except (ValueError,TypeError,RecursionError,UnicodeError,OverflowError) as exc:
        raise SerializationError("Yu malformed canonical object") from None
