"""Bounded canonical study snapshots. Secret snapshots are plaintext."""
import json

from ibme.core.errors import SerializationError


def encode(kind,fields):
    return json.dumps(dict(kind=kind,fields=fields),sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")


def decode(raw,kind,*,limit=1024*1024):
    if type(raw) is not bytes or len(raw)>limit:raise SerializationError("study input type/size")
    def pairs(items):
        out={}
        for key,value in items:
            if key in out:raise ValueError("duplicate field")
            out[key]=value
        return out
    try:
        value=json.loads(raw,object_pairs_hook=pairs)
        if type(value) is not dict or set(value)!={"kind","fields"} or value["kind"]!=kind:raise ValueError("study kind")
        if type(value["fields"]) is not dict or encode(kind,value["fields"])!=raw:raise ValueError("study canonical encoding")
        return value["fields"]
    except (TypeError,ValueError,UnicodeError,RecursionError) as exc:raise SerializationError("invalid study snapshot") from exc


def fields(value,expected):
    if type(value) is not dict or set(value)!=set(expected):raise SerializationError("study fields")
    return value


def octets(value,maximum):
    if type(value) is not str or len(value)>2*maximum or len(value)%2:raise SerializationError("study hex length/type")
    try:result=bytes.fromhex(value)
    except ValueError as exc:raise SerializationError("study hex") from exc
    if result.hex()!=value:raise SerializationError("study canonical hex")
    return result
