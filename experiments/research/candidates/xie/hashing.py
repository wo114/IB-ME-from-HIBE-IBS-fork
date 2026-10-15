"""Bounded domain-separated SHAKE candidate, not an ideal-RO theorem."""
import hashlib
from math import comb

from ibme.core.types import validate_identity,validate_bytes
from .ring import coefficients


def frame(*items):return b"".join(len(x).to_bytes(4,"big")+x for x in items)


class HashAbort(RuntimeError):pass


class XOF:
    def __init__(self,address):self.shake=hashlib.shake_256(address);self.offset=0
    def read(self,n):
        if self.offset+n>65536:raise HashAbort("hash byte budget")
        result=self.shake.digest(self.offset+n)[self.offset:];self.offset+=n
        return result


def uniform(source,bound):
    bits=(bound-1).bit_length();size=(bits+7)//8;mask=(1<<bits)-1
    for _ in range(128):
        raw=source.read(size)
        if type(raw) is not bytes or len(raw)!=size:raise HashAbort("hash source output")
        value=int.from_bytes(raw,"big")&mask
        if value<bound:return value
    raise HashAbort("hash rejection budget")


def identity_hash(public,identity):
    identity=validate_identity(identity,max_bytes=public.params.identity_bytes)
    source=XOF(frame(b"XIE-STUDY/IDENTITY/1",public.context,identity))
    return tuple(uniform(source,public.params.q) for _ in range(public.params.n))


def challenge_count(n,weight):return sum(comb(n,w)*2**w for w in range(weight+1))


def unrank_challenge(n,weight,rank):
    if type(rank) is not int or not 0<=rank<challenge_count(n,weight):raise ValueError("challenge rank")
    w=0
    while rank>=comb(n,w)*2**w:rank-=comb(n,w)*2**w;w+=1
    subset_rank,signs=divmod(rank,2**w);result=[0]*n;start=0
    for left in reversed(range(w)):
        for position in range(start,n-left):
            count=comb(n-position-1,left)
            if subset_rank<count:
                result[position]=1 if signs&1 else -1;signs>>=1;start=position+1;break
            subset_rank-=count
    return tuple(result)


def message_bytes(public,message):
    result=validate_bytes(message,name="message")
    if len(result)>public.params.message_bytes:raise ValueError("study message capacity")
    return result


def challenge_hash(public,commitment,message):
    p=public.params;commitment=coefficients(commitment,p.n,modulus=p.q)
    message=message_bytes(public,message)
    packed=b"".join(x.to_bytes(4,"big") for x in commitment)
    source=XOF(frame(b"XIE-STUDY/CHALLENGE/1",public.context,packed,message))
    return unrank_challenge(p.n,p.challenge_weight,uniform(source,challenge_count(p.n,p.challenge_weight)))
