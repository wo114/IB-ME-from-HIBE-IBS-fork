"""Public-only equation study verification. Does not require Sage or secrets."""
from ibme.core.errors import EncodingError,SerializationError
from .objects import Public,Signature
from .hashing import identity_hash,challenge_hash,message_bytes,HashAbort
from .ring import add,neg,mul


def verify(public,identity,message,signature):
    if type(public) is not Public or type(signature) is not Signature:return False
    p=public.params
    if signature.context!=public.context or len(signature.u)!=p.n:return False
    if sum(abs(x) for x in signature.u)>p.challenge_weight:return False
    if sum(x*x for x in signature.z1+signature.z2)>8*p.n*p.signing_width**2:return False
    try:
        message=message_bytes(public,message);t=identity_hash(public,identity)
        commitment=add(add(signature.z1,mul(public.h,signature.z2,p.q),p.q),neg(mul(t,signature.u,p.q)),p.q)
        return challenge_hash(public,commitment,message)==signature.u
    except (EncodingError,ValueError,HashAbort):return False


def load_signature(public,raw):
    if type(public) is not Public:raise TypeError("study public key")
    result=Signature.from_bytes(raw)
    if (result.context!=public.context or len(result.u)!=public.params.n
            or sum(abs(x) for x in result.u)>public.params.challenge_weight):
        raise SerializationError("study signature parameter binding")
    return result
