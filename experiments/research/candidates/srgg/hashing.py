"""Canonical SRGG XOF, H(ID) and Hbar(commitment,message), no identity in Hbar."""
from hashlib import sha256, shake_256

from ibme.core.encoding import encode_bytes
from ..wang_pw.codec import canonical
from ..wang_pw.hashing import XOFStream, uniform_values

VERSION=b"IBME-SRGG-IBS-v1"
DOMAINS=(b"SRGG-XOF-v1",b"SRGG-ID-v1",b"SRGG-MESSAGE-v1")


def frame(*parts): return b"".join(encode_bytes(p) for p in parts)


def public_matrix(config,seed):
    p=config.algebra
    stream=XOFStream(frame(DOMAINS[0],canonical(config.record()),seed),p.rank*p.rank*p.degree*1024)
    values=uniform_values(stream,p.modulus,p.rank*p.rank*p.degree)
    return tuple(tuple(tuple(values[(i*p.rank+j)*p.degree:(i*p.rank+j+1)*p.degree])
                       for j in range(p.rank)) for i in range(p.rank))


def identity_target(pk,identity):
    p=pk.config.algebra
    stream=XOFStream(frame(DOMAINS[1],pk.to_bytes(),identity),p.rank*p.degree*1024)
    values=uniform_values(stream,p.modulus,p.rank*p.degree)
    return tuple(tuple(values[i*p.degree:(i+1)*p.degree]) for i in range(p.rank))


def message_challenge(pk,commitment,message):
    from .algebra import vector
    p=pk.config.algebra
    commitment=vector(p,commitment,p.rank,2*p.modulus)
    data=shake_256(frame(DOMAINS[2],pk.to_bytes(),canonical(commitment),message)).digest((p.degree+7)//8)
    return tuple((data[i//8]>>(i%8))&1 for i in range(p.degree))


def context(pk): return sha256(pk.to_bytes()).digest()
