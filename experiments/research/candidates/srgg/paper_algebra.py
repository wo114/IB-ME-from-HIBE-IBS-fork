"""Reuse exact SRGG relations under the paper's separate public namespace."""
from hashlib import shake_256

from sage.all import PolynomialRing, ZZ

from experiments.research.candidates.wang_pw.hashing import XOFStream, uniform_values
from .paper_parameters import PaperParams
from .structured_execution import ExactRing, _canonical, _frame, _bytes

DOMAIN = b"IBME-SRGG-paper-Table4-v1"


class PaperRing(ExactRing):
    """Same algebra, without the optimization candidate's parameter gates."""
    def __init__(self, params):
        if type(params) is not PaperParams:
            raise TypeError("published PaperParams required")
        self.params, self.n = params, params.degree
        self.ring = PolynomialRing(ZZ, "x")
        self.modulus = self.ring.gen()**self.n+1
        self.products = 0


def public_matrix(params, seed):
    _bytes(seed, "public seed", 32, 32)
    count = params.rank**2*params.degree
    stream = XOFStream(_frame(DOMAIN, b"matrix", _canonical(params.record()), seed), count*4096)
    values = uniform_values(stream, params.modulus, count)
    n, d = params.degree, params.rank
    return tuple(tuple(tuple(values[(i*d+j)*n:(i*d+j+1)*n])
                       for j in range(d)) for i in range(d))


def identity_target(public, identity):
    _bytes(identity, "identity", 1)
    p = public.params
    count = p.rank*p.degree
    stream = XOFStream(_frame(DOMAIN, b"identity", public.to_bytes(), identity), count*4096)
    values = uniform_values(stream, p.modulus, count)
    return tuple(tuple(values[i*p.degree:(i+1)*p.degree]) for i in range(p.rank))


def message_challenge(public, commitment, message):
    _bytes(message, "message", maximum=65536)
    p = public.params
    commitment = PaperRing(p).vector(commitment, p.rank, 2*p.modulus)
    data = shake_256(_frame(DOMAIN, b"message", public.to_bytes(),
                           _canonical(commitment), message)).digest((p.degree+7)//8)
    return tuple((data[i//8] >> (i%8)) & 1 for i in range(p.degree))
