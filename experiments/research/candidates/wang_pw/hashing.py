"""PW J_id(id,r), J_msg(M,s); Wang H1(A,x), H2(A,x,y), four independent domains."""
from hashlib import shake_256

from ibme.core.encoding import encode_bytes

DOMAINS = (b"IBME-IBS-PW-ID-v1", b"IBME-IBS-PW-MSG-v1",
           b"IBME-IBS-WANG-H1-v1", b"IBME-IBS-WANG-H2-v1")


def frame(*fields): return b"".join(encode_bytes(x) for x in fields)


def inner_identity(params, identity, salt):
    return shake_256(frame(DOMAINS[0], identity, salt)).digest(params.inner_identity_bytes)


def inner_message(params, message, salt):
    # PW's message oracle intentionally does not receive the identity.
    return shake_256(frame(DOMAINS[1], message, salt)).digest(params.inner_message_bytes)


class XOFStream:
    """Prefix-compatible SHAKE stream with a finite read budget."""
    def __init__(self, data, budget):
        self.xof, self.budget, self.position, self.buffer = shake_256(data), budget, 0, b""

    def read(self, size):
        end = self.position+size
        if size < 0 or end > self.budget: raise ValueError("hash rejection budget exhausted")
        if end > len(self.buffer):
            self.buffer = self.xof.digest(min(self.budget, max(end, len(self.buffer)*2, 4096)))
        result = self.buffer[self.position:end]
        self.position = end
        return result


def uniform_values(stream, q, count, *, max_trials=256):
    width = ((q-1).bit_length()+7)//8
    limit = (1 << (8*width))//q*q
    result = []
    for _ in range(count):
        for _ in range(max_trials):
            data = stream.read(width)
            if type(data) is not bytes or len(data) != width: raise ValueError("short hash stream")
            value = int.from_bytes(data, "big")
            if value < limit:
                result.append(value % q)
                break
        else: raise ValueError("uniform hash rejection budget exhausted")
    return tuple(result)


def _hash_values(pk, domain, fields, count):
    width = ((pk.params.q-1).bit_length()+7)//8
    stream = XOFStream(frame(domain, pk.to_bytes(), *fields), width*count*256)
    return uniform_values(stream, pk.params.q, count)


def identity_matrix(pk, inner_id):
    p = pk.params
    values = _hash_values(pk, DOMAINS[2], (inner_id,), p.n*p.w)
    return tuple(tuple(values[i*p.w:(i+1)*p.w]) for i in range(p.n))


def message_vector(pk, inner_id, inner_msg):
    return _hash_values(pk, DOMAINS[3], (inner_id, inner_msg), pk.params.n)
