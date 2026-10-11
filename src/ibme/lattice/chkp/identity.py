"""Canonical H/G for the depth-two CHKP ROHIBE and its 256-bit amortization.

CHKP, fixed 36-page author version, sections 5.1--5.3, PDF pp. 19--22.
This defines the real public identity algorithm, never the proof simulator's
controlled-growth matrices or hidden trapdoors. SHAKE-256 instantiates two
domain-separated oracles; exact residue rejection has an explicit abort limit.
It does not establish a ROM/QROM theorem or certify a supplied root matrix.
"""

from dataclasses import dataclass, field
import hashlib

from ibme.core.encoding import encode_bytes
from ibme.core.errors import EncodingError, InvalidParameterError, SerializationError
from ibme.core.hashing import shake256
from ibme.core.types import validate_identity

MAGIC = b"IBME:CHKP:RO-CONTEXT:v1"
DOMAIN_CONTEXT = b"IBME:CHKP:PUBLIC-CONTEXT:v1"
DOMAIN_H = b"IBME:CHKP:RO-H:v1"
DOMAIN_G = b"IBME:CHKP:RO-G-POSITION:v1"
SEED_BITS = 256
MAX_ENTRIES = 2**20
MAX_CONTEXT_BYTES = 16 * 2**20
MAX_DIMENSION = 65536
MAX_RESIDUE_TRIALS = 128
MAX_PUBLIC_CONFIGURATION = 4096


def checked_int(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise InvalidParameterError(f"{name} must be an integer in {low}..{high}")
    return value


def checked_bytes(value, name, limit, *, nonempty=True):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise EncodingError(f"{name} must be bytes-like")
    size = value.nbytes if isinstance(value, memoryview) else len(value)
    if size > limit or (nonempty and size == 0):
        raise EncodingError(f"{name} has an invalid length")
    return bytes(value)


class Reader:
    def __init__(self, data, *, maximum=MAX_CONTEXT_BYTES):
        try:
            self.data = checked_bytes(data, "wire", maximum)
        except EncodingError as exc:
            raise SerializationError(str(exc)) from exc
        self.pos = 0

    def take(self, count):
        if type(count) is not int or count < 0 or self.pos + count > len(self.data):
            raise SerializationError("truncated or oversized field")
        value = self.data[self.pos:self.pos + count]
        self.pos += count
        return value

    def number(self, width=4):
        return int.from_bytes(self.take(width), "big")

    def blob(self, maximum, *, nonempty=True):
        length = self.number()
        if length > maximum or (nonempty and length == 0):
            raise SerializationError("field length outside its public budget")
        return self.take(length)

    def finish(self):
        if self.pos != len(self.data):
            raise SerializationError("appended or duplicate fields")


class _OracleStream:
    def __init__(self, domain, canonical_input):
        self.state = hashlib.shake_256(encode_bytes(domain) + encode_bytes(canonical_input))
        self.counter, self.buffer = 0, b""

    def read(self, count):
        while len(self.buffer) < count:
            block = self.state.copy()
            block.update(self.counter.to_bytes(8, "big"))
            self.buffer += block.digest(64)
            self.counter += 1
        out, self.buffer = self.buffer[:count], self.buffer[count:]
        return out


def _residues(domain, canonical_input, q, count):
    source = _OracleStream(domain, canonical_input)
    bits = (q - 1).bit_length()
    size, mask = (bits + 7) // 8, (1 << bits) - 1
    result = []
    for _ in range(count):
        for _ in range(MAX_RESIDUE_TRIALS):
            candidate = int.from_bytes(source.read(size), "big") & mask
            if candidate < q:
                result.append(candidate)
                break
        else:
            raise InvalidParameterError("identity oracle residue budget exhausted; no fallback")
    return tuple(result)


@dataclass(frozen=True)
class ROHIBEContext:
    """A canonical public root and oracle layout, not a GenBasis certificate.

    Identities are bounded raw bytes. H hashes full ordered prefixes; G hashes
    full ordered paths plus a fixed bit position. Repeated syndrome VALUES are
    allowed; independent oracle addresses need not have distinct outputs.
    """

    n: int
    m: int
    q: int
    root_rows: tuple
    public_configuration: bytes
    identity_bytes: int = 86
    seed_bits: int = field(default=SEED_BITS, init=False)
    security_claim: str = field(default="none", init=False)
    backend_admitted: bool = field(default=False, init=False)
    context: bytes = field(init=False, repr=False)

    def __post_init__(self):
        checked_int(self.n, "n", 1, 4096)
        checked_int(self.m, "m", self.n, MAX_DIMENSION // 3)
        checked_int(self.q, "q", 2, 2**61 - 1)
        checked_int(self.identity_bytes, "identity bytes", 1, 256)
        object.__setattr__(self, "public_configuration", checked_bytes(
            self.public_configuration, "full public parameter configuration", MAX_PUBLIC_CONFIGURATION))
        if self.n * self.m > MAX_ENTRIES:
            raise InvalidParameterError("public root entry budget exceeded")
        if not isinstance(self.root_rows, (tuple, list)) or len(self.root_rows) != self.n:
            raise InvalidParameterError("wrong public root row count")
        rows = []
        for row in self.root_rows:
            if not isinstance(row, (tuple, list)) or len(row) != self.m:
                raise InvalidParameterError("wrong public root column count")
            rows.append(tuple(checked_int(x, "root residue", 0, self.q - 1) for x in row))
        object.__setattr__(self, "root_rows", tuple(rows))
        object.__setattr__(self, "context", shake256(DOMAIN_CONTEXT, self.to_bytes(), 64))

    @property
    def residue_bytes(self):
        return ((self.q - 1).bit_length() + 7) // 8

    @property
    def leaf_dimension(self):
        return 3 * self.m

    def to_bytes(self):
        header = (MAGIC + self.n.to_bytes(4, "big") + self.m.to_bytes(4, "big")
                  + self.q.to_bytes(8, "big") + self.identity_bytes.to_bytes(4, "big")
                  + SEED_BITS.to_bytes(4, "big"))
        return header + encode_bytes(self.public_configuration) + b"".join(x.to_bytes(self.residue_bytes, "big")
                                  for row in self.root_rows for x in row)

    @classmethod
    def from_bytes(cls, data):
        r = Reader(data)
        if r.take(len(MAGIC)) != MAGIC:
            raise SerializationError("unknown CHKP oracle context version")
        n, m, q, identity_bytes, bits = r.number(), r.number(), r.number(8), r.number(), r.number()
        try:
            checked_int(n, "n", 1, 4096)
            checked_int(m, "m", n, MAX_DIMENSION // 3)
            checked_int(q, "q", 2, 2**61 - 1)
            checked_int(identity_bytes, "identity bytes", 1, 256)
            if bits != SEED_BITS or n * m > MAX_ENTRIES:
                raise InvalidParameterError("wrong seed capacity or public root budget")
            configuration = r.blob(MAX_PUBLIC_CONFIGURATION)
            width = ((q - 1).bit_length() + 7) // 8
            if len(r.data) - r.pos != n * m * width:
                raise SerializationError("public root size mismatch")
            rows = tuple(tuple(r.number(width) for _ in range(m)) for _ in range(n))
            r.finish()
            return cls(n, m, q, rows, configuration, identity_bytes)
        except (EncodingError, InvalidParameterError) as exc:
            raise SerializationError(str(exc)) from exc

    def path_bytes(self, path):
        if not isinstance(path, (tuple, list)) or not 1 <= len(path) <= 2:
            raise EncodingError("identity path needs one or two ordered components")
        ids = tuple(validate_identity(x, max_bytes=self.identity_bytes) for x in path)
        return len(ids).to_bytes(4, "big") + b"".join(encode_bytes(x) for x in ids)

    def h(self, path):
        data = encode_bytes(self.context) + self.path_bytes(path)
        values = _residues(DOMAIN_H, data, self.q, self.n * self.m)
        return tuple(values[i * self.m:(i + 1) * self.m] for i in range(self.n))

    def g(self, path, position):
        checked_int(position, "fixed bit position", 0, SEED_BITS - 1)
        data = encode_bytes(self.context) + self.path_bytes(path) + position.to_bytes(4, "big")
        return _residues(DOMAIN_G, data, self.q, self.n)

    def parent_rows(self, receiver):
        block = self.h((receiver,))
        return tuple(a + b for a, b in zip(self.root_rows, block))

    def leaf_rows(self, receiver, sender):
        parent = self.parent_rows(receiver)
        block = self.h((receiver, sender))
        return tuple(a + b for a, b in zip(parent, block))

    def targets(self, receiver, sender):
        path = (receiver, sender)
        # Validate both identities before hashing the first position.
        self.path_bytes(path)
        return tuple(self.g(path, position) for position in range(SEED_BITS))

    def certificate(self):
        return dict(algorithm="CHKP ROHIBE depth-two H/G; indexed G amortization",
                    context_bytes=64, matrix_shape=[self.n, self.m], depth=2,
                    seed_bits=SEED_BITS, hash="SHAKE-256, role/prefix/position/counter domains",
                    max_residue_trials=MAX_RESIDUE_TRIALS,
                    ideal_uniform_residue_abort_union_upper=f"{self.n * self.m}/2^{MAX_RESIDUE_TRIALS}",
                    root_genbasis_certified=False, instantiated_random_oracle_proved=False,
                    security_claim="none", backend_admitted=False)
