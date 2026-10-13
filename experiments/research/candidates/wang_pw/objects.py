"""Strict objects, full public context and secret G-trapdoor relation checks."""
from dataclasses import dataclass, field
from hashlib import sha256

from ibme.core.errors import EncodingError, SerializationError
from ibme.core.hashing import hash_identity
from ibme.core.types import validate_identity
from ibme.ibs.api import IBSPublicKey, IBSMasterSecret, IBSSigningKey, IBSSignature

from .codec import blob, decode, encode, matrix_rows, unhex
from .params import Params


def gadget_entry(p, i, j):
    k = (p.q-1).bit_length()
    return (1 << (j % k)) % p.q if j//k == i else 0


def _restore(cls, kind, data, fields, convert):
    record = decode(kind, data, fields)
    try:
        result = cls(**convert(record))
        if result.to_bytes() != bytes(data): raise ValueError("noncanonical decoded coefficients")
        return result
    except (EncodingError, SerializationError, ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise SerializationError("invalid object relation, parameters or fields") from exc


@dataclass(frozen=True, eq=False)
class PublicKey(IBSPublicKey):
    params: Params
    a: tuple

    def __post_init__(self):
        if not isinstance(self.params, Params): raise ValueError("WangPW Params required")
        p = self.params
        object.__setattr__(self, "a", matrix_rows(self.a, p.n, p.m, q=p.q))
        # Full row rank is required even for a public-only imported key.
        work, pivot = [list(row) for row in self.a], 0
        for j in range(p.m):
            row = next((i for i in range(pivot, p.n) if work[i][j]), None)
            if row is None: continue
            work[pivot], work[row] = work[row], work[pivot]
            inv = pow(work[pivot][j], -1, p.q)
            work[pivot] = [x*inv % p.q for x in work[pivot]]
            for i in range(pivot+1, p.n):
                factor = work[i][j]
                work[i] = [(x-factor*y) % p.q for x, y in zip(work[i], work[pivot])]
            pivot += 1
            if pivot == p.n: break
        if pivot != p.n: raise ValueError("public matrix must have full row rank")

    @property
    def context(self): return sha256(self.to_bytes()).digest()

    def to_bytes(self): return encode("PK", {"params": self.params.record(), "a": self.a})

    @classmethod
    def from_bytes(cls, data):
        return _restore(cls, "PK", data, ("params", "a"),
                        lambda r: {"params": Params.from_record(r["params"]), "a": r["a"]})


@dataclass(frozen=True, eq=False)
class MasterSecret(IBSMasterSecret):
    public_key: PublicKey
    trapdoor: tuple = field(repr=False)

    def __post_init__(self):
        if not isinstance(self.public_key, PublicKey): raise ValueError("public key required")
        pk, p = self.public_key, self.public_key.params
        r = matrix_rows(self.trapdoor, p.m_bar, p.w)
        object.__setattr__(self, "trapdoor", r)
        if sum(x*x for row in r for x in row) > p.master_quality:
            raise ValueError("root quality class exceeded")
        for i in range(p.n):
            for j in range(p.w):
                value = pk.a[i][p.m_bar+j]+sum(pk.a[i][t]*r[t][j] for t in range(p.m_bar))
                if value % p.q != gadget_entry(p, i, j):
                    raise ValueError("root F[K;I]=G relation mismatch")

    def to_bytes(self): return encode("MSK", {"pk": self.public_key.to_bytes().hex(), "trapdoor": self.trapdoor})

    @classmethod
    def from_bytes(cls, data):
        return _restore(cls, "MSK", data, ("pk", "trapdoor"),
                        lambda r: {"public_key": PublicKey.from_bytes(unhex(r["pk"])), "trapdoor": r["trapdoor"]})


@dataclass(frozen=True, eq=False)
class SigningKey(IBSSigningKey):
    public_key: PublicKey
    _identity: bytes = field(repr=False)
    identity_salt: bytes = field(repr=False)
    trapdoor: tuple = field(repr=False)

    def __post_init__(self):
        if not isinstance(self.public_key, PublicKey): raise ValueError("public key required")
        p = self.public_key.params
        identity = validate_identity(self._identity)
        if len(identity) > p.identity_max_bytes: raise ValueError("identity capacity exceeded")
        object.__setattr__(self, "_identity", identity)
        blob(self.identity_salt, p.salt_bytes)
        r = matrix_rows(self.trapdoor, p.m, p.w)
        object.__setattr__(self, "trapdoor", r)
        if sum(x*x for row in r for x in row) > p.user_quality:
            raise ValueError("user quality class exceeded")
        from .hashing import identity_matrix, inner_identity
        b = identity_matrix(self.public_key, inner_identity(p, identity, self.identity_salt))
        for i in range(p.n):
            for j in range(p.w):
                value = b[i][j]+sum(self.public_key.a[i][t]*r[t][j] for t in range(p.m))
                if value % p.q != gadget_entry(p, i, j):
                    raise ValueError("identity/public-key G-trapdoor binding mismatch")

    @property
    def identity(self): return self._identity
    @property
    def identity_digest(self): return hash_identity(self._identity, 32)

    def to_bytes(self):
        return encode("SK", {"pk": self.public_key.to_bytes().hex(), "identity": self.identity.hex(),
                             "identity_salt": self.identity_salt.hex(), "trapdoor": self.trapdoor})

    @classmethod
    def from_bytes(cls, data):
        return _restore(cls, "SK", data, ("pk", "identity", "identity_salt", "trapdoor"),
                        lambda r: {"public_key": PublicKey.from_bytes(unhex(r["pk"])),
                                   "_identity": unhex(r["identity"]), "identity_salt": unhex(r["identity_salt"]),
                                   "trapdoor": r["trapdoor"]})


@dataclass(frozen=True, eq=False)
class Signature(IBSSignature):
    context: bytes
    identity_salt: bytes
    message_salt: bytes
    z: tuple

    def __post_init__(self):
        blob(self.context, 32)
        for salt in (self.identity_salt, self.message_salt):
            if type(salt) is not bytes or not 1 <= len(salt) <= 64: raise ValueError("invalid salt")
        if not isinstance(self.z, (tuple, list)) or not 1 <= len(self.z) <= 128:
            raise ValueError("bounded signature vector required")
        object.__setattr__(self, "z", matrix_rows((self.z,), 1, len(self.z))[0])

    def to_bytes(self):
        return encode("SIG", {"context": self.context.hex(), "identity_salt": self.identity_salt.hex(),
                              "message_salt": self.message_salt.hex(), "z": self.z})

    @classmethod
    def from_bytes(cls, data):
        return _restore(cls, "SIG", data, ("context", "identity_salt", "message_salt", "z"),
                        lambda r: {"context": unhex(r["context"]), "identity_salt": unhex(r["identity_salt"]),
                                   "message_salt": unhex(r["message_salt"]), "z": r["z"]})
