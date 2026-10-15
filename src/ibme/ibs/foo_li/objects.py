"""Immutable public key and signature, with full parameter/epoch binding."""
from dataclasses import dataclass, field
from hashlib import sha256

from ibme.core.errors import EncodingError, SerializationError
from ibme.core.types import validate_identity
from ibme.ibs.api import IBSPublicKey, IBSSignature
from . import codec
from .params import FooLiParams


@dataclass(frozen=True, eq=False, repr=False)
class PublicKey(IBSPublicKey):
    params: FooLiParams
    epoch: bytes
    coefficients: tuple
    _verifier: object = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        if type(self.params) is not FooLiParams:
            raise SerializationError("expected FooLiParams public context")
        try:
            epoch = validate_identity(self.epoch, max_bytes=256)
        except EncodingError as exc:
            raise SerializationError("invalid Foo-Li epoch") from exc
        object.__setattr__(self, "epoch", epoch)
        p = self.params
        if (type(self.coefficients) is not tuple or len(self.coefficients) != p.n*p.m
                or any(type(x) is not int or not 0 <= x < p.q for x in self.coefficients)):
            raise SerializationError("noncanonical Foo-Li public matrix")
        from sage.all import ZZ, matrix
        from experiments.research.foo_li_public_verifier import PublicVerifier
        verifier = PublicVerifier(p.research_config(), epoch,
                                  matrix(ZZ, p.n, p.m, self.coefficients))
        object.__setattr__(self, "_verifier", verifier)

    @property
    def context(self): return sha256(self._verifier.context).digest()

    def to_bytes(self):
        return codec.encode(codec.PK_MAGIC, codec.params_bytes(self.params), self.epoch,
                            codec.pack_ints(self.coefficients, signed=False))

    @classmethod
    def from_bytes(cls, data):
        config, epoch, coefficients = codec.decode(data, codec.PK_MAGIC, 3, limit=1024*1024)
        params = codec.parse_params(config)
        return cls(params, epoch, codec.unpack_ints(coefficients, params.n*params.m, signed=False))

    def __repr__(self): return "FooLiPublicKey(<public research context>)"


@dataclass(frozen=True, eq=False)
class Signature(IBSSignature):
    context: bytes
    vector: tuple
    bit: int

    def __post_init__(self):
        if type(self.context) is not bytes or len(self.context) != 32:
            raise SerializationError("invalid Foo-Li signature context")
        if type(self.bit) is not int or self.bit not in (0, 1):
            raise SerializationError("invalid Foo-Li signature branch")
        if type(self.vector) is not tuple or not 1 <= len(self.vector) <= 128:
            raise SerializationError("invalid Foo-Li vector shape")
        codec.pack_ints(self.vector, signed=True)

    @property
    def raw(self): return self.vector, self.bit

    def to_bytes(self):
        return codec.encode(codec.SIG_MAGIC, self.context, bytes([self.bit]),
                            codec.pack_ints(self.vector, signed=True))

    @classmethod
    def from_bytes(cls, data):
        context, bit, values = codec.decode(data, codec.SIG_MAGIC, 3, limit=2048)
        if len(bit) != 1 or len(values) % 8:
            raise SerializationError("invalid Foo-Li signature fields")
        return cls(context, codec.unpack_ints(values, len(values)//8, signed=True), bit[0])


def signature_shape(pk, signature):
    return (type(signature) is Signature and signature.context == pk.context
            and len(signature.vector) == pk.params.dimension
            and sum(x*x for x in signature.vector) <= pk.params.signature_bound_squared)
