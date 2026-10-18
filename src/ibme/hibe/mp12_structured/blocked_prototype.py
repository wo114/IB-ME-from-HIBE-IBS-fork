"""Versioned 3m root/parent/256-target feasibility consumer, not a registered suite.

Uses the author-manuscript CHKP H/G dimensions and MP12 Algorithm 3/4.
Wide-q state is independent of the unchanged structured HIBE v1/v2 wire.
Private parent packets contain their own sampled R, never a master key.
This first consumer ends at the real fixed leaf; wide-q KEM/CLI integration
is intentionally a subsequent engineering step after resource measurements.
"""

from dataclasses import asdict, dataclass, field
from fractions import Fraction
from math import isqrt
import json
from typing import ClassVar

from ibme.core.encoding import encode_bytes
from ibme.core.hashing import shake256
from ibme.core.types import validate_identity
from ibme.lattice.chkp.identity import ROHIBEContext, Reader, DOMAIN_CONTEXT
from ibme.lattice.matrix_sampling.scalar import MatrixFiniteOptions, MatrixFiniteGaussian
from ibme.lattice.matrix_sampling.mp12_blocked import PackedTrapdoor, output_width, VERSION, RADIX_VERSION
from ibme.lattice.matrix_sampling.packed import PackedMatrix

MAGIC = b"IBME:MP12-BLOCKED-3M:OBJECT:v1\0"
CONTEXT_MAGIC = b"IBME:MP12-BLOCKED-3M:CONTEXT:v1\0"
RADIX_MAGIC = b"IBME:MP12-RADIX-BLOCKED-3M:OBJECT:v1\0"
RADIX_CONTEXT_MAGIC = b"IBME:MP12-RADIX-BLOCKED-3M:CONTEXT:v1\0"
MAX_OBJECT_BYTES = 512*2**20


def canonical(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii")


def read_record(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= 8192:
        raise ValueError("blocked metadata size")
    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result: raise ValueError("duplicate blocked metadata")
            result[k] = v
        return result
    def reject(value): raise ValueError("noninteger blocked metadata")
    def integer(value):
        if len(value) > 150: raise ValueError("blocked metadata integer budget")
        return int(value)
    result = json.loads(raw.decode("ascii"), object_pairs_hook=unique,
        parse_int=integer, parse_float=reject, parse_constant=reject)
    if canonical(result) != raw: raise ValueError("noncanonical blocked metadata")
    return result


@dataclass(frozen=True)
class PrototypeParams:
    version: ClassVar[str] = VERSION
    radix_bits: ClassVar[int] = 1
    n: int = 2
    q: int = 604462909807314587353111  # next prime above 2^79; 80 bits
    root_r_squared: int = 16
    identity_bytes: int = 86
    epsilon_bits: int = 192
    entropy_cap_bytes: int = 2**40

    def __post_init__(self):
        from ibme.lattice.matrix_sampling.prime_gadget import radix_geometry
        for name, low, high in (("n", 2, 4096), ("root_r_squared", 4*self.n, 2**80),
                ("identity_bytes", 1, 86), ("epsilon_bits", 192, 192),
                ("entropy_cap_bytes", 1, 2**48)):
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError("blocked parameter integer domain: "+name)
        radix_geometry(self.q, self.radix_bits)
        if self.parent_dimension*self.w > 2**24 or 256*3*self.m > 2**24 or 3*self.m > 8192:
            raise ValueError("blocked complete-chain entry budget")
        if self.leaf_width_squared > 2**192 or self.parent_bound >= 2**256:
            raise ValueError("blocked complete-chain scalar/norm domain")
        if not self.noise_budget()["conditional_noise_sufficient"]:
            raise ValueError("blocked complete 3m noise condition")

    @property
    def w(self): return self.n*(((self.q-1).bit_length()+self.radix_bits-1)//self.radix_bits)
    @property
    def m(self): return 2*self.n+self.w
    @property
    def root_bound(self): return 2*self.n*self.w*self.root_r_squared
    @property
    def parent_dimension(self): return 2*self.m-self.w
    @property
    def parent_width_squared(self): return output_width(self.w, self.root_bound, self.epsilon_bits, radix_bits=self.radix_bits)
    @property
    def parent_bound(self): return self.parent_dimension*self.w*self.parent_width_squared
    @property
    def leaf_width_squared(self): return output_width(self.w, self.parent_bound, self.epsilon_bits, radix_bits=self.radix_bits)
    @property
    def q_alpha(self): return max(4, isqrt(4*self.n)+1)

    def options(self):
        return MatrixFiniteOptions(tail_bits=192, gaussian_abort_bits=192,
            mass_bits=320, precision_bits=384, max_uniform_trials=256)

    def noise_budget(self):
        # Same exact sufficient rounding/Chernoff inequality as the existing
        # joint_parameters.evaluate_noise, extended to this explicit big-q
        # consumer. This is a condition only: no encryption is inferred.
        dimension, width = 3*self.m, self.leaf_width_squared
        l1 = isqrt(dimension*dimension*width)
        l1 += int(l1*l1 < dimension*dimension*width)
        rounding = Fraction(l1+1, 2)
        margin = (self.q//2-1)//2-rounding
        continuous = self.q_alpha**2*(dimension*width+1)*161
        return dict(dimension=dimension, q=str(self.q), q_alpha=self.q_alpha, decode_error_bits=160,
            conditional_noise_sufficient=bool(margin > 0 and continuous <= margin*margin),
            assumes_leaf_norm_bound=True, actual_encryption_executed=False)

    def record(self):
        return dict(version=self.version, parameters=asdict(self), w=self.w, m=self.m,
            leaf_dimension=3*self.m, parent_R_rows=self.parent_dimension,
            root_bound=str(self.root_bound), parent_bound=str(self.parent_bound),
            parent_width_squared=str(self.parent_width_squared), leaf_width_squared=str(self.leaf_width_squared),
            finite_options=asdict(self.options()), full_H_columns=self.m,
            q_alpha=self.q_alpha, oracle_max_residue_trials=128,
            security_claim="none", backend_admitted=False, parameters_are_formal=False)


@dataclass(frozen=True)
class RadixPrototypeParams(PrototypeParams):
    """Separate opt-in wire/profile; binary parameters retain their old bytes."""

    version: ClassVar[str] = RADIX_VERSION
    radix_bits: int = field(default=12, kw_only=True)

    def __post_init__(self):
        if type(self.radix_bits) is not int or not 2 <= self.radix_bits <= 32:
            raise ValueError("radix prototype requires explicit radix bits 2..32")
        super().__post_init__()


@dataclass(frozen=True)
class PrototypeContext(ROHIBEContext):
    """The existing H/G address algorithms with a new canonical big-q context."""

    params_type: ClassVar[type] = PrototypeParams
    context_magic: ClassVar[bytes] = CONTEXT_MAGIC
    key_magic: ClassVar[bytes] = MAGIC

    def __post_init__(self):
        record = read_record(self.public_configuration)
        p = self.params_type(**record["parameters"])
        if (canonical(p.record()) != self.public_configuration or
                (self.n, self.m, self.q, self.identity_bytes) != (p.n, p.m, p.q, p.identity_bytes)):
            raise ValueError("blocked public parameter context")
        public = PackedMatrix.from_rows(self.root_rows, self.q-1, False)
        if (public.nrows, public.ncols) != (p.n, p.m): raise ValueError("blocked public dimensions")
        if any(self.root_rows[i][j] != int(i == j) for i in range(p.n) for j in range(p.n)):
            raise ValueError("blocked root leading identity")
        object.__setattr__(self, "root_rows", public.rows())
        object.__setattr__(self, "params", p)
        object.__setattr__(self, "context", shake256(DOMAIN_CONTEXT, self.to_bytes(), 64))

    def to_bytes(self):
        return (self.context_magic+encode_bytes(self.public_configuration)
                +encode_bytes(PackedMatrix.from_rows(self.root_rows, self.q-1, False).to_bytes()))

    @classmethod
    def create(cls, params, public):
        if type(params) is not cls.params_type or (public.nrows, public.ncols) != (params.n, params.m):
            raise ValueError("blocked public root shape")
        # The dataclass constructor runs the validating __post_init__ below.
        return cls(params.n, params.m, params.q, public.rows(), canonical(params.record()), params.identity_bytes)

    @classmethod
    def from_bytes(cls, raw):
        r = Reader(raw, maximum=MAX_OBJECT_BYTES)
        if r.take(len(cls.context_magic)) != cls.context_magic: raise ValueError("blocked context version")
        config = r.blob(8192)
        record = read_record(config)
        p = cls.params_type(**record["parameters"])
        if canonical(p.record()) != config: raise ValueError("blocked parameter snapshot mismatch")
        public = PackedMatrix.from_bytes(r.blob(MAX_OBJECT_BYTES))
        r.finish()
        result = cls.create(p, public)
        if result.to_bytes() != raw: raise ValueError("blocked context noncanonical")
        return result


@dataclass(frozen=True)
class RadixPrototypeContext(PrototypeContext):
    params_type: ClassVar[type] = RadixPrototypeParams
    context_magic: ClassVar[bytes] = RADIX_CONTEXT_MAGIC
    key_magic: ClassVar[bytes] = RADIX_MAGIC


def _metadata(context, kind, receiver=b"", sender=b""):
    if kind not in ("root", "parent", "leaf"): raise ValueError("blocked key kind")
    if kind != "root": validate_identity(receiver, max_bytes=context.identity_bytes)
    elif receiver or sender: raise ValueError("root identity fields")
    if kind == "leaf": validate_identity(sender, max_bytes=context.identity_bytes)
    elif sender: raise ValueError("non-leaf sender field")
    return dict(version=context.params.version, context=context.context.hex(), kind=kind,
                receiver=receiver.hex(), sender=sender.hex())


def _frame(metadata, *matrices, magic=MAGIC):
    raw = magic+encode_bytes(canonical(metadata))+b"".join(encode_bytes(p.to_bytes()) for p in matrices)
    if len(raw) > MAX_OBJECT_BYTES: raise ValueError("blocked key object byte budget")
    return raw


def dump_trapdoor(context, trapdoor, receiver=b""):
    kind = "parent" if receiver else "root"
    if trapdoor.radix_bits != context.params.radix_bits:
        raise ValueError("blocked key/context radix mismatch")
    return _frame(_metadata(context, kind, receiver), trapdoor.public, trapdoor.r, magic=context.key_magic)


def load_trapdoor(raw, context, receiver=b"", **packing):
    kind = "parent" if receiver else "root"
    r = Reader(raw, maximum=MAX_OBJECT_BYTES)
    if r.take(len(context.key_magic)) != context.key_magic: raise ValueError("blocked private key version")
    if read_record(r.blob(8192)) != _metadata(context, kind, receiver):
        raise ValueError("blocked private key scope")
    public = PackedMatrix.from_bytes(r.blob(MAX_OBJECT_BYTES), **packing)
    private = PackedMatrix.from_bytes(r.blob(MAX_OBJECT_BYTES), **packing)
    r.finish()
    p = context.params
    expected = context.parent_rows(receiver) if receiver else context.root_rows
    if public.rows() != expected: raise ValueError("blocked key public/identity binding")
    prefix = p.parent_dimension if receiver else 2*p.n
    if private.nrows != prefix: raise ValueError("blocked key prefix dimension")
    coordinate_bound = (isqrt(p.parent_dimension*p.parent_width_squared) if receiver else
        MatrixFiniteGaussian(p.root_r_squared, p.root_r_squared, options=p.options()).radius)
    if private.bound != coordinate_bound: raise ValueError("blocked canonical coordinate bound")
    return PackedTrapdoor(p.n, p.q, public, private,
        p.parent_bound if receiver else p.root_bound,
        column_norm_bound=p.parent_dimension*p.parent_width_squared if receiver else None, radix_bits=p.radix_bits)


def dump_leaf(context, receiver, sender, preimages):
    return _frame(_metadata(context, "leaf", receiver, sender), preimages, magic=context.key_magic)


def load_leaf(raw, context, receiver, sender, **packing):
    r = Reader(raw, maximum=MAX_OBJECT_BYTES)
    if r.take(len(context.key_magic)) != context.key_magic: raise ValueError("blocked leaf version")
    if read_record(r.blob(8192)) != _metadata(context, "leaf", receiver, sender):
        raise ValueError("blocked leaf scope")
    preimages = PackedMatrix.from_bytes(r.blob(MAX_OBJECT_BYTES), **packing)
    r.finish()
    p = context.params
    limit = 3*p.m*p.leaf_width_squared
    if ((preimages.nrows, preimages.ncols) != (3*p.m, 256) or not preimages.signed
            or preimages.bound != isqrt(limit)):
        raise ValueError("blocked fixed leaf dimension/bound")
    public = PackedMatrix.from_rows(context.leaf_rows(receiver, sender), p.q-1, False, **packing)
    for col, target in zip(preimages.columns(), context.targets(receiver, sender)):
        if sum(x*x for x in col) > limit or tuple(int(x) % p.q for x in public.multiply(col)) != target:
            raise ValueError("blocked fixed leaf norm/equation")
    return preimages
