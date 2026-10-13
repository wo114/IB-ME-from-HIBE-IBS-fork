"""Yu--Liu--Li 2026 Figure 5: independent, bounded research implementation.

Real AP09/CHKP/GPV lattice operations and key-input BPR NAND circuits.
Fixed-length bit strings follow the paper directly; no hash-to-identity,
shared IBS interface, ROM, or full IB-ME adapter is introduced.
"""

from dataclasses import dataclass, field
from typing import ClassVar

from ibme.core.randomness import SecureRandom
from experiments.research.chkp_basis import KernelBasis, ModMatrixReference
from experiments.research.chkp_genbasis import AP09Parameters
from experiments.research.gaussian_reference import SamplingAbort, draw_uniform_integer

from . import bpr
from .evaluation import EvalParams, bits, integer, matrix, join, eval_public, equality_circuit
from .trapdoors import generate_root, issue_basis, sample_zero

SIGNATURE_MAGIC = b"IBME/YU2026/F5/SIG/1\x00"
MAX_SIGNATURE_BYTES = 8192


@dataclass(frozen=True)
class Params:
    root: AP09Parameters
    identity_prf: object
    signing_prf: object
    message_bits: int
    salt_bits: int
    gamma_squared: int
    delta_squared: int
    max_vectors: int = 80
    epsilon_bits: int = 16
    postprocess: bool = True
    security_claim: ClassVar[str] = "none"
    backend_admitted: ClassVar[bool] = False
    parameters_are_formal: ClassVar[bool] = False

    def __post_init__(self):
        if not isinstance(self.root, AP09Parameters):
            raise ValueError("AP09 root configuration required")
        if not isinstance(self.identity_prf, bpr.BPRSpec) or not isinstance(self.signing_prf, bpr.BPRSpec):
            raise ValueError("certified finite BPR specifications required")
        integer(self.message_bits, 1, 64, "message bits")
        integer(self.salt_bits, 1, 64, "salt bits")
        if self.signing_prf.params.input_bits != self.identity_bits + self.message_bits + self.salt_bits:
            raise ValueError("tilde input must be identity || message || salt")
        for name in ("gamma_squared", "delta_squared"):
            integer(getattr(self, name), 1, 10**12, name)
        integer(self.max_vectors, self.evaluation.m + self.evaluation.w, 4096, "RandBasis vector budget")
        integer(self.epsilon_bits, 2, 128, "epsilon bits")
        if type(self.postprocess) is not bool:
            raise ValueError("postprocess must be a boolean")
        if self.signature_dimension > 192:
            raise ValueError("total signature dimension exceeds sampler budget")

    @property
    def identity_bits(self):
        return self.identity_prf.params.input_bits

    @property
    def evaluation(self):
        return EvalParams(self.root.n, self.root.m1 + self.root.m2, self.root.q)

    @property
    def signature_dimension(self):
        return self.evaluation.m + 2 * self.evaluation.w


@dataclass(frozen=True, repr=False)
class PublicKey:
    params: Params
    a: tuple
    hat: tuple
    tilde: tuple

    def __post_init__(self):
        if not isinstance(self.params, Params):
            raise ValueError("Params required")
        p = self.params.evaluation
        object.__setattr__(self, "a", matrix(self.a, p.n, p.m, p.q))
        for name, count in (("hat", self.params.identity_prf.params.key_bits),
                            ("tilde", self.params.signing_prf.params.key_bits)):
            value = getattr(self, name)
            if not isinstance(value, (tuple, list)) or len(value) != count:
                raise ValueError("public PRF block count mismatch")
            object.__setattr__(self, name, tuple(matrix(block, p.n, p.w, p.q) for block in value))

    def __repr__(self):
        return "YuPublicKey(matrices=<omitted>, security_claim='none')"


@dataclass(frozen=True, repr=False)
class MasterKey:
    public: PublicKey
    basis: KernelBasis = field(repr=False)

    def __post_init__(self):
        if not isinstance(self.public, PublicKey) or not isinstance(self.basis, KernelBasis):
            raise ValueError("validated public key and kernel basis required")
        if self.basis.public.rows != self.public.a or self.basis.public.q != self.public.params.root.q:
            raise ValueError("master basis does not belong to public key")

    def __repr__(self):
        return "YuMasterKey(trapdoor=<redacted>)"


@dataclass(frozen=True, repr=False)
class UserKey:
    public: PublicKey
    identity: tuple
    r_hat: tuple
    c_hat: tuple
    basis: KernelBasis = field(repr=False)

    def __post_init__(self):
        if not isinstance(self.public, PublicKey) or not isinstance(self.basis, KernelBasis):
            raise ValueError("validated public key and kernel basis required")
        p, e = self.public.params, self.public.params.evaluation
        object.__setattr__(self, "identity", bits(self.identity, p.identity_bits))
        object.__setattr__(self, "r_hat", bits(self.r_hat, p.identity_prf.params.output_bits))
        object.__setattr__(self, "c_hat", matrix(self.c_hat, e.n, e.w, e.q))
        if self.basis.public.q != e.q or self.basis.public.rows != join((self.public.a, self.c_hat)):
            raise ValueError("user basis does not belong to delegated public matrix")
        if self.c_hat != _evaluate_match(self.public, self.identity, self.r_hat, identity=True):
            raise ValueError("delegated block is not bound to this identity and r_hat")

    def __repr__(self):
        return "YuUserKey(identity=<omitted>, trapdoor=<redacted>)"


@dataclass(frozen=True, repr=False)
class Signature:
    s: tuple
    r_hat: tuple
    r_tilde: tuple
    salt: tuple

    def __post_init__(self):
        if not isinstance(self.s, (tuple, list)) or not 1 <= len(self.s) <= 192:
            raise ValueError("bounded signature vector required")
        object.__setattr__(self, "s", tuple(integer(x, -(1 << 127), (1 << 127)-1,
                                                   "signed signature coefficient") for x in self.s))
        for name in ("r_hat", "r_tilde", "salt"):
            value = getattr(self, name)
            if not isinstance(value, (tuple, list)) or not 1 <= len(value) <= 64:
                raise ValueError("bounded nonempty bit string required")
            object.__setattr__(self, name, bits(value, len(value)))

    def __repr__(self):
        return "YuSignature(material=<omitted>)"

    def _shape(self, params):
        if (not isinstance(params, Params) or not isinstance(self.s, (tuple, list))
                or len(self.s) != params.signature_dimension):
            raise ValueError("signature dimension mismatch")
        for value in self.s:
            integer(value, -(1 << 127), (1 << 127)-1, "signed signature coefficient")
        bits(self.r_hat, params.identity_prf.params.output_bits)
        bits(self.r_tilde, params.signing_prf.params.output_bits)
        bits(self.salt, params.salt_bits)

    def to_bytes(self, params):
        """Canonical length-prefixed encoding; signed ZZ vector stays signed."""
        self._shape(params)
        result = SIGNATURE_MAGIC + len(self.s).to_bytes(2, "big")
        result += b"".join(x.to_bytes(16, "big", signed=True) for x in self.s)
        for value in (self.r_hat, self.r_tilde, self.salt):
            result += len(value).to_bytes(2, "big") + bytes(value)
        return result

    @classmethod
    def from_bytes(cls, data, params):
        if not isinstance(params, Params) or not isinstance(data, bytes) or len(data) > MAX_SIGNATURE_BYTES:
            raise ValueError("bounded signature bytes and Params required")
        offset = 0

        def take(count):
            nonlocal offset
            if offset + count > len(data):
                raise ValueError("truncated signature")
            value = data[offset:offset+count]
            offset += count
            return value

        if take(len(SIGNATURE_MAGIC)) != SIGNATURE_MAGIC:
            raise ValueError("signature domain or version mismatch")
        if int.from_bytes(take(2), "big") != params.signature_dimension:
            raise ValueError("signature dimension mismatch")
        s = tuple(int.from_bytes(take(16), "big", signed=True) for _ in range(params.signature_dimension))
        values = []
        for count in (params.identity_prf.params.output_bits, params.signing_prf.params.output_bits, params.salt_bits):
            if int.from_bytes(take(2), "big") != count:
                raise ValueError("bit-string length mismatch")
            values.append(bits(tuple(take(count)), count))
        if offset != len(data):
            raise ValueError("trailing or duplicate signature data")
        result = cls(s, *values)
        if result.to_bytes(params) != data:
            raise ValueError("noncanonical signature")
        return result


class _CheckedRandom:
    """Check actual byte count before any shared random sampler sees a draw."""
    def __init__(self, source):
        self._source = source

    def read(self, count):
        data = self._source.read(count)
        size = data.nbytes if isinstance(data, memoryview) else len(data) if isinstance(data, (bytes, bytearray)) else -1
        if size != count:
            raise ValueError("invalid random source response")
        return bytes(data)


def _source(rng):
    rng = SecureRandom() if rng is None else rng
    if not callable(getattr(rng, "read", None)):
        raise ValueError("random source must implement read(n)")
    return rng if isinstance(rng, _CheckedRandom) else _CheckedRandom(rng)


def _random_bits(rng, count):
    size = (count + 7) // 8
    data = rng.read(size)
    received = data.nbytes if isinstance(data, memoryview) else len(data) if isinstance(data, (bytes, bytearray)) else -1
    if received != size:
        raise ValueError("invalid random source response")
    ticket = int.from_bytes(data, "big")
    return tuple((ticket >> i) & 1 for i in range(count))


def _evaluate_match(public, x, pattern, *, identity):
    spec = public.params.identity_prf if identity else public.params.signing_prf
    inputs = public.hat if identity else public.tilde
    x = bits(x, spec.params.input_bits)
    pattern = bits(pattern, spec.params.output_bits)
    circuit = bpr.compile_key_circuit(spec, x)
    outputs = eval_public(public.params.evaluation, circuit, public.a, inputs)
    return eval_public(public.params.evaluation, equality_circuit(pattern), public.a, outputs)[0]


def setup(params, *, rng=None):
    """Figure 5 Setup: independently uniform public matrices; no PRF secrets."""
    if not isinstance(params, Params):
        raise ValueError("Params required")
    rng, p = _source(rng), params.evaluation
    root = generate_root(params.root, rng=rng)

    def blocks(count):
        return tuple(tuple(tuple(draw_uniform_integer(rng, p.q) for _ in range(p.w))
                           for _ in range(p.n)) for _ in range(count))

    public = PublicKey(params, root.public.rows, blocks(params.identity_prf.params.key_bits),
                       blocks(params.signing_prf.params.key_bits))
    return public, MasterKey(public, root)


def keygen(master, identity, *, rng=None):
    """Raw KeyGen may issue fresh randomness; Authority below provides reuse."""
    if not isinstance(master, MasterKey):
        raise ValueError("MasterKey required")
    rng, public = _source(rng), master.public
    p = public.params
    identity = bits(identity, p.identity_bits)
    r_hat = _random_bits(rng, p.identity_prf.params.output_bits)
    c_hat = _evaluate_match(public, identity, r_hat, identity=True)
    delegated = issue_basis(master.basis, ModMatrixReference(c_hat, p.root.q), p.gamma_squared, p.max_vectors,
                            rng=rng, epsilon_bits=p.epsilon_bits, postprocess=p.postprocess)
    return UserKey(public, identity, r_hat, c_hat, delegated)


def sign(user, message, *, rng=None):
    if not isinstance(user, UserKey):
        raise ValueError("UserKey required")
    rng, p = _source(rng), user.public.params
    message = bits(message, p.message_bits)
    salt = _random_bits(rng, p.salt_bits)
    r_tilde = _random_bits(rng, p.signing_prf.params.output_bits)
    c_tilde = _evaluate_match(user.public, user.identity + message + salt, r_tilde, identity=False)
    s = sample_zero(user.basis, ModMatrixReference(c_tilde, p.root.q), p.delta_squared,
                    rng=rng, epsilon_bits=p.epsilon_bits)
    norm_squared = sum(x*x for x in s)
    if not 0 < norm_squared <= p.delta_squared * p.signature_dimension:
        raise SamplingAbort("zero or over-norm signature; this call aborts without retry")
    return Signature(s, user.r_hat, r_tilde, salt)


def verification_matrix(public, identity, message, signature):
    """Public-only matrix recomputation, also used by independent equation tests."""
    if not isinstance(public, PublicKey) or not isinstance(signature, Signature):
        raise ValueError("public key and signature required")
    p = public.params
    identity, message = bits(identity, p.identity_bits), bits(message, p.message_bits)
    signature._shape(p)
    hat = _evaluate_match(public, identity, signature.r_hat, identity=True)
    tilde = _evaluate_match(public, identity + message + signature.salt, signature.r_tilde, identity=False)
    return join((public.a, hat, tilde))


def verify(public, identity, message, signature):
    """Only Figure 5's exact norm and public zero-syndrome checks accept."""
    try:
        if not isinstance(public, PublicKey):
            return False
        p = public.params
        identity, message = bits(identity, p.identity_bits), bits(message, p.message_bits)
        if isinstance(signature, bytes):
            signature = Signature.from_bytes(signature, p)
        if not isinstance(signature, Signature):
            return False
        signature._shape(p)
        if not 0 < sum(x*x for x in signature.s) <= p.delta_squared * p.signature_dimension:
            return False
        rows = verification_matrix(public, identity, message, signature)
        return all(sum(x*y for x, y in zip(row, signature.s)) % p.root.q == 0 for row in rows)
    except (ValueError, TypeError, OverflowError):
        return False


class Authority:
    """Explicit fixed-key-per-identity wrapper; no hidden registry in Verify."""
    def __init__(self, master, *, rng=None):
        if not isinstance(master, MasterKey):
            raise ValueError("MasterKey required")
        self._master, self._rng, self._keys = master, _source(rng), {}

    def extract(self, identity):
        identity = bits(identity, self._master.public.params.identity_bits)
        if identity not in self._keys:
            self._keys[identity] = keygen(self._master, identity, rng=self._rng)
        return self._keys[identity]

    def sign(self, identity, message):
        message = bits(message, self._master.public.params.message_bits)
        return sign(self.extract(identity), message, rng=self._rng)

    def __repr__(self):
        return "YuAuthority(keys=<redacted>)"
