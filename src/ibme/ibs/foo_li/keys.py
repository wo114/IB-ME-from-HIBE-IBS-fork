"""Independent signing keys and locked, serializable fixed-identity issuance."""
from dataclasses import dataclass, field
import threading

from ibme.core.errors import EncodingError, SerializationError
from ibme.core.hashing import hash_identity
from ibme.core.types import validate_identity
from ibme.ibs.api import IBSMasterSecret, IBSSigningKey
from . import codec
from .objects import PublicKey
from .params import preflight
from .state_validation import validate_snapshot


@dataclass(frozen=True, eq=False, repr=False)
class SigningKey(IBSSigningKey):
    public_key: PublicKey
    _identity: bytes
    bit: int
    trapdoor: tuple = field(repr=False)
    seed: bytes = field(repr=False)
    _sampler: object = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        if type(self.public_key) is not PublicKey:
            raise SerializationError("invalid Foo-Li signing public key")
        p = self.params
        try:
            identity = validate_identity(self._identity, max_bytes=p.identity_max_bytes)
        except EncodingError as exc:
            raise SerializationError("invalid Foo-Li signing identity") from exc
        object.__setattr__(self, "_identity", identity)
        if type(self.bit) is not int or self.bit not in (0, 1):
            raise SerializationError("invalid Foo-Li signing branch")
        if type(self.seed) is not bytes or len(self.seed) != 32:
            raise SerializationError("Foo-Li user seed must have 32 bytes")
        if (type(self.trapdoor) is not tuple or len(self.trapdoor) != p.m*p.w
                or any(type(x) is not int for x in self.trapdoor)
                or sum(x*x for x in self.trapdoor) > p.user_quality):
            raise SerializationError("Foo-Li user trapdoor shape/quality mismatch")
        from sage.all import ZZ, matrix
        from experiments.research.online_mp12_reference import sampler_for_quality
        from experiments.research.gaussian_reference import SamplingAbort
        try:
            preflight(p)
            c, v = p.research_config(), self.public_key._verifier
            profile, sampler = sampler_for_quality(c.q, v.public,
                matrix(ZZ, p.m, p.w, self.trapdoor), c.user_quality,
                r_squared=c.user_r_squared, gamma=c.gamma, options=c.options)
            if profile["status"] != "admitted" or sampler.public_matrix() != v.public.augment(v.identity_matrix(identity, self.bit)):
                raise ValueError("Foo-Li signing trapdoor equation mismatch")
        except (ValueError, SamplingAbort) as exc:
            raise SerializationError("Foo-Li signing key fails sampling/equation checks") from exc
        object.__setattr__(self, "_sampler", sampler)

    @property
    def params(self): return self.public_key.params

    @property
    def identity(self): return self._identity

    @property
    def identity_digest(self): return hash_identity(self.identity, 32)

    def to_bytes(self):
        return codec.encode(codec.SK_MAGIC, self.public_key.to_bytes(), self.identity,
                            bytes([self.bit]), codec.pack_ints(self.trapdoor, signed=True), self.seed)

    @classmethod
    def from_bytes(cls, data):
        public, identity, bit, trapdoor, seed = codec.decode(data, codec.SK_MAGIC, 5)
        pk = PublicKey.from_bytes(public)
        if len(bit) != 1:
            raise SerializationError("invalid Foo-Li signing branch field")
        return cls(pk, identity, bit[0], codec.unpack_ints(trapdoor, pk.params.m*pk.params.w, signed=True), seed)

    def __repr__(self): return "FooLiSigningKey(<private identity state>)"


class MasterSecret(IBSMasterSecret):
    """In-memory lock plus persist-before-release callback; snapshots are plaintext."""
    __hash__ = None

    def __init__(self, params, session, *, persist_callback=None):
        from experiments.research.foo_li_runtime_reference import ResearchSession
        if type(session) is not ResearchSession or session.config != params.research_config():
            raise SerializationError("Foo-Li master configuration mismatch")
        self.public_key = PublicKey(params, session.epoch, tuple(int(x) for x in session.generated.public.list()))
        self._session = session
        self._states = {i: "issued" for i in session.users}
        self._states.update({i: "failed" for i in session.failures})
        self._keys = {}
        self._lock = threading.RLock()
        self.persist_callback = persist_callback

    @property
    def params(self): return self.public_key.params

    def _issued_key(self, identity):
        if identity not in self._keys:
            user = self._session.users[identity]
            self._keys[identity] = SigningKey(self.public_key, identity, user.bit,
                                             tuple(int(x) for x in user.trapdoor.list()), user.seed)
        return self._keys[identity]

    def to_bytes(self):
        with self._lock:
            states = [[i.hex(), status] for i, status in sorted(self._states.items())]
            return codec.encode(codec.MSK_MAGIC, self.public_key.to_bytes(),
                                self._session.dump_secret_state(), codec.canonical(states))

    @classmethod
    def from_bytes(cls, data):
        from experiments.research.foo_li_runtime_reference import ResearchSession
        from experiments.research.gaussian_reference import SamplingAbort
        public, secret, encoded_states = codec.decode(data, codec.MSK_MAGIC, 3)
        pk = PublicKey.from_bytes(public)
        try:
            checked = validate_snapshot(pk, secret, encoded_states)
            preflight(pk.params)
            session = ResearchSession.restore(secret)
            result = cls(pk.params, session)
            if result.public_key != pk:
                raise ValueError("master public context mismatch")
            result._states = checked
            if result.to_bytes() != codec.bounded_bytes(data):
                raise ValueError("noncanonical master snapshot")
            return result
        except (ValueError, TypeError, KeyError, EncodingError, SamplingAbort) as exc:
            raise SerializationError("invalid Foo-Li master snapshot") from exc

    def __repr__(self): return "FooLiMasterSecret(<private fixed-issuance state>)"
