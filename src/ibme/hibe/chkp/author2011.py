"""Versioned two-depth CHKP author-manuscript service.

The existing CHKP backend implements the depth-two leaf path.  This service
adds the depth-one decryption vector and fixed-length anonymous KEM preamble
without changing any v1 object or its persistent issuance state.  MP12 root
generation is an explicitly documented GenBasis implementation choice.  The
2011 manuscript's theorem/proof dimension mismatch is not resolved here.
"""

from dataclasses import dataclass, field
from hmac import compare_digest
from threading import RLock

from ibme.core.encoding import encode_bytes
from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.core.types import validate_identity
from ibme.lattice.chkp.identity import Reader
from ibme.lattice.chkp.leaf_state import _read_signed, _signed

from .backend import CHKPHIBE, _noise, _options, _source
from .objects import (CHKPPublicKey, CHKPMasterSecret, CHKPLevel1SecretKey,
                      CHKPLevel2SecretKey, CHKPCiphertext,
                      MAX_OBJECT_BYTES as BASE_MAX_OBJECT_BYTES)
from .params import research_params


VERSION = "chkp-author2011-3m-v1"
MAGIC = b"IBME:CHKP:AUTHOR2011-3M:OBJECT:v1"
MAX_OBJECT_BYTES = 64 * 2**20
MAX_PUBLIC_BYTES = 2 * 2**20
HYBRID_COMPONENT_BYTES = MAX_OBJECT_BYTES


def _frame(kind, *values):
    raw = MAGIC + encode_bytes(kind) + b"".join(encode_bytes(value) for value in values)
    if len(raw) > MAX_OBJECT_BYTES:
        raise SerializationError("author2011 CHKP object exceeds the declared budget")
    return raw


def _reader(raw, kind):
    reader = Reader(raw, maximum=MAX_OBJECT_BYTES)
    if reader.take(len(MAGIC)) != MAGIC or reader.blob(32) != kind:
        raise SerializationError("unknown author2011 CHKP object type or version")
    return reader


def _dump_preimages(preimages, dimension):
    if (not isinstance(preimages, tuple) or len(preimages) != 256
            or any(not isinstance(v, tuple) or len(v) != dimension for v in preimages)):
        raise InvalidParameterError("author2011 level-one vector shape")
    raw = dimension.to_bytes(4, "big") + b"".join(_signed(x) for v in preimages for x in v)
    if len(raw) > MAX_OBJECT_BYTES:
        raise SerializationError("author2011 level-one vectors exceed the private wire budget")
    return raw


def _load_preimages(raw, dimension):
    reader = Reader(raw, maximum=MAX_OBJECT_BYTES)
    if reader.number() != dimension:
        raise SerializationError("author2011 level-one vector dimension mismatch")
    vectors = tuple(tuple(_read_signed(reader) for _ in range(dimension)) for _ in range(256))
    reader.finish()
    if _dump_preimages(vectors, dimension) != bytes(raw):
        raise SerializationError("noncanonical author2011 level-one vectors")
    return vectors


@dataclass(frozen=True)
class Author2011PublicKey:
    base: CHKPPublicKey

    security_claim = "none"
    backend_admitted = False
    parameters_are_formal = False

    def __post_init__(self):
        if not isinstance(self.base, CHKPPublicKey):
            raise InvalidParameterError("validated CHKP public root required")

    @property
    def params(self): return self.base.params

    @property
    def oracle(self): return self.base.oracle

    @property
    def context(self): return self.base.context

    def to_bytes(self): return _frame(b"PUBLIC", self.base.to_bytes())

    @classmethod
    def from_bytes(cls, raw):
        reader = _reader(raw, b"PUBLIC")
        base = CHKPPublicKey.from_bytes(reader.blob(MAX_PUBLIC_BYTES))
        reader.finish()
        result = cls(base)
        if result.to_bytes() != bytes(raw):
            raise SerializationError("noncanonical author2011 CHKP public key")
        return result


@dataclass(frozen=True, repr=False)
class Author2011Level1Key:
    public_key: Author2011PublicKey
    base: CHKPLevel1SecretKey = field(repr=False)
    preimages: object = field(repr=False)

    hybrid_component_max_bytes = HYBRID_COMPONENT_BYTES

    def __post_init__(self):
        from ibme.lattice.chkp.level1_kem import Level1Preimages, validate_level1_preimages

        if (not isinstance(self.public_key, Author2011PublicKey)
                or not isinstance(self.base, CHKPLevel1SecretKey)
                or not compare_digest(self.public_key.base.to_bytes(), self.base.public_key.to_bytes())):
            raise InvalidParameterError("author2011 first-level public/parent binding")
        if not isinstance(self.preimages, Level1Preimages):
            raise InvalidParameterError("validated author2011 first-level preimages required")
        checked = validate_level1_preimages(self.public_key.oracle, self.base.identity,
                                            self.preimages.preimages, self.params.parent_width_squared)
        if checked != self.preimages:
            raise InvalidParameterError("author2011 first-level preimage scope mismatch")

    @property
    def params(self): return self.public_key.params

    @property
    def identity(self): return self.base.identity

    def __repr__(self): return "Author2011Level1Key(RESEARCH, private state hidden)"

    def to_bytes(self):
        return _frame(b"LEVEL1", self.public_key.to_bytes(), self.base.to_bytes(),
                      _dump_preimages(self.preimages.preimages, 2*self.params.m))

    @classmethod
    def from_bytes(cls, raw):
        from ibme.lattice.chkp.level1_kem import validate_level1_preimages

        reader = _reader(raw, b"LEVEL1")
        public = Author2011PublicKey.from_bytes(reader.blob(MAX_PUBLIC_BYTES))
        base = CHKPLevel1SecretKey.from_bytes(reader.blob(MAX_OBJECT_BYTES))
        vectors = _load_preimages(reader.blob(MAX_OBJECT_BYTES), 2*public.params.m)
        reader.finish()
        key = validate_level1_preimages(public.oracle, base.identity, vectors,
                                        public.params.parent_width_squared)
        result = cls(public, base, key)
        if result.to_bytes() != bytes(raw):
            raise SerializationError("noncanonical author2011 first-level key")
        return result


class Author2011MasterSecret:
    """One owner for the old CHKP tree and all first-level decryption vectors."""

    hybrid_component_max_bytes = HYBRID_COMPONENT_BYTES

    def __init__(self, public_key, base):
        if (not isinstance(public_key, Author2011PublicKey)
                or not isinstance(base, CHKPMasterSecret)
                or not compare_digest(public_key.base.to_bytes(), base.public_key.to_bytes())):
            raise InvalidParameterError("author2011 master/public binding")
        self.public_key, self.base = public_key, base
        self._entries, self._lock = {}, RLock()

    @property
    def params(self): return self.public_key.params

    def __repr__(self): return "Author2011MasterSecret(RESEARCH, private state hidden)"

    def _result(self, identity):
        return Author2011Level1Key(self.public_key,
            CHKPLevel1SecretKey(self.public_key.base, self.base.state.lookup(identity)),
            self._entries[identity])

    def lookup(self, identity):
        identity = validate_identity(identity, max_bytes=self.params.identity_bytes)
        with self._lock:
            if identity not in self._entries:
                raise KeyError("first-level address not yet issued")
            if self._entries[identity] is None:
                raise InvalidParameterError("first-level address failed or pending; no reissue")
            return self._result(identity)

    def issue(self, identity, generate):
        identity = validate_identity(identity, max_bytes=self.params.identity_bytes)
        with self._lock:
            if identity in self._entries:
                return self.lookup(identity)
            if len(self._entries) >= self.params.max_receivers:
                raise InvalidParameterError("author2011 first-level address capacity exhausted")
            # Reserve the worst canonical signed encoding for all 256 new
            # vectors before the first private byte. The nested CHKP master
            # has its own 16 MiB bound and may grow while issuing this parent.
            # Include that entire bound rather than the current base length.
            outer_overhead = len(self.to_bytes()) - len(self.base.to_bytes())
            vector_bound = 4 + 256*(2*self.params.m)*37
            entry_bound = 4 + len(identity) + 1 + 4 + vector_bound + 256
            if BASE_MAX_OBJECT_BYTES + outer_overhead + entry_bound > MAX_OBJECT_BYTES:
                raise InvalidParameterError("author2011 first-level snapshot capacity exhausted")
            self._entries[identity] = None
            key = generate()
            self._entries[identity] = key
            try:
                result = self._result(identity)
                self.to_bytes()
            except Exception:
                self._entries[identity] = None
                raise
            return result

    def to_bytes(self):
        with self._lock:
            # The old tree may already hold a parent if the new preimage phase
            # failed.  The outer failed entry prevents a second sampling attempt.
            if not set(self.base.state._entries).issubset(self._entries):
                raise SerializationError("author2011 master omits an occupied base address")
            chunks = [len(self._entries).to_bytes(4, "big")]
            for identity, key in sorted(self._entries.items()):
                chunks += [encode_bytes(identity), bytes([int(key is not None)])]
                if key is not None:
                    self.base.state.lookup(identity)
                    chunks.append(encode_bytes(_dump_preimages(key.preimages, 2*self.params.m)))
            return _frame(b"MASTER", self.public_key.to_bytes(), self.base.to_bytes(), b"".join(chunks))

    @classmethod
    def from_bytes(cls, raw):
        from ibme.lattice.chkp.level1_kem import validate_level1_preimages

        reader = _reader(raw, b"MASTER")
        public = Author2011PublicKey.from_bytes(reader.blob(MAX_PUBLIC_BYTES))
        base = CHKPMasterSecret.from_bytes(reader.blob(MAX_OBJECT_BYTES))
        entries = Reader(reader.blob(MAX_OBJECT_BYTES), maximum=MAX_OBJECT_BYTES)
        reader.finish()
        result = cls(public, base)
        count, previous = entries.number(), None
        if count > public.params.max_receivers:
            raise SerializationError("author2011 first-level address count exceeds capacity")
        for _ in range(count):
            identity = validate_identity(entries.blob(public.params.identity_bytes),
                                         max_bytes=public.params.identity_bytes)
            if previous is not None and identity <= previous:
                raise SerializationError("duplicate or unordered author2011 identity")
            status = entries.number(1)
            if status not in (0, 1):
                raise SerializationError("invalid author2011 address status")
            key = None
            if status:
                try:
                    base.state.lookup(identity)
                except (KeyError, InvalidParameterError) as exc:
                    raise SerializationError(
                        "author2011 ready address lacks a ready parent basis") from exc
                vectors = _load_preimages(entries.blob(MAX_OBJECT_BYTES), 2*public.params.m)
                key = validate_level1_preimages(public.oracle, identity, vectors,
                                                public.params.parent_width_squared)
            result._entries[identity], previous = key, identity
        entries.finish()
        if result.to_bytes() != bytes(raw):
            raise SerializationError("noncanonical author2011 master state")
        return result


@dataclass(frozen=True, repr=False)
class Author2011Level2Key:
    public_key: Author2011PublicKey
    base: CHKPLevel2SecretKey = field(repr=False)

    def __post_init__(self):
        if (not isinstance(self.public_key, Author2011PublicKey)
                or not isinstance(self.base, CHKPLevel2SecretKey)
                or not compare_digest(self.public_key.base.to_bytes(), self.base.public_key.to_bytes())):
            raise InvalidParameterError("author2011 leaf/public binding")

    @property
    def params(self): return self.public_key.params

    @property
    def parent_identity(self): return self.base.parent_identity

    @property
    def child_identity(self): return self.base.child_identity

    def __repr__(self): return "Author2011Level2Key(RESEARCH, private preimages hidden)"

    def to_bytes(self): return _frame(b"LEVEL2", self.public_key.to_bytes(), self.base.to_bytes())

    @classmethod
    def from_bytes(cls, raw):
        reader = _reader(raw, b"LEVEL2")
        public = Author2011PublicKey.from_bytes(reader.blob(MAX_PUBLIC_BYTES))
        base = CHKPLevel2SecretKey.from_bytes(reader.blob(MAX_OBJECT_BYTES))
        reader.finish()
        result = cls(public, base)
        if result.to_bytes() != bytes(raw):
            raise SerializationError("noncanonical author2011 leaf key")
        return result


@dataclass(frozen=True, repr=False)
class Author2011Ciphertext:
    capsule: object = field(repr=False)

    def __post_init__(self):
        from ibme.lattice.chkp.seed_kem import SeedCapsule
        if not isinstance(self.capsule, SeedCapsule):
            raise InvalidParameterError("canonical CHKP seed capsule required")

    def to_bytes(self): return _frame(b"CIPHERTEXT", self.capsule.to_bytes())

    @classmethod
    def from_bytes(cls, raw):
        from ibme.lattice.chkp.seed_kem import SeedCapsule
        reader = _reader(raw, b"CIPHERTEXT")
        capsule = SeedCapsule.from_bytes(reader.blob(MAX_PUBLIC_BYTES))
        reader.finish()
        return cls(capsule)


class Author2011HIBE:
    """Full depth-one/depth-two functional author-manuscript 3m route."""

    security_claim = "none"
    backend_admitted = False
    parameters_are_formal = False

    def setup(self, params, *, rng=None):
        base_public, base_master = CHKPHIBE().setup(params, rng=rng)
        public = Author2011PublicKey(base_public)
        return public, Author2011MasterSecret(public, base_master)

    def extract(self, master, parent_id, *, rng=None):
        if not isinstance(master, Author2011MasterSecret):
            raise TypeError("author2011 master secret required")
        receiver = validate_identity(parent_id, max_bytes=master.params.identity_bytes)
        try:
            return master.lookup(receiver)
        except KeyError:
            pass
        source = _source(rng)

        def generate():
            from ibme.lattice.chkp.level1_kem import (sample_level1_preimages,
                                                       validate_level1_preimages)
            CHKPHIBE().extract(master.base, receiver, rng=source)
            vectors = sample_level1_preimages(master.base.state.root_basis_for_research(),
                master.public_key.oracle, receiver, master.params.parent_width_squared,
                epsilon_bits=master.params.epsilon_bits, options=_options(master.params),
                entropy_budget=master.params.leaf_entropy_budget, rng=source)
            return validate_level1_preimages(master.public_key.oracle, receiver,
                                             vectors, master.params.parent_width_squared)

        return master.issue(receiver, generate)

    def derive(self, parent, child_id, *, rng=None):
        if not isinstance(parent, Author2011Level1Key):
            raise TypeError("author2011 first-level key required")
        child = CHKPHIBE().derive(parent.base, child_id, rng=rng)
        return Author2011Level2Key(parent.public_key, child)

    def encrypt(self, public, parent_id, child_id, payload, *, rng=None):
        if not isinstance(public, Author2011PublicKey):
            raise TypeError("author2011 public key required")
        return Author2011Ciphertext(CHKPHIBE().encrypt(public.base, parent_id,
                                                       child_id, payload, rng=rng).capsule)

    def decrypt(self, child, ciphertext, *, rng=None):
        if not isinstance(child, Author2011Level2Key) or not isinstance(ciphertext, Author2011Ciphertext):
            raise TypeError("author2011 leaf key and ciphertext required")
        return CHKPHIBE().decrypt(child.base, CHKPCiphertext(ciphertext.capsule), rng=rng)

    def encrypt_level1(self, public, parent_id, seed, *, rng=None):
        if not isinstance(public, Author2011PublicKey):
            raise TypeError("author2011 public key required")
        if public.params.message_mode != "seed32":
            raise InvalidParameterError("author2011 first-level KEM requires seed32 profile")
        from ibme.lattice.chkp.level1_kem import encapsulate_level1
        return Author2011Ciphertext(encapsulate_level1(public.oracle, parent_id,
            seed, _noise(public.params), rng=rng))

    def decrypt_level1(self, parent, ciphertext):
        if not isinstance(parent, Author2011Level1Key) or not isinstance(ciphertext, Author2011Ciphertext):
            raise TypeError("author2011 first-level key and ciphertext required")
        from ibme.lattice.chkp.level1_kem import decapsulate_level1
        return decapsulate_level1(parent.public_key.oracle, parent.identity,
                                  parent.preimages, ciphertext.capsule)

    def load_ciphertext(self, raw): return Author2011Ciphertext.from_bytes(raw)

    def validate_key_binding(self, public, secret):
        return bool(isinstance(public, Author2011PublicKey)
                    and isinstance(secret, (Author2011MasterSecret, Author2011Level1Key,
                                            Author2011Level2Key))
                    and compare_digest(public.to_bytes(), secret.public_key.to_bytes()))


def check_object(value, params):
    if (not isinstance(value, (Author2011PublicKey, Author2011MasterSecret,
                               Author2011Level1Key, Author2011Level2Key))
            or value.params != params):
        raise SerializationError("author2011 CHKP object differs from selected parameters")


def ciphertext_size(params, payload_bytes, identity_bytes=None):
    from .params import ciphertext_size as base_size
    capsule = base_size(params, payload_bytes, identity_bytes)
    return len(MAGIC) + 4 + len(b"CIPHERTEXT") + 4 + capsule


def author2011_research_params():
    return research_params(message_mode="seed32")
