"""Versioned Foo-Li research lifecycle on the actual online MP12 samplers.

NOT an IBSBackend, production keystore, constant-time implementation or ROM
instantiation theorem. Secret snapshots are plaintext and trusted-input only.
Raw signing does not reject zero/large vectors and never retries a failed band.
All five addresses bind the full public configuration, epoch and public matrix.
"""

from dataclasses import asdict, dataclass, field
import json

from sage.all import QQ, ZZ, identity_matrix, matrix, vector

from ibme.core.encoding import encode_bytes
from ibme.core.hashing import shake256
from ibme.core.randomness import SecureRandom
from ibme.core.types import validate_bytes, validate_identity
from .gaussian_reference import SamplingAbort, draw_uniform_integer
from .mp12_trapdoor_chain import GeneratedTrapdoor
from .online_gaussian_reference import OnlineOptions, exact_integer
from .online_mp12_reference import OnlineGaussianGenTrap, delegate_stream, sampler_for_quality
from .foo_li_initialization import check_initialized_state, initialization_budget


VERSION = "FooLi-online-research-v1"
DOMAINS = (b"select-bit", b"delegation-tape", b"identity-matrix",
           b"message-syndrome", b"signature-tape")


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def framed(*fields):
    return b"".join(encode_bytes(x) for x in fields)


class AddressStream:
    """Counter-block SHAKE candidate; chunk-invariant and explicitly finite.

    Blocks are 65536 bytes and numbered by u64be. This is a concrete candidate
    for the oracle tape, NOT information-theoretically uniform random bytes.
    No fallback to SecureRandom, and no seed/address in repr or audit output.
    """
    BLOCK = 65536

    def __init__(self, address, length):
        self.address = address
        self.remaining = exact_integer(length, "stream length", maximum=2**40)
        self.counter, self.buffer = 0, b""

    def read(self, size):
        size = exact_integer(size, "read size", maximum=256*1024*1024)
        if size > self.remaining:
            raise SamplingAbort("Address stream exhausted; no fallback")
        chunks, needed = [], size
        while needed:
            if not self.buffer:
                self.buffer = shake256(b"IBME:FooLi:stream:v1",
                    framed(self.address, self.counter.to_bytes(8, "big")), self.BLOCK)
                self.counter += 1
            take = min(needed, len(self.buffer))
            chunks.append(self.buffer[:take])
            self.buffer = self.buffer[take:]
            needed -= take
        self.remaining -= size
        return b"".join(chunks)


class ShakeOracleCandidate:
    def stream(self, domain, context, fields, length):
        if domain not in DOMAINS:
            raise ValueError("Unknown Foo-Li domain")
        return AddressStream(framed(VERSION.encode(), domain, context, *fields), length)


@dataclass(frozen=True)
class ResearchConfig:
    q: int = 3
    n: int = 1
    m_bar: int = 1
    master_quality: int = 8
    user_quality: int = 3402
    generation_width_squared: int = 1
    master_r_squared: int = 9
    user_r_squared: int = 9
    gamma: int = 5
    epsilon0: str = "1/65536"
    identity_max_bytes: int = 256
    message_max_bytes: int = 4096
    max_users: int = 16
    options: OnlineOptions = field(default_factory=OnlineOptions)

    def __post_init__(self):
        bounds = {"q": (2, 2**32), "n": (1, 128), "m_bar": (1, 128),
            "master_quality": (0, 10**12), "user_quality": (0, 10**12),
            "generation_width_squared": (1, 10**12), "master_r_squared": (1, 10**12),
            "user_r_squared": (1, 10**12), "gamma": (2, 128),
            "identity_max_bytes": (1, 4096), "message_max_bytes": (1, 1024*1024),
            "max_users": (1, 1024)}
        for name, (low, high) in bounds.items():
            object.__setattr__(self, name, exact_integer(getattr(self, name), name, minimum=low, maximum=high))
        if not isinstance(self.options, OnlineOptions) or not isinstance(self.epsilon0, str):
            raise ValueError("Need OnlineOptions and exact epsilon string")
        epsilon = QQ(self.epsilon0)
        if not 0 < epsilon <= QQ(1)/4 or str(epsilon) != self.epsilon0:
            raise ValueError("Noncanonical or invalid epsilon0")

    @property
    def w(self):
        return self.n*(self.q-1).bit_length()

    @property
    def m(self):
        return self.m_bar+self.w

    @property
    def s_squared(self):
        return self.master_r_squared*(self.gamma+2)*(self.master_quality+1)

    @property
    def t_squared(self):
        return self.user_r_squared*(self.gamma+2)*(self.user_quality+1)


@dataclass(frozen=True)
class Outcome:
    status: str
    value: object = field(default=None, repr=False)


@dataclass(frozen=True)
class UserState:
    identity: bytes
    bit: int
    trapdoor: object = field(repr=False)  # MP12 T; Foo-Li R_id = -T
    seed: bytes = field(repr=False)


def checked_read(rng, length):
    data = rng.read(length)
    if not isinstance(data, (bytes, bytearray, memoryview)) or len(data) != length:
        raise ValueError("Random source returned wrong byte type/length")
    return bytes(data)


def prepare(config):
    """Whole public class/resource preflight, BEFORE secret entropy is read."""
    if not isinstance(config, ResearchConfig):
        raise ValueError("Need ResearchConfig")
    c = config
    generator = OnlineGaussianGenTrap(c.q, c.n, c.m_bar, c.generation_width_squared, options=c.options)
    if c.user_quality < c.m*c.w*c.s_squared or c.t_squared < c.s_squared:
        raise ValueError("C3 quality or L4 width condition fails")
    # Zero is only a constructor probe. Widths and error bounds are those of the
    # FULL declared quality class, not of this easier zero trapdoor.
    _, master = sampler_for_quality(c.q, matrix(ZZ, c.n, c.m_bar), matrix(ZZ, c.m_bar, c.w),
        c.master_quality, r_squared=c.master_r_squared, gamma=c.gamma, options=c.options)
    _, user = sampler_for_quality(c.q, matrix(ZZ, c.n, c.m), matrix(ZZ, c.m, c.w),
        c.user_quality, r_squared=c.user_r_squared, gamma=c.gamma, options=c.options)
    budget = initialization_budget(generator, c.master_quality, c.s_squared, c.epsilon0)
    if budget["delta_init_upper"] is None:
        raise ValueError("Initialization C2 sufficient condition not certified")
    return generator, master, user, budget


class ResearchSession:
    """One master epoch, persistent per-identity seeds and no retry semantics.

    dump_secret_state/restore are an explicit research codec, not an encrypted
    or authenticated store. Caller owns durable I/O, access control and locking.
    This single-threaded reference must not be shared across concurrent issuers.
    """

    def __init__(self, config, epoch, generated, k1, k2, *, oracle=None):
        self.config = config
        self.generator, _, user_probe, self.init_budget = prepare(config)
        self.epoch = validate_identity(epoch, max_bytes=256)
        self.k1, self.k2 = self._seed(k1), self._seed(k2)
        self.init_state = check_initialized_state(self.generator, generated,
            config.master_quality, config.s_squared, config.epsilon0)
        if not self.init_state["InitGood_this_state"]:
            raise ValueError("Master state not InitGood")
        _, self.master = sampler_for_quality(config.q, generated.a_bar, generated.trapdoor,
            config.master_quality, r_squared=config.master_r_squared, gamma=config.gamma, options=config.options)
        # Own immutable copies; do not retain caller-owned mutable key matrices.
        owned_tag = identity_matrix(ZZ, config.n)
        owned_tag.set_immutable()
        self.generated = GeneratedTrapdoor(config.q, self.master.a_bar, self.master.public_matrix(),
            self.master.trapdoor, self.generator.gadget, owned_tag)
        self.user_tape_bytes = user_probe.random_tape_bytes
        self.context = framed(VERSION.encode(), canonical_json(asdict(config)), self.epoch,
            canonical_json([[int(x) for x in row] for row in generated.public.rows()]))
        self.oracle = ShakeOracleCandidate() if oracle is None else oracle
        self.users, self.failures = {}, {}

    @staticmethod
    def _seed(seed):
        seed = validate_bytes(seed)
        if len(seed) != 32:
            raise ValueError("Research seed must have 32 bytes (not a security claim)")
        return seed

    @classmethod
    def setup(cls, config, epoch, *, rng=None, oracle=None):
        generator, _, _, _ = prepare(config)
        epoch = validate_identity(epoch, max_bytes=256)
        rng = SecureRandom() if rng is None else rng
        tape = checked_read(rng, generator.random_tape_bytes)
        try:
            generated = generator.generate_from_tape(tape)
        except SamplingAbort:
            return Outcome("setup_sampling_abort")
        state = check_initialized_state(generator, generated,
            config.master_quality, config.s_squared, config.epsilon0)
        if not state["conditions"]["master_quality"]:
            return Outcome("setup_quality_rejected", state)
        if not state["InitGood_this_state"]:
            raise AssertionError("Generated state failed algebra/resource invariant")
        # Separate calls; no key derived from public identity, key or message.
        return Outcome("ok", cls(config, epoch, generated, checked_read(rng, 32),
            checked_read(rng, 32), oracle=oracle))

    def _identity(self, identity):
        return validate_identity(identity, max_bytes=self.config.identity_max_bytes)

    def _message(self, message):
        message = validate_bytes(message)
        if len(message) > self.config.message_max_bytes:
            raise ValueError("Message exceeds research limit")
        return message

    def _stream(self, domain, fields, length):
        return self.oracle.stream(domain, self.context, tuple(fields), length)

    def _modular_hash(self, domain, fields, count):
        c = self.config
        length = count*c.options.max_uniform_trials*(((c.q-1).bit_length()+7)//8)
        source = self._stream(domain, fields, length)
        return tuple(draw_uniform_integer(source, c.q, max_trials=c.options.max_uniform_trials) for _ in range(count))

    def identity_matrix(self, identity, bit):
        identity = self._identity(identity)
        bit = exact_integer(bit, "bit", maximum=1)
        c = self.config
        return matrix(ZZ, c.n, c.w, self._modular_hash(DOMAINS[2], (identity, bytes([bit])), c.n*c.w))

    def syndrome(self, identity, message):
        return self._modular_hash(DOMAINS[3], (self._identity(identity), self._message(message)), self.config.n)

    def extract(self, identity, *, seed_rng=None):
        identity = self._identity(identity)
        if identity in self.users:
            return Outcome("ok", self.users[identity])
        if identity in self.failures:
            return Outcome(self.failures[identity])
        if len(self.users)+len(self.failures) >= self.config.max_users:
            raise ValueError("Public research user-state limit reached")
        bit = checked_read(self._stream(DOMAINS[0], (self.k1, identity), 1), 1)[0] & 1
        try:
            extension = self.identity_matrix(identity, bit)
        except SamplingAbort:
            self.failures[identity] = "identity_hash_abort"
            return Outcome(self.failures[identity])
        try:
            delegated, _ = delegate_stream(self.master, extension,
                rng=self._stream(DOMAINS[1], (self.k2, identity), self.config.w*self.master.random_tape_bytes))
        except SamplingAbort:
            self.failures[identity] = "delegation_sampling_abort"
            return Outcome(self.failures[identity])
        if delegated.norm_squared > self.config.user_quality:
            self.failures[identity] = "user_quality_rejected"
            return Outcome(self.failures[identity])
        seed_rng = SecureRandom() if seed_rng is None else seed_rng
        user = UserState(identity, bit, delegated.trapdoor, checked_read(seed_rng, 32))
        self.users[identity] = user
        return Outcome("ok", user)

    def _user_sampler(self, user):
        extension = self.identity_matrix(user.identity, user.bit)
        c = self.config
        profile, sampler = sampler_for_quality(c.q, self.generated.public, user.trapdoor,
            c.user_quality, r_squared=c.user_r_squared, gamma=c.gamma, options=c.options)
        if profile["status"] != "admitted" or sampler.public_matrix() != self.generated.public.augment(extension):
            raise ValueError("User trapdoor quality or sign convention mismatch")
        if sampler.random_tape_bytes != self.user_tape_bytes:
            raise AssertionError("Public user tape length changed with secret state")
        return sampler

    def sign_raw(self, identity, message):
        identity, message = self._identity(identity), self._message(message)
        if identity not in self.users:
            raise ValueError("Identity has no persisted signing state")
        user = self.users[identity]
        try:
            syndrome = self.syndrome(identity, message)
            sampler = self._user_sampler(user)
        except SamplingAbort:
            return Outcome("public_hash_abort")
        tape = checked_read(self._stream(DOMAINS[4], (user.seed, identity, message), self.user_tape_bytes),
            self.user_tape_bytes)
        try:
            output = sampler.sample_from_tape(syndrome, tape)
        except SamplingAbort:
            return Outcome("signature_sampling_abort")
        # Keep the actual raw output; no norm/zero rejection or rerandomization.
        return Outcome("ok", (output, user.bit))

    def verify(self, identity, message, signature):
        identity, message = self._identity(identity), self._message(message)
        if not isinstance(signature, tuple) or len(signature) != 2:
            return False
        output, bit = signature
        if type(bit) is not int or bit not in (0, 1) or not isinstance(output, tuple):
            return False
        c = self.config
        if len(output) != c.m+c.w or any(type(x) is not int for x in output):
            return False
        if sum(x*x for x in output) > (c.m+c.w)*c.t_squared:
            return False
        try:
            f = self.generated.public.augment(self.identity_matrix(identity, bit))
            u = self.syndrome(identity, message)
        except SamplingAbort:
            return False
        return tuple(int(x) % c.q for x in f*vector(ZZ, output)) == u

    def dump_secret_state(self):
        """PLAINTEXT research snapshot. Never include output in logs/reports."""
        def rows(value):
            return [[int(x) for x in row] for row in value.rows()]
        return canonical_json({"version": VERSION, "config": asdict(self.config), "epoch": self.epoch.hex(),
            "base": rows(self.generated.a_bar), "R0": rows(self.generated.trapdoor),
            "k1": self.k1.hex(), "k2": self.k2.hex(),
            "users": [{"id": key.hex(), "bit": value.bit, "T": rows(value.trapdoor), "seed": value.seed.hex()}
                for key, value in sorted(self.users.items())],
            "failures": [[key.hex(), value] for key, value in sorted(self.failures.items())]})

    @classmethod
    def restore(cls, data, *, oracle=None):
        """Strict canonical codec plus algebra checks; not tamper authentication."""
        data = validate_bytes(data)
        if len(data) > 16*1024*1024:
            raise ValueError("Research snapshot exceeds public 16 MiB cap")
        record = json.loads(data)
        if not isinstance(record, dict) or canonical_json(record) != data or record.get("version") != VERSION:
            raise ValueError("Noncanonical snapshot or wrong version")
        if set(record) != {"version", "config", "epoch", "base", "R0", "k1", "k2", "users", "failures"}:
            raise ValueError("Missing or extra snapshot fields")
        if not isinstance(record["users"], list) or not isinstance(record["failures"], list):
            raise ValueError("Invalid snapshot collections")
        if any(not isinstance(item, dict) or set(item) != {"id", "bit", "T", "seed"} for item in record["users"]):
            raise ValueError("Missing or extra user fields")
        cfg = dict(record["config"])
        cfg["options"] = OnlineOptions(**cfg["options"])
        c = ResearchConfig(**cfg)
        generator, _, _, _ = prepare(c)
        # Validate signed/canonical entries before Sage coercion, which accepts bool.
        def ints(rows):
            if not isinstance(rows, list) or any(not isinstance(row, list) or any(type(x) is not int for x in row) for row in rows):
                raise ValueError("Snapshot matrix must contain exact JSON integers")
            return rows
        _, master = sampler_for_quality(c.q, ints(record["base"]), ints(record["R0"]), c.master_quality,
            r_squared=c.master_r_squared, gamma=c.gamma, options=c.options)
        if master is None:
            raise ValueError("Snapshot master quality rejected")
        generated = GeneratedTrapdoor(c.q, master.a_bar, master.public_matrix(), master.trapdoor,
            generator.gadget, identity_matrix(ZZ, c.n))
        session = cls(c, bytes.fromhex(record["epoch"]), generated,
            bytes.fromhex(record["k1"]), bytes.fromhex(record["k2"]), oracle=oracle)
        if len(record["users"])+len(record["failures"]) > c.max_users:
            raise ValueError("Snapshot exceeds public user limit")
        for item in record["users"]:
            identity = session._identity(bytes.fromhex(item["id"]))
            bit = exact_integer(item["bit"], "bit", maximum=1)
            expected = checked_read(session._stream(DOMAINS[0], (session.k1, identity), 1), 1)[0] & 1
            if bit != expected:
                raise ValueError("Snapshot branch differs from persistent master seed")
            # sampler_for_quality validates shape/integer values before use.
            raw = ints(item["T"])
            _, sampler = sampler_for_quality(c.q, generated.public, raw, c.user_quality,
                r_squared=c.user_r_squared, gamma=c.gamma, options=c.options)
            if sampler is None:
                raise ValueError("Snapshot user quality rejected")
            user = UserState(identity, bit, sampler.trapdoor, cls._seed(bytes.fromhex(item["seed"])))
            session._user_sampler(user)
            session.users[identity] = user
        for identity, status in record["failures"]:
            identity = session._identity(bytes.fromhex(identity))
            if status not in {"identity_hash_abort", "delegation_sampling_abort", "user_quality_rejected"} or identity in session.users:
                raise ValueError("Invalid failure record")
            session.failures[identity] = status
        # Also rejects extra fields, duplicates, noncanonical hex and ordering.
        if session.dump_secret_state() != data:
            raise ValueError("Noncanonical, duplicate or extra snapshot fields")
        return session
