"""Original Table 4 SRGG lifecycle; separate from optimization candidates.

The Table 3 factor ONE and anisotropic shapes are retained. The rounded
published r is used under an explicitly named notation interpretation.
No Q>2gamma or additional raw/user norm cap is imposed. Resource limits
are explicit operational limits, not claims of original security bounds.
"""
from fractions import Fraction
from collections import OrderedDict
from threading import Lock

from ibme.core.randomness import SecureRandom
from ibme.core.errors import EncodingError, SerializationError
from experiments.research.gaussian_reference import SamplingAbort
from .aggregate_budget import AggregateByteSource
from .paper_parameters import PaperParams
from .paper_algebra import PaperRing, public_matrix, identity_target, message_challenge
from .paper_objects import (
    PublicKey, MasterSecret, SigningKey, Signature, MAX_USERS,
    _identity, _message,
)
from .paper_samplef import PaperSampleF, WitnessGeometryError
from .paper_samplef import PaperSeriesOptions
from .structured_geometry import master_operator, signature_operator
from .structured_execution import GadgetRecurrence, sampler_profile, _norm
from .wide_scalar import WideScalarGaussian


class PaperGadget(GadgetRecurrence):
    def sample_scalar(self, target, source):
        # Algorithm 6 writes e=u mod p, v=(u-e)/p without prescribing an
        # integer representative. Use the centered small error in Z_p;
        # Python's unsigned % would add a large constant-coefficient bias.
        p = self.params
        if type(target) is not int or not 0 <= target < p.modulus:
            raise ValueError("canonical paper gadget target required")
        error = (target+p.p//2)%p.p-p.p//2
        state, result = (target-error)//p.p, []
        for _ in range(p.digits):
            residue = state%p.base
            value = residue+p.base*self.scalar.sample(p.r_squared,
                Fraction(-residue, p.base), rng=source)
            if (state-value)%p.base:
                raise RuntimeError("paper gadget digit congruence failed")
            result.append(value)
            state = (state-value)//p.base
        if (p.p*sum(p.base**i*x for i, x in enumerate(result))-target+error)%p.modulus:
            raise RuntimeError("paper gadget recurrence relation failed")
        return tuple(result), error

    def sample(self, target, *, rng):
        p = self.params
        target = PaperRing(p).vector(target, p.rank, p.modulus)
        source = AggregateByteSource(rng, self.batch["selected_cap_bytes"])
        result, errors = [], []
        for poly in target:
            values = [self.sample_scalar(value, source) for value in poly]
            result.extend(tuple(value[0][j] for value in values) for j in range(p.digits))
            errors.append(tuple(value[1] for value in values))
        return tuple(result), tuple(errors)


class Backend:
    security_claim = "none"
    backend_admitted = False
    parameters_are_formal = False
    nist_security_category = None

    def __init__(self, *, rng=None, setup_max_attempts=64, sign_max_attempts=64,
                 plan_cache_entries=2):
        self.rng = SecureRandom() if rng is None else rng
        if not callable(getattr(self.rng, "read", None)):
            raise TypeError("random source with read(n) required")
        for value in (setup_max_attempts, sign_max_attempts):
            if type(value) is not int or not 1 <= value <= 1024:
                raise ValueError("bounded operational retry limit required")
        self.setup_max_attempts, self.sign_max_attempts = setup_max_attempts, sign_max_attempts
        # Numerical precision and operational work budget, independent of the
        # published cryptographic inputs. The certificate checks the resulting
        # error; no width, norm or trapdoor support changes with these settings.
        _unused, self.scalar_options = sampler_profile("query-bounded")
        self.series_options = PaperSeriesOptions(precision_bits=768, ticket_bits=512,
            vector_dyadic_bits=256, series_error_bits=160, max_terms=8192,
            aggregate_abort_bits=192, max_ring_products=1000000)
        self._components_cache = {}
        self.setup_attempts = self.sign_attempts = self.extract_calls = 0
        self.last_master_certificate = self.last_sign_certificate = None
        self._plan_lock = Lock()
        self.configure_sign_plan_cache(plan_cache_entries)

    def configure_sign_plan_cache(self, capacity):
        """Bound secret-dependent preparation retention; zero disables reuse.

        Entries keep a strong reference to the immutable original key, preventing
        id reuse. No random sample or random-source state is retained here.
        """
        if type(capacity) is not int or not 0 <= capacity <= 16:
            raise ValueError("sign plan cache capacity must be an integer in [0, 16]")
        with self._plan_lock:
            self._plan_capacity = capacity
            self._sign_plans = OrderedDict()
            self._plan_hits = self._plan_misses = 0

    def clear_sign_plan_cache(self):
        with self._plan_lock:
            self._sign_plans.clear()

    def sign_plan_cache_info(self):
        with self._plan_lock:
            return dict(capacity=self._plan_capacity, entries=len(self._sign_plans),
                        hits=self._plan_hits, misses=self._plan_misses)

    def prepare_signing(self, key):
        """Explicitly pay deterministic preparation before repeated signing."""
        return self._sign_plan(key).public_certificate()

    def _read(self, count):
        data = self.rng.read(count)
        if type(data) is not bytes or len(data) != count:
            raise ValueError("invalid random source response")
        return data

    def _components(self, params):
        if type(params) is not PaperParams:
            raise TypeError("published PaperParams required")
        if params not in self._components_cache:
            self._components_cache[params] = (
                PaperGadget(params, scalar_options=self.scalar_options,
                            aggregate_abort_bits=self.series_options.aggregate_abort_bits),
                WideScalarGaussian(params.r_squared, params.r_squared, options=self.scalar_options))
        return self._components_cache[params]

    def _master_plan(self, params, witness):
        return PaperSampleF(master_operator(degree=params.degree, rank=params.rank,
            digits=params.digits, base=params.base, witness=witness,
            first_squared=params.master_first_squared, second_squared=params.master_second_squared,
            r_squared=params.r_squared), options=self.series_options, scalar_options=self.scalar_options)

    def _sign_plan(self, key):
        if type(key) is not SigningKey:
            raise TypeError("paper SigningKey required")
        options = (self.series_options, self.scalar_options)
        with self._plan_lock:
            entry = self._sign_plans.get(id(key))
            if entry is not None and entry[0] is key and entry[1] == options:
                self._plan_hits += 1
                self._sign_plans.move_to_end(id(key))
                return entry[2]
            self._plan_misses += 1
            plan = self._build_sign_plan(key)
            if self._plan_capacity:
                self._sign_plans[id(key)] = (key, options, plan)
                self._sign_plans.move_to_end(id(key))
                while len(self._sign_plans) > self._plan_capacity:
                    self._sign_plans.popitem(last=False)
            return plan

    def _build_sign_plan(self, key):
        p = key.public_key.params
        return PaperSampleF(signature_operator(degree=p.degree, rank=p.rank, digits=p.digits,
            user_vector=key.full, first_squared=p.signature_first_squared,
            second_squared=p.signature_second_squared, r_squared=p.r_squared,
            noise_factor=1), options=self.series_options, scalar_options=self.scalar_options)

    def setup(self, params):
        self._components(params)
        p, ring = params, PaperRing(params)
        seed = self._read(32)
        a_hat = public_matrix(p, seed)
        for _ in range(self.setup_max_attempts):
            self.setup_attempts += 1
            data = self._read(2*p.rank*p.rank*p.digits*p.degree)
            values = tuple((x&1)-((x>>1)&1) for x in data)
            witness = tuple(tuple(tuple(values[(i*p.rank*p.digits+j)*p.degree:
                (i*p.rank*p.digits+j+1)*p.degree]) for j in range(p.rank*p.digits))
                for i in range(2*p.rank))
            try:
                plan = self._master_plan(p, witness)
            except WitnessGeometryError:
                continue  # Algorithm 1 explicitly repeats nonpositive perturbation roots.
            self.last_master_certificate = plan.public_certificate()
            public = PublicKey(p, seed, a_hat, ring.build_public(a_hat, witness))
            return public, MasterSecret(public, witness)
        raise SamplingAbort("paper Algorithm 1 exhausted the operational setup limit")

    def key_extract(self, master, identity):
        if type(master) is not MasterSecret:
            raise TypeError("paper MasterSecret required")
        identity = _identity(identity)
        master._entries()
        entry = master.states.get(identity)
        if entry is not None:
            if entry[0] == "issued":
                return entry[1]
            raise SamplingAbort("paper identity pending/failed; automatic reissue blocked")
        if len(master.states) >= MAX_USERS:
            raise SamplingAbort("paper issuer operational capacity exceeded")
        master.states[identity] = ("pending", None)
        try:
            self.extract_calls += 1
            public, p = master.public_key, master.public_key.params
            ring = PaperRing(p)
            gadget, _ = self._components(p)
            plan = self._master_plan(p, master.witness)
            self.last_master_certificate = plan.public_certificate()
            flat = plan.sample(rng=self.rng)
            perturbation = tuple(tuple(flat[i:i+p.degree]) for i in range(0, len(flat), p.degree))
            target = identity_target(public, identity)
            residual = tuple(ring.add(h, ring.scale(a, -1), p.modulus) for h, a in zip(
                target, ring.matvec(ring.public_a(public), perturbation, p.modulus)))
            digits, error = gadget.sample(residual, rng=self.rng)
            raw = ring.raw_from_values(public, master.witness, target, perturbation, digits, error)
            key = SigningKey(public, identity, raw[p.rank:])
            master.states[identity] = ("issued", key)
            return key
        except BaseException:
            master.states[identity] = ("failed", None)
            raise

    def sign(self, key, message):
        if type(key) is not SigningKey:
            raise TypeError("paper SigningKey required")
        message = _message(message)
        public, p = key.public_key, key.public_key.params
        ring, (_, scalar) = PaperRing(p), self._components(p)
        plan = self._sign_plan(key)
        self.last_sign_certificate = plan.public_certificate()
        target = identity_target(public, key.identity)
        for _ in range(self.sign_max_attempts):
            self.sign_attempts += 1
            flat = plan.sample(rng=self.rng)
            perturbation = tuple(tuple(flat[i:i+p.degree]) for i in range(0, len(flat), p.degree))
            commitment = ring.matvec(ring.signing_matrix(public, target), perturbation, 2*p.modulus)
            challenge = message_challenge(public, commitment, message)
            centers = tuple(Fraction(-x, 2) for x in ring.multiply(ring.zeta(True), challenge))
            u = tuple(int(scalar.sample(p.r_squared, center, rng=self.rng)) for center in centers)
            response = ring.response(key.full, perturbation, u, challenge)
            if _norm(response) > p.signature_norm_cap:
                continue  # Algorithm 7's original norm retry, without changing gamma.
            result = Signature(public.context, response, challenge)
            if not self.verify(public, key.identity, message, result):
                raise RuntimeError("paper honest commitment invariant failed")
            return result
        raise SamplingAbort("paper Algorithm 7 exhausted the operational sign limit")

    def verify(self, public, identity, message, signature):
        try:
            if type(public) is not PublicKey or type(signature) is not Signature:
                return False
            identity, message = _identity(identity), _message(message)
            p, ring = public.params, PaperRing(public.params)
            if signature.context != public.context or _norm(signature.response) > p.signature_norm_cap:
                return False
            ring.vector(signature.response, p.columns+1)
            ring.poly(signature.challenge)
            if any(type(bit) is not int or bit not in (0, 1) for bit in signature.challenge):
                return False
            commitment = ring.recover(public, identity_target(public, identity), signature.response, signature.challenge)
            return message_challenge(public, commitment, message) == signature.challenge
        except (EncodingError, SerializationError, ValueError, TypeError, AttributeError, OverflowError):
            return False

    def load_signature(self, public, data):
        if type(public) is not PublicKey:
            raise TypeError("paper PublicKey required")
        value = Signature.from_bytes(data)
        try:
            ring = PaperRing(public.params)
            ring.vector(value.response, public.params.columns+1)
            if value.context != public.context or _norm(value.response) > public.params.signature_norm_cap:
                raise ValueError("signature public binding/norm mismatch")
            return value
        except (ValueError, TypeError):
            raise SerializationError("paper signature context/dimension/norm mismatch") from None
