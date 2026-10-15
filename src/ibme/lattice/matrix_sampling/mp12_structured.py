"""A3 structured MP12 Algorithm 3/4 research consumers, with identity tag.

No full m-by-m kernel basis, continuous normal RNG, or diagonal substitute for
the perturbation covariance. The finite perturbation uses spherical Gaussian
proposals and exact low-rank precision corrections. Only the k-by-k gadget
block and mbar-by-mbar Schur inverse are expanded. These are new explicit
research tools, not a replacement/registration of an existing HIBE backend.
"""

from dataclasses import asdict, dataclass, field
from hashlib import sha256
from itertools import islice
import json
from threading import RLock

from sage.all import QQ, ZZ, matrix, vector, identity_matrix, lcm

from ibme.core.encoding import encode_bytes
from ibme.core.randomness import SecureRandom
from ibme.core.types import validate_identity
from ibme.lattice.chkp.joint_parameters import smoothing_factor
from experiments.research.chkp_basis import KernelBasis, ModMatrixReference
from experiments.research.first_suite.entropy import CheckedEntropy
from experiments.research.gaussian_reference import SamplingAbort, draw_uniform_integer, interval_bounds
from .scalar import MatrixFiniteOptions, MatrixFiniteGaussian, exact_integer, capped_exp_minus_pi
from .gpv import MatrixFiniteGPV

VERSION = "IBME/MP12-STRUCTURED/1"
MAX_PREFIX, MAX_COLUMNS, MAX_R_ENTRIES, MAX_BYTES = 512, 8192, 2**22, 32*2**20


def _rows(values, height, width, *, q=None):
    if not isinstance(values, (tuple, list)) or len(values) != height:
        raise ValueError("structured matrix height mismatch")
    result = []
    for row in values:
        if not isinstance(row, (tuple, list)) or len(row) != width:
            raise ValueError("structured matrix width mismatch")
        checked = []
        for value in row:
            if isinstance(value, bool) or not isinstance(value, (int, type(ZZ(0)))):
                raise ValueError("structured matrices need exact integers")
            value = int(value)
            if abs(value).bit_length() > 4096 or q is not None and not 0 <= value < q:
                raise ValueError("structured integer/residue resource limit")
            checked.append(value)
        result.append(tuple(checked))
    return tuple(result)


def _syndrome(values, n, q):
    if isinstance(values, (str, bytes, bytearray, memoryview)):
        raise ValueError("canonical syndrome vector required")
    try:
        values = tuple(islice(iter(values), n+1))
    except TypeError:
        raise ValueError("canonical syndrome vector required") from None
    if len(values) != n:
        raise ValueError("structured syndrome dimension")
    return _rows((values,), 1, n, q=q)[0]


def _canonical(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii")


def _read_record(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_BYTES:
        raise ValueError("bounded structured snapshot bytes required")
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("duplicate structured snapshot field")
            out[key] = value
        return out
    def integer(text):
        if len(text) > 1250:
            raise ValueError("structured snapshot integer budget")
        return int(text)
    def reject(value):
        raise ValueError("noninteger structured snapshot number")
    record = json.loads(raw.decode("ascii"), object_pairs_hook=unique,
        parse_int=integer, parse_float=reject, parse_constant=reject)
    if _canonical(record) != raw:
        raise ValueError("noncanonical structured snapshot")
    return record


@dataclass(frozen=True, repr=False)
class StructuredTrapdoor:
    n: int
    q: int
    a_bar: tuple = field(repr=False)
    r: tuple = field(repr=False)
    frobenius_squared_bound: int
    public: object = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        n = exact_integer(self.n, "structured n", minimum=1, maximum=128)
        q = exact_integer(self.q, "structured q", minimum=3, maximum=2**61-1)
        if q % 2 == 0 or not ZZ(q).is_prime(proof=True):
            raise ValueError("structured trapdoor requires an odd prime")
        if (not isinstance(self.a_bar, (tuple, list)) or not self.a_bar or
                not isinstance(self.a_bar[0], (tuple, list))):
            raise ValueError("structured public prefix required")
        prefix = len(self.a_bar[0])
        w = n*(q-1).bit_length()
        if not 1 <= prefix <= MAX_PREFIX or prefix+w > MAX_COLUMNS or prefix*w > MAX_R_ENTRIES:
            raise ValueError("structured matrix profile resource limit")
        bound = exact_integer(self.frobenius_squared_bound, "public R norm bound", minimum=0, maximum=2**256)
        a = _rows(self.a_bar, n, prefix, q=q)
        r = _rows(self.r, prefix, w)
        if sum(x*x for row in r for x in row) > bound:
            raise ValueError("structured trapdoor exceeds its declared norm bound")
        a_matrix, r_matrix = matrix(ZZ, a), matrix(ZZ, r)
        k = (q-1).bit_length()
        gadget = matrix(ZZ, n, w, lambda i, j: 2**(j % k) if i == j//k else 0)
        public = a_matrix.augment(gadget-a_matrix*r_matrix).apply_map(lambda x: x % q)
        object.__setattr__(self, "n", n)
        object.__setattr__(self, "q", q)
        object.__setattr__(self, "a_bar", a)
        object.__setattr__(self, "r", r)
        object.__setattr__(self, "frobenius_squared_bound", bound)
        object.__setattr__(self, "public", ModMatrixReference(tuple(tuple(int(x) for x in row) for row in public.rows()), q))

    @property
    def prefix(self):
        return len(self.r)

    @property
    def w(self):
        return self.n*(self.q-1).bit_length()

    @property
    def dimension(self):
        return self.prefix+self.w

    def record(self):
        """PRIVATE record, only for a private state store; never a receipt."""
        return dict(schema=VERSION+"/KEY", n=self.n, q=self.q, a_bar=self.a_bar,
            r=self.r, frobenius_squared_bound=self.frobenius_squared_bound)

    def to_bytes(self):
        raw = _canonical(self.record())
        if len(raw) > MAX_BYTES:
            raise ValueError("structured key snapshot budget")
        return raw

    @classmethod
    def from_record(cls, record):
        fields = {"schema", "n", "q", "a_bar", "r", "frobenius_squared_bound"}
        if type(record) is not dict or set(record) != fields or record["schema"] != VERSION+"/KEY":
            raise ValueError("structured key version/shape")
        return cls(**{k: v for k, v in record.items() if k != "schema"})

    @classmethod
    def from_bytes(cls, raw):
        return cls.from_record(_read_record(raw))


def generate_structured_root(n, q, r_squared, *, rng=None, options=None):
    """MP12 computational [I|Ahat] root; no native/full-basis conversion."""
    n = exact_integer(n, "structured n", minimum=2, maximum=128)
    q = exact_integer(q, "structured q", minimum=3, maximum=2**61-1)
    r_squared = exact_integer(r_squared, "root R squared width", minimum=4*n, maximum=2**80)
    if not ZZ(q).is_prime(proof=True):
        raise ValueError("structured root prime required")
    w = n*(q-1).bit_length()
    if 2*n+w > MAX_COLUMNS or 2*n*w > MAX_R_ENTRIES:
        raise ValueError("structured root input resource limit")
    opts = MatrixFiniteOptions() if options is None else options
    scalar = MatrixFiniteGaussian(r_squared, r_squared, options=opts)
    tape = n*n*opts.max_uniform_trials*((q.bit_length()+7)//8)+2*n*w*scalar.random_tape_bytes
    if tape > opts.max_tape_bytes:
        raise ValueError("structured root tape resource limit")
    source = CheckedEntropy(SecureRandom() if rng is None else rng, tape)
    a_bar = tuple(tuple(int(i == j) for j in range(n))+tuple(
        draw_uniform_integer(source, q, max_trials=opts.max_uniform_trials) for _ in range(n)) for i in range(n))
    r = tuple(tuple(scalar.sample(r_squared, rng=source) for _ in range(w)) for _ in range(2*n))
    bound = 2*n*w*r_squared
    if sum(x*x for row in r for x in row) > bound:
        raise SamplingAbort("structured root norm event failed; no automatic retry")
    return StructuredTrapdoor(n, q, a_bar, r, bound)


def gadget_block(q):
    """Complete prime-q binary gadget kernel, k-by-k only, shared by n blocks."""
    q = exact_integer(q, "gadget q", minimum=3, maximum=2**61-1)
    if q % 2 == 0 or not ZZ(q).is_prime(proof=True):
        raise ValueError("gadget block requires an odd prime")
    k = (q-1).bit_length()
    basis = matrix(ZZ, k, k)
    for j in range(k-1):
        basis[j, j], basis[j+1, j] = 2, -1
    for i in range(k):
        basis[i, k-1] = (q >> i) & 1
    return KernelBasis(ModMatrixReference((tuple(2**i for i in range(k)),), q), basis)


def _output_width(trapdoor, r_squared):
    # Paper Sigma >= 7*T*T^t, AND a trace-based determinant bound:
    # product(1-lambda_i) >= 1-sum(lambda_i) >= 1/2.
    # tr(T*T^t)=w+||R||_F^2. This uses the declared bound, never a
    # favorable observed secret norm, and needs no extra factor of m.
    return max(7*r_squared*(1+trapdoor.frobenius_squared_bound),
               10*r_squared*(trapdoor.w+trapdoor.frobenius_squared_bound))


class StructuredPreimageSampler:
    """MP12 Algorithm 3 at H=I, Sigma_G=5I, conservative spherical output.

    Perturbation covariance C=s^2 I-g^2 T T^t, T=[R;I]. Rejection proposes
    independent D_Z,s and weights by exp(-pi*x^t(C^-1-s^-2 I)*x).
    The precision correction uses only R and an mbar-square Schur inverse.
    Theorem5.5's two normalizer factors are expanded in mp12_bounds; the
    resulting stochastic budget still excludes hardware and security claims.
    """

    def __init__(self, trapdoor, *, r_squared=None, output_squared=None,
                 epsilon_bits=128, max_trials=512, options=None):
        if not isinstance(trapdoor, StructuredTrapdoor):
            raise ValueError("validated structured trapdoor required")
        self.trapdoor = trapdoor
        self.epsilon_bits = exact_integer(epsilon_bits, "epsilon bits", minimum=8, maximum=256)
        self.max_trials = exact_integer(max_trials, "perturbation trials", minimum=1, maximum=4096)
        self.options = MatrixFiniteOptions() if options is None else options
        if type(self.options) is not MatrixFiniteOptions:
            raise ValueError("explicit matrix finite options required")
        t = trapdoor
        minimum_r = 4*smoothing_factor(t.w, self.epsilon_bits)
        self.r_squared = minimum_r if r_squared is None else exact_integer(r_squared, "r squared", minimum=minimum_r, maximum=2**80)
        self.gadget_squared = 5*self.r_squared
        minimum_s = _output_width(t, self.r_squared)
        self.output_squared = minimum_s if output_squared is None else exact_integer(output_squared, "output squared", minimum=minimum_s, maximum=2**192)
        if self.output_squared > 2**192:
            raise ValueError("structured output squared width outside finite scalar profile")
        self.scalar = MatrixFiniteGaussian(self.output_squared, self.output_squared, options=self.options)
        self.gadget = MatrixFiniteGPV(gadget_block(t.q), self.gadget_squared,
            epsilon_bits=self.epsilon_bits, options=self.options)
        self.bernoulli_bytes = (self.options.mass_bits+7)//8
        self.perturbation_tape_bytes = self.max_trials*(t.dimension*self.scalar.random_tape_bytes+self.bernoulli_bytes)
        self.random_tape_bytes = self.perturbation_tape_bytes+t.n*self.gadget.random_tape_bytes
        if self.random_tape_bytes > self.options.max_tape_bytes:
            raise ValueError("structured full-call tape limit")
        # det(C/s^2 I)>=1/2 and rho_s(Z)^m<=2*s^m certify ideal acceptance>=1/4.
        if t.dimension*self.scalar.theta > QQ(1)/2:
            raise ValueError("structured spherical normalizer bound failed")
        self._r = matrix(ZZ, t.r)
        self._r.set_immutable()
        self._d = self.output_squared-self.gadget_squared
        schur = self._d*identity_matrix(ZZ, t.prefix)-self.gadget_squared*(self._r*self._r.transpose())
        self._schur_inverse = matrix(QQ, schur).inverse()
        self._schur_inverse.set_immutable()
        for value in self._schur_inverse.list():
            if max(abs(int(value.numerator())).bit_length(), int(value.denominator()).bit_length()) > self.options.rational_bits:
                raise ValueError("structured exact Schur arithmetic limit")
        # All proposal coordinates lie in the already-certified scalar box.
        # Pre-admit EVERY possible precision numerator/denominator, rather
        # than learning about a bad rational path after consuming entropy.
        denominator = ZZ(1)
        for value in self._schur_inverse.list():
            denominator = lcm(denominator, value.denominator())
            if denominator.nbits() > self.options.rational_bits:
                raise ValueError("structured common Schur denominator limit")
        numerator_mass = sum(abs(denominator*x) for x in self._schur_inverse.list())
        y_bound = self.scalar.radius*(1+max(sum(abs(x) for x in col) for col in self._r.columns()))
        z_bound = y_bound*max(sum(abs(x) for x in row) for row in self._r.rows())
        numerator_bound = self.gadget_squared*(t.w*y_bound**2*denominator+
            self.gadget_squared*z_bound**2*numerator_mass)
        denominator_bound = self.output_squared*self._d*denominator
        if max(ZZ(numerator_bound).nbits(), ZZ(denominator_bound).nbits()) > self.options.rational_bits:
            raise ValueError("structured all-proposal exact precision path limit")
        self.last_trace = None

    def precision_correction(self, values):
        """PRIVATE exact quadratic form, exposed for independent public-toy QA."""
        t = self.trapdoor
        values = _rows((values,), 1, t.dimension)[0]
        top, bottom = vector(ZZ, values[:t.prefix]), vector(ZZ, values[t.prefix:])
        y = self._r.transpose()*top+bottom
        z = self._r*y
        correction = QQ(self.gadget_squared)/(self.output_squared*self._d)*(
            y.dot_product(y)+self.gadget_squared*z.dot_product(self._schur_inverse*z))
        if correction < 0:
            raise ArithmeticError("negative structured precision correction")
        if max(abs(int(correction.numerator())).bit_length(), int(correction.denominator()).bit_length()) > self.options.rational_bits:
            raise SamplingAbort("structured precision arithmetic limit; entire call aborted")
        return correction

    def _perturb(self, source):
        for trial in range(1, self.max_trials+1):
            values = tuple(self.scalar.sample(self.output_squared, rng=source) for _ in range(self.trapdoor.dimension))
            exponent = self.precision_correction(values)
            mass = 0
            if exponent < self.options.mass_bits:
                weight = capped_exp_minus_pi(exponent, self.scalar.field, self.scalar.cap_bits)
                lower, upper = interval_bounds(weight)
                if upper-lower > self.scalar.weight_width:
                    raise ArithmeticError("structured directed weight precision bound failed")
                mass = int((2**self.options.mass_bits*lower).floor())
            ticket = int.from_bytes(source.read(self.bernoulli_bytes), "big") & (2**self.options.mass_bits-1)
            if ticket < mass:
                return values, trial
        raise SamplingAbort("structured perturbation trials exhausted; no fallback")

    def sample(self, syndrome, *, rng=None):
        t = self.trapdoor
        target = _syndrome(syndrome, t.n, t.q)
        source = CheckedEntropy(SecureRandom() if rng is None else rng, self.random_tape_bytes)
        self.last_trace = dict(status="started", perturbation_trials=None, private_entropy_bytes=0)
        try:
            p, trials = self._perturb(source)
            a = t.public.rows
            v = tuple((u-sum(x*y for x, y in zip(row, p))) % t.q for u, row in zip(target, a))
            z = tuple(x for value in v for x in self.gadget.sample((value,), rng=source))
            rz = self._r*vector(ZZ, z)
            result = tuple(p[i]+int(rz[i]) for i in range(t.prefix))+tuple(p[t.prefix+j]+z[j] for j in range(t.w))
            if any(sum(x*y for x, y in zip(row, result)) % t.q != u for row, u in zip(a, target)):
                raise ArithmeticError("structured SampleD equation failed")
            self.last_trace.update(status="passed", perturbation_trials=trials)
            return result
        finally:
            self.last_trace["private_entropy_bytes"] = source.bytes_used
            if self.last_trace["status"] == "started":
                self.last_trace["status"] = "aborted"

    def public_certificate(self):
        from .mp12_bounds import sample_distribution_budget
        t = self.trapdoor
        proposal_tv = t.dimension*self.scalar.tv_upper
        weight_tv = self.scalar.weight_width+QQ(2)**(-self.options.mass_bits)
        # Lemma5.3: GS^2 <= 5*(sqrt(B)+1)^2 <= 10*(B+1).
        # Lemma2.3: smoothing_factor(D,b) exceeds ln(2D(1+2^b))/pi.
        # This theoretical basis is not constructed or used for sampling.
        target_smoothing = self.output_squared >= (
            10*(t.frobenius_squared_bound+1)*smoothing_factor(t.dimension, self.epsilon_bits))
        budget = sample_distribution_budget(dimension=t.dimension,
            epsilon_bits=self.epsilon_bits, max_trials=self.max_trials,
            proposal_scalar_tv=str(self.scalar.tv_upper), bernoulli_weight_error=str(weight_tv),
            gadget_tv_total=str(min(QQ(1), t.n*self.gadget.tv_upper)),
            target_smoothing_verified=bool(target_smoothing))
        return dict(profile=VERSION+"/SAMPLED", paper="MP12 section5.4, Algorithm3, Theorem5.5; H=I; Sigma_G=5I",
            n=t.n, q=t.q, prefix_dimension=t.prefix, gadget_columns=t.w, total_dimension=t.dimension,
            r_squared=str(self.r_squared), gadget_squared=str(self.gadget_squared), output_squared=str(self.output_squared),
            declared_R_frobenius_squared_bound=str(t.frobenius_squared_bound),
            ideal_perturbation_acceptance_lower="1/4",
            public_perturbation_trace_bound_ratio=str(QQ(self.gadget_squared)*(t.w+t.frobenius_squared_bound)/self.output_squared),
            ideal_perturbation_abort_upper=str((QQ(3)/4)**self.max_trials),
            finite_perturbation_coupling_upper=str(min(QQ(1), self.max_trials*(proposal_tv+weight_tv))),
            gadget_finite_coupling_upper=str(min(QQ(1), t.n*self.gadget.tv_upper)),
            concrete_convolution_theorem_term=budget["convolution_tv_upper"],
            distribution_budget=budget,
            modeled_sample_TV_including_abort_upper=budget["modeled_sample_TV_including_abort_upper"],
            full_sample_TV_or_failure_upper=None,
            arithmetic_resource_abort_upper=None,
            all_proposal_precision_rational_paths_admitted=True,
            finite_terms_assume_directed_MPFR_MPFI_weight_bound=True,
            expanded_full_kernel_bases=0, gadget_basis_dimension=(t.q-1).bit_length(),
            schur_dimension=t.prefix, stored_R_entries=t.prefix*t.w,
            finite_options=asdict(self.options), max_perturbation_trials=self.max_trials,
            public_random_tape_bytes=self.random_tape_bytes,
            constant_time=False, public_diagnostics_exclude_private_geometry=True,
            security_claim="none", backend_admitted=False, parameters_are_formal=False)


def _tail_digest(tail, n, q):
    return sha256(b"IBME:MP12-STRUCTURED:DELEGATION:v1"+encode_bytes(_canonical(dict(n=n, q=q, tail=tail)))).hexdigest()


class StructuredDelegator:
    """Algorithm4 consumer: one attempt per address, fixed successful R'.

    Standalone primitive state, not a HIBE/CLI transaction or anti-rollback
    store. persist_pending may save its opaque snapshot before private entropy.
    This first profile fixes the sampler's default options in its version.
    """
    def __init__(self, trapdoor, *, max_addresses=2, persist_pending=None):
        if not isinstance(trapdoor, StructuredTrapdoor):
            raise ValueError("structured delegation needs its own trapdoor")
        self.trapdoor = trapdoor
        self.max_addresses = exact_integer(max_addresses, "addresses", minimum=1, maximum=8)
        if persist_pending is not None and not callable(persist_pending):
            raise ValueError("structured pending persister must be callable")
        self._persist = persist_pending
        self._entries = {}
        self._lock = RLock()

    def issue(self, address, tail, *, rng=None):
        address = validate_identity(address, max_bytes=86)
        t = self.trapdoor
        tail = _rows(tail, t.n, t.w, q=t.q)
        digest = _tail_digest(tail, t.n, t.q)
        with self._lock:
            if address in self._entries:
                old_digest, key = self._entries[address]
                if old_digest != digest:
                    raise ValueError("structured address bound to another extension")
                if key is None:
                    raise SamplingAbort("structured delegation address failed; no reissue")
                return key
            if len(self._entries) >= self.max_addresses:
                raise ValueError("structured address capacity")
            self._entries[address] = (digest, None)
            if self._persist is not None:
                self._persist(self)
            # Every failure below leaves the address occupied, including a
            # resource rejection before the first private random byte.
            if t.dimension > MAX_PREFIX or t.dimension*t.w > MAX_R_ENTRIES:
                raise ValueError("structured delegated prefix exceeds this profile")
            sampler = StructuredPreimageSampler(t)
            if t.w*sampler.random_tape_bytes > sampler.options.max_tape_bytes:
                raise ValueError("structured whole-delegation tape limit")
            columns = []
            k = (t.q-1).bit_length()
            source = CheckedEntropy(SecureRandom() if rng is None else rng, sampler.options.max_tape_bytes)
            for j in range(t.w):
                target = tuple((int(i == j//k)*2**(j % k)-tail[i][j]) % t.q for i in range(t.n))
                x = sampler.sample(target, rng=source)
                if sum(v*v for v in x) > t.dimension*sampler.output_squared:
                    raise SamplingAbort("structured delegated column norm event; no retry")
                columns.append(x)
            r_new = tuple(tuple(columns[j][i] for j in range(t.w)) for i in range(t.dimension))
            result = StructuredTrapdoor(t.n, t.q, t.public.rows, r_new,
                t.dimension*t.w*sampler.output_squared)
            if any(result.public.rows[i][t.dimension+j] != tail[i][j] for i in range(t.n) for j in range(t.w)):
                raise ArithmeticError("structured Algorithm4 extension relation failed")
            result.to_bytes()
            self._entries[address] = (digest, result)
            try:
                self.to_bytes()
            except Exception:
                self._entries[address] = (digest, None)
                raise
            return result

    def to_bytes(self):
        with self._lock:
            record = dict(schema=VERSION+"/STATE", root=self.trapdoor.record(), max_addresses=self.max_addresses,
                entries=[dict(address=k.hex(), tail_digest=v[0], key=None if v[1] is None else v[1].record())
                         for k, v in sorted(self._entries.items())])
            raw = _canonical(record)
            if len(raw) > MAX_BYTES:
                raise ValueError("structured delegation snapshot budget")
            return raw

    @classmethod
    def from_bytes(cls, raw, *, persist_pending=None):
        record = _read_record(raw)
        if type(record) is not dict or set(record) != {"schema", "root", "max_addresses", "entries"} or record["schema"] != VERSION+"/STATE":
            raise ValueError("structured delegation state version/shape")
        result = cls(StructuredTrapdoor.from_record(record["root"]),
            max_addresses=record["max_addresses"], persist_pending=persist_pending)
        entries = record["entries"]
        if type(entries) is not list or len(entries) > result.max_addresses:
            raise ValueError("structured state address capacity")
        previous = None
        for entry in entries:
            if type(entry) is not dict or set(entry) != {"address", "tail_digest", "key"}:
                raise ValueError("structured state entry fields")
            if type(entry["address"]) is not str or len(entry["address"]) > 172:
                raise ValueError("structured state address encoding")
            address = validate_identity(bytes.fromhex(entry["address"]), max_bytes=86)
            if address.hex() != entry["address"] or previous is not None and address <= previous:
                raise ValueError("structured state duplicate/address order")
            previous = address
            digest = entry["tail_digest"]
            if type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("structured state extension digest")
            key = None if entry["key"] is None else StructuredTrapdoor.from_record(entry["key"])
            if key is not None:
                t = result.trapdoor
                tail = tuple(tuple(row[t.dimension:]) for row in key.public.rows)
                default_width = _output_width(t, 4*smoothing_factor(t.w, 128))
                expected_bound = t.dimension*t.w*default_width
                if (key.n != t.n or key.q != t.q or key.a_bar != t.public.rows or
                        key.frobenius_squared_bound != expected_bound or _tail_digest(tail, t.n, t.q) != digest):
                    raise ValueError("structured cached key/public extension binding")
                if any(sum(key.r[i][j]**2 for i in range(key.prefix)) > t.dimension*default_width for j in range(key.w)):
                    raise ValueError("structured cached delegation column norm")
            result._entries[address] = (digest, key)
        if result.to_bytes() != raw:
            raise ValueError("noncanonical structured state")
        return result
