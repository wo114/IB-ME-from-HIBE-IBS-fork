"""Opt-in MP12 3m feasibility machinery, with full perturbation and big q.

Algorithm 3's precision quadratic form is enclosed by a matrix-free solve.
Fixed-point iteration only proposes a solution; an EXACT integer residual and
the declared spectral bound certify its error. No approximate inverse is
trusted. Directed acceptance weights obey the scalar profile's error budget.
The output law/equations are the existing MP12 mechanism, with a new finite
arithmetic profile, not a new HIBE paper algorithm or an admitted backend.
"""

from math import isqrt

from sage.all import QQ, ZZ, vector

from ibme.core.randomness import SecureRandom
from ibme.lattice.chkp.entropy import CheckedEntropy
from ibme.lattice.chkp.joint_parameters import smoothing_factor
from experiments.research.gaussian_reference import SamplingAbort, draw_uniform_integer, interval_bounds
from .scalar import MatrixFiniteOptions, MatrixFiniteGaussian, exact_integer
from .prime_gadget import PrimeGadgetSampler, _modulus
from .packed import PackedMatrix

VERSION = "IBME/MP12-BLOCKED-3M/1"


def _target(values, n, q):
    if not isinstance(values, (tuple, list)) or len(values) != n:
        raise ValueError("blocked syndrome shape")
    return tuple(exact_integer(x, "syndrome", maximum=q-1) for x in values)


def output_width(w, bound, epsilon_bits=192):
    r = 4*smoothing_factor(w, epsilon_bits)
    return max(7*r*(1+bound), 10*r*(w+bound))


class PackedTrapdoor:
    """Independent [Abar | G-Abar*R] key; no ancestor secret is retained."""

    def __init__(self, n, q, public, r, bound, *, column_norm_bound=None):
        self.n = exact_integer(n, "blocked n", minimum=2, maximum=4096)
        self.q = _modulus(q)
        self.w = n*(q-1).bit_length()
        self.bound = exact_integer(bound, "declared R norm", maximum=2**256-1)
        if not isinstance(public, PackedMatrix) or not isinstance(r, PackedMatrix):
            raise ValueError("packed public and private matrices required")
        self.prefix, self.dimension = r.nrows, r.nrows+self.w
        if ((public.nrows, public.ncols) != (n, self.dimension) or r.ncols != self.w
                or public.signed or public.bound != q-1 or not r.signed):
            raise ValueError("blocked trapdoor dimensions/modulus")
        if r.norm_squared() > bound:
            raise ValueError("blocked R norm exceeds declaration")
        if column_norm_bound is not None and any(sum(x*x for x in col) > column_norm_bound for col in r.columns()):
            raise ValueError("blocked delegated column norm")
        self.public, self.r = public, r
        k = (q-1).bit_length()
        # Check A*[R;I]=G using n*dimension public storage, no large inverse.
        for j, col in enumerate(r.columns()):
            values = col+tuple(int(i == j) for i in range(self.w))
            actual = public.multiply(values)
            if any(int(actual[i]) % q != int(i == j//k)*2**(j % k) for i in range(n)):
                raise ValueError("blocked trapdoor equation")

    def __repr__(self):
        return f"PackedTrapdoor(n={self.n}, private_values_hidden=True)"


def generate_root(n, q, root_r_squared, *, options=None, rng=None, **packing):
    n = exact_integer(n, "blocked n", minimum=2, maximum=4096)
    q = _modulus(q)
    root_r_squared = exact_integer(root_r_squared, "root width", minimum=4*n, maximum=2**80)
    opts = MatrixFiniteOptions() if options is None else options
    scalar = MatrixFiniteGaussian(root_r_squared, root_r_squared, options=opts)
    w = n*(q-1).bit_length()
    # Check allocations and whole-operation entropy before the first read.
    if 2*n*w > 2**24:
        raise ValueError("blocked root entry budget")
    tape = n*n*opts.max_uniform_trials*((q.bit_length()+7)//8)+2*n*w*scalar.random_tape_bytes
    if tape > opts.max_tape_bytes:
        raise ValueError("blocked root entropy budget")
    source = CheckedEntropy(SecureRandom() if rng is None else rng, tape)
    abar = tuple(tuple(int(i == j) for j in range(n))+tuple(
        draw_uniform_integer(source, q, max_trials=opts.max_uniform_trials) for _ in range(n)) for i in range(n))
    # Keep only one sampled column and the packed backing during construction.
    r = PackedMatrix.from_columns(2*n, w, scalar.radius, True,
        (tuple(scalar.sample(root_r_squared, rng=source) for _ in range(2*n)) for _ in range(w)), **packing)
    a = PackedMatrix.from_rows(abar, q-1, False, **packing)
    k = (q-1).bit_length()
    def columns():
        yield from a.columns()
        for j, col in enumerate(r.columns()):
            values = a.multiply(col)
            yield tuple((int(i == j//k)*2**(j % k)-int(values[i])) % q for i in range(n))
    public = PackedMatrix.from_columns(n, 2*n+w, q-1, False, columns(), **packing)
    return PackedTrapdoor(n, q, public, r, 2*n*w*root_r_squared)


class BlockedPreimageSampler:
    """SampleLeft on [A|E]; E coordinates receive full Gaussian perturbation."""

    def __init__(self, trapdoor, extension=None, *, epsilon_bits=192, options=None):
        if not isinstance(trapdoor, PackedTrapdoor):
            raise ValueError("validated packed trapdoor required")
        self.trapdoor = t = trapdoor
        self.epsilon_bits = exact_integer(epsilon_bits, "epsilon", minimum=8, maximum=256)
        self.options = MatrixFiniteOptions() if options is None else options
        if type(self.options) is not MatrixFiniteOptions:
            raise ValueError("explicit matrix finite options required")
        if extension is not None and (not isinstance(extension, PackedMatrix)
                or extension.nrows != t.n or extension.signed or extension.bound != t.q-1):
            raise ValueError("blocked extension shape/residue domain")
        self.extension = extension
        self.dimension = t.dimension+(0 if extension is None else extension.ncols)
        self.r_squared = 4*smoothing_factor(t.w, epsilon_bits)
        self.gadget_squared = 5*self.r_squared
        self.output_squared = output_width(t.w, t.bound, epsilon_bits)
        self.scalar = MatrixFiniteGaussian(self.output_squared, self.output_squared, options=self.options)
        self.gadget = PrimeGadgetSampler(t.n, t.q, self.gadget_squared,
            epsilon_bits=epsilon_bits, options=self.options)
        self.rho = QQ(self.gadget_squared)*(1+t.bound)/self.output_squared
        if not 0 <= self.rho <= QQ(1)/2:
            raise ValueError("matrix-free SPD contraction condition")
        if self.dimension*self.scalar.theta > QQ(1)/2:
            raise ValueError("blocked spherical normalizer condition")
        self.max_trials = 512
        self.bernoulli_bytes = (self.options.mass_bits+7)//8
        self.random_tape_bytes = self.max_trials*(self.dimension*self.scalar.random_tape_bytes+self.bernoulli_bytes)+self.gadget.random_tape_bytes
        if self.random_tape_bytes > self.options.max_tape_bytes:
            raise ValueError("blocked sampler whole-call tape limit")
        self.scale = ZZ(1) << (self.options.precision_bits+128)
        self.max_solve_steps = self.options.precision_bits+256
        self.last_trace = None

    def _gram_product(self, values):
        r = self.trapdoor.r
        return r.multiply(r.multiply(values), transpose=True)+values

    def correction_interval(self, values):
        """PRIVATE enclosure of p^t(C^-1-S^-1 I)p; never a receipt field."""
        t, S, g = self.trapdoor, self.output_squared, self.gadget_squared
        if len(values) != self.dimension:
            raise ValueError("blocked perturbation dimension")
        v = t.r.multiply(values[:t.prefix], transpose=True)+vector(ZZ, values[t.prefix:t.dimension])
        vnorm = v.dot_product(v)
        if vnorm == 0:
            return QQ(0), QQ(0)
        scaled_v = self.scale*v
        candidate = scaled_v
        prefactor = QQ(g)/(S*S)
        tolerance = self.scalar.weight_width/16
        for _ in range(self.max_solve_steps):
            product = self._gram_product(candidate)
            residual = S*scaled_v-S*candidate+g*product
            square = int(vnorm*residual.dot_product(residual))
            root = isqrt(square)
            root += int(root*root < square)
            error = prefactor*QQ(root)/(S*self.scale*(1-self.rho))
            if 2*error <= tolerance:
                center = prefactor*QQ(v.dot_product(candidate))/self.scale
                return max(QQ(0), center-error), center+error
            # Integer division only constructs a candidate; the residual above
            # checks all rounding error independently on the next iteration.
            candidate = scaled_v+vector(ZZ, (g*x//S for x in product))
        raise SamplingAbort("blocked precision solve exhausted; no fallback")

    def _perturb(self, source):
        for trial in range(1, self.max_trials+1):
            values = tuple(self.scalar.sample(self.output_squared, rng=source) for _ in range(self.dimension))
            lower, upper = self.correction_interval(values)
            mass = 0
            if lower < self.options.mass_bits:
                field = self.scalar.field
                weight = (-field.pi()*field(lower, upper)).exp()
                lo, hi = interval_bounds(weight)
                if hi-lo > self.scalar.weight_width:
                    raise SamplingAbort("blocked directed precision weight budget")
                mass = int((2**self.options.mass_bits*lo).floor())
            ticket = int.from_bytes(source.read(self.bernoulli_bytes), "big") & (2**self.options.mass_bits-1)
            if ticket < mass:
                return values, trial
        raise SamplingAbort("blocked perturbation trials exhausted; no fallback")

    def public_product(self, values):
        t = self.trapdoor
        out = t.public.multiply(values[:t.dimension])
        if self.extension is not None:
            out += self.extension.multiply(values[t.dimension:])
        return tuple(int(x) % t.q for x in out)

    def sample(self, syndrome, *, rng=None):
        t = self.trapdoor
        target = _target(syndrome, t.n, t.q)
        source = CheckedEntropy(SecureRandom() if rng is None else rng, self.random_tape_bytes)
        p, trials = self._perturb(source)
        ap = self.public_product(p)
        z = self.gadget.sample(tuple((u-a) % t.q for u, a in zip(target, ap)), rng=source)
        rz = t.r.multiply(z)
        result = (tuple(p[i]+int(rz[i]) for i in range(t.prefix))
                  +tuple(p[t.prefix+j]+z[j] for j in range(t.w))+p[t.dimension:])
        if self.public_product(result) != target:
            raise ArithmeticError("blocked SampleLeft equation")
        self.last_trace = dict(perturbation_trials=trials, entropy_bytes=source.bytes_used)
        return result

    def public_certificate(self):
        from .mp12_bounds import sample_distribution_budget
        t = self.trapdoor
        budget = sample_distribution_budget(dimension=self.dimension, epsilon_bits=self.epsilon_bits,
            max_trials=self.max_trials, proposal_scalar_tv=str(self.scalar.tv_upper),
            bernoulli_weight_error=str(self.scalar.weight_width+QQ(2)**(-self.options.mass_bits)),
            gadget_tv_total=str(self.gadget.tv_upper), target_smoothing_verified=bool(
                self.output_squared >= 10*(t.bound+1)*smoothing_factor(self.dimension, self.epsilon_bits)))
        return dict(profile=VERSION, q=str(self.trapdoor.q), n=self.trapdoor.n,
            dimension=self.dimension, output_squared=str(self.output_squared),
            stored_R_entries=self.trapdoor.prefix*self.trapdoor.w,
            full_kernel_bases=0, dense_Schur_entries=0,
            precision_method="fixed-point candidate; exact integer residual; declared SPD bound; directed MPFI weight",
            precision_weight_error_upper=str(self.scalar.weight_width),
            max_solve_steps=self.max_solve_steps, max_perturbation_trials=self.max_trials,
            random_tape_bytes=self.random_tape_bytes,
            finite_scalar_tv_upper=str(self.scalar.tv_upper),
            gadget_tv_upper=str(self.gadget.tv_upper),
            distribution_budget=budget,
            arithmetic_resource_abort_probability_certified=False,
            constant_time=False, security_claim="none", backend_admitted=False, parameters_are_formal=False)


def delegate(trapdoor, extension, *, epsilon_bits=192, options=None, rng=None,
             entropy_budget=2**40, **packing):
    """Algorithm 4: one full sampled column at a time, no output coordinates omitted."""
    t = trapdoor
    if not isinstance(extension, PackedMatrix) or extension.ncols < t.w:
        raise ValueError("complete H extension required")
    extras_count = extension.ncols-t.w
    extras = None if extras_count == 0 else PackedMatrix.from_columns(t.n, extras_count,
        t.q-1, False, (extension.column(j) for j in range(extras_count)), **packing)
    sampler = BlockedPreimageSampler(t, extras, epsilon_bits=epsilon_bits, options=options)
    if sampler.dimension*t.w > 2**24:
        raise ValueError("blocked whole-delegation resource limit")
    # This is an explicit runtime cap, not a claim that every possible
    # rejection path fits. Exhaustion aborts this occupied operation; it is
    # reported separately from the modeled finite sampling error.
    entropy_budget = exact_integer(entropy_budget, "delegation entropy cap", minimum=1, maximum=2**48)
    source = CheckedEntropy(SecureRandom() if rng is None else rng, entropy_budget)
    limit = sampler.dimension*sampler.output_squared
    k = (t.q-1).bit_length()
    def columns():
        for j in range(t.w):
            tail = extension.column(extras_count+j)
            target = tuple((int(i == j//k)*2**(j % k)-tail[i]) % t.q for i in range(t.n))
            result = sampler.sample(target, rng=source)
            if sum(x*x for x in result) > limit:
                raise SamplingAbort("blocked parent column norm event; no retry")
            yield result
    r = PackedMatrix.from_columns(sampler.dimension, t.w, isqrt(limit), True, columns(), **packing)
    def public_columns():
        yield from t.public.columns()
        yield from extension.columns()
    public = PackedMatrix.from_columns(t.n, t.dimension+extension.ncols, t.q-1, False, public_columns(), **packing)
    return PackedTrapdoor(t.n, t.q, public, r, sampler.dimension*t.w*sampler.output_squared,
                          column_norm_bound=limit)
