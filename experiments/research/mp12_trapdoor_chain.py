"""MP12 GenTrap/DelTrap and a bounded, connected rank-one research instance.

General prime-q generation/delegation; the uniform admission proof is restricted
to q=2, n=w=m_bar=1 and qualified one-column trapdoors. Research only, variable
time, no IBS/HIBE backend and no security level. Uniform-byte assumption.
Run in WSL conda ~/miniconda3/envs/sage with PYTHONPATH=src.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from math import gcd, lcm

from sage.all import GF, QQ, ZZ, RealIntervalField, identity_matrix, matrix, vector

from ibme.core.randomness import SecureRandom
from .gaussian_reference import (SamplingAbort, build_gaussian_table_squared,
    draw_uniform_integer, interval_bounds)
from .general_gadget_reference import GeneralModulusGadgetSampler
from .mp12_sampled_reference import (FiniteByteTape, MP12SampleD, matrix_record,
    outward_upper, rational_matrix)


def integer(value, name, *, minimum=0, maximum=2**32):
    if isinstance(value, bool) or not isinstance(value, (int, type(ZZ(0)))):
        raise ValueError(f"{name} must be an integer")
    value = int(value)
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} outside reference range")
    return value


def rational(value, name):
    if isinstance(value, bool) or not isinstance(value, (str, int, Fraction, type(QQ(0)), type(ZZ(0)))):
        raise ValueError(f"{name} must be an exact rational")
    try:
        return QQ(value)
    except (ValueError, TypeError, ZeroDivisionError) as exc:
        raise ValueError(f"Invalid {name}") from exc


def modular_matrix(value, q, shape, name):
    value = rational_matrix(value, name)
    if value.dimensions() != shape or any(x.denominator() != 1 or not 0 <= x < q for x in value.list()):
        raise ValueError(f"{name} needs shape {shape} and canonical modular integers")
    out = matrix(ZZ, value)
    out.set_immutable()
    return out


def invertible_tag(value, q, n):
    tag = modular_matrix(identity_matrix(ZZ, n) if value is None else value, q, (n, n), "tag")
    if not matrix(GF(q), tag).is_invertible():
        raise ValueError("Tag must be invertible modulo q")
    return tag


def public_tape_bytes(draws, options):
    mass_upper = (1 << options["mass_bits"])*(2*options["max_radius"]+2)
    return draws*options["max_trials"]*(((mass_upper-1).bit_length()+7)//8)


@dataclass(frozen=True)
class GeneratedTrapdoor:
    q: int
    a_bar: object
    public: object
    trapdoor: object
    gadget: object
    tag: object

    @property
    def norm_squared(self):
        return sum(int(x)**2 for x in self.trapdoor.list())


class GaussianGenTrap:
    """MP12 Algorithm 1, sampling a genuine finite Gaussian matrix D.

    The public near-uniform property needs its own parameter analysis. The
    default tiny connected instance deliberately does NOT satisfy regularity.
    """

    def __init__(self, q, n, m_bar, width_squared, **table_options):
        self.q = integer(q, "q", minimum=2)
        if not ZZ(self.q).is_prime():
            raise ValueError("Need prime q")
        self.n = integer(n, "n", minimum=1, maximum=8)
        self.m_bar = integer(m_bar, "m_bar", minimum=1, maximum=16)
        self.w = self.n*(self.q-1).bit_length()
        if self.m_bar+self.w > 16:
            raise ValueError("Reference output dimension exceeds 16")
        self.table = build_gaussian_table_squared(width_squared, **table_options)
        config = self.table.config_record()
        self.options = {key: config[key] for key in ("tail_bits", "mass_bits", "precision_bits", "max_trials")}
        self.options["max_radius"] = int(table_options.get("max_radius", 512))
        self.gadget = matrix(ZZ, self.n, self.w)
        k = self.w//self.n
        for i in range(self.n):
            for j in range(k):
                self.gadget[i, i*k+j] = (1 << j) % self.q
        self.gadget.set_immutable()
        trials = 1 if self.q == 2 else self.options["max_trials"]
        self.matrix_tape_bytes = self.n*self.m_bar*trials*(((self.q-1).bit_length()+7)//8)
        self.random_tape_bytes = self.matrix_tape_bytes+public_tape_bytes(self.m_bar*self.w, self.options)
        if self.random_tape_bytes > 16*1024*1024:
            raise ValueError("Generation random tape exceeds 16 MiB")

    def generate(self, *, tag=None, rng=None):
        tag = invertible_tag(tag, self.q, self.n)
        rng = SecureRandom() if rng is None else rng
        a_bar = matrix(ZZ, self.n, self.m_bar, [draw_uniform_integer(rng, self.q,
            max_trials=self.options["max_trials"]) for _ in range(self.n*self.m_bar)])
        trapdoor = matrix(ZZ, self.m_bar, self.w,
            [self.table.sample(rng=rng) for _ in range(self.m_bar*self.w)])
        public = a_bar.augment(tag*self.gadget-a_bar*trapdoor).apply_map(lambda x: x % self.q)
        for value in (a_bar, trapdoor, public):
            value.set_immutable()
        assert (public*trapdoor.stack(identity_matrix(ZZ, self.w))-tag*self.gadget).apply_map(lambda x: x % self.q).is_zero()
        return GeneratedTrapdoor(self.q, a_bar, public, trapdoor, self.gadget, tag)

    def generate_from_tape(self, tape, *, tag=None):
        rng = FiniteByteTape(tape)
        if len(rng.data) != self.random_tape_bytes:
            raise ValueError("Generation tape must have the public fixed length")
        return self.generate(tag=tag, rng=rng)


@dataclass(frozen=True)
class DelegatedTrapdoor:
    parent_public: object
    extension: object
    new_tag: object
    trapdoor: object
    syndromes: tuple
    column_tape_bytes: int
    joint_tv_upper: object

    @property
    def foo_li_R_id(self):
        result = -self.trapdoor
        result.set_immutable()
        return result

    @property
    def norm_squared(self):
        return sum(int(x)**2 for x in self.trapdoor.list())


def delegate_from_tape(parent, extension, tape, *, parent_tag=None, new_tag=None):
    """MP12 Algorithm 4 with one disjoint fixed tape segment per column."""
    extension = modular_matrix(extension, parent.q, (parent.n, parent.w), "extension")
    new_tag = invertible_tag(new_tag, parent.q, parent.n)
    parent_public = parent.public_matrix(parent_tag)
    full = FiniteByteTape(tape)
    if len(full.data) != parent.w*parent.random_tape_bytes:
        raise ValueError("Delegation tape must contain w disjoint public-length segments")
    targets = (new_tag*parent.g-extension).apply_map(lambda x: x % parent.q)
    syndromes, columns = [], []
    for j in range(parent.w):
        syndrome = tuple(int(x) for x in targets.column(j))
        segment = full.read(parent.random_tape_bytes)
        columns.append(parent.sample_from_tape(syndrome, segment, tag=parent_tag))
        syndromes.append(syndrome)
    trapdoor = matrix(ZZ, columns).transpose()
    trapdoor.set_immutable()
    assert (parent_public*trapdoor-new_tag*parent.g+extension).apply_map(lambda x: x % parent.q).is_zero()
    error = min(QQ(1), parent.w*QQ(parent.certificate()["tv_upper_including_abort"]))
    return DelegatedTrapdoor(parent_public, extension, new_tag, trapdoor,
        tuple(syndromes), parent.random_tape_bytes, error)


def delegate(parent, extension, *, parent_tag=None, new_tag=None, rng=None):
    # Validate all public inputs before consuming entropy.
    modular_matrix(extension, parent.q, (parent.n, parent.w), "extension")
    invertible_tag(new_tag, parent.q, parent.n)
    parent.public_matrix(parent_tag)
    rng = SecureRandom() if rng is None else rng
    tape = rng.read(parent.w*parent.random_tape_bytes)
    return delegate_from_tape(parent, extension, tape, parent_tag=parent_tag, new_tag=new_tag)


@dataclass(frozen=True)
class RankOneParameters:
    """Public parameters for the q=2, n=w=m_bar=1 connected research class."""
    master_quality_squared: int = 4
    user_quality_squared: int = 128
    generator_width_squared: object = 1
    master_r_squared: object = 4
    user_r_squared: object = 4
    gamma: int = 5
    tail_bits: int = 80
    mass_bits: int = 128
    precision_bits: int = 192
    max_trials: int = 128
    max_radius: int = 512
    max_center_classes: int = 4096

    def __post_init__(self):
        for name in ("master_quality_squared", "user_quality_squared"):
            object.__setattr__(self, name, integer(getattr(self, name), name, maximum=4096))
        object.__setattr__(self, "gamma", integer(self.gamma, "gamma", minimum=2, maximum=128))
        for name in ("generator_width_squared", "master_r_squared", "user_r_squared"):
            value = rational(getattr(self, name), name)
            if value <= 0:
                raise ValueError("Widths must be positive")
            object.__setattr__(self, name, value)
        for name, low, high in (("tail_bits", 8, 1024), ("mass_bits", 32, 2048),
            ("precision_bits", 96, 4096), ("max_trials", 1, 4096),
            ("max_radius", 1, 4096), ("max_center_classes", 1, 20000)):
            object.__setattr__(self, name, integer(getattr(self, name), name, minimum=low, maximum=high))

    @property
    def table_options(self):
        return {name: getattr(self, name) for name in
            ("tail_bits", "mass_bits", "precision_bits", "max_trials", "max_radius")}

    def stage(self, which):
        if which not in ("master", "user"):
            raise ValueError("Unknown stage")
        dimension = 2 if which == "master" else 3
        quality = getattr(self, f"{which}_quality_squared")
        r_squared = getattr(self, f"{which}_r_squared")
        sigma = (self.gamma+2)*(quality+1)
        return dimension, quality, r_squared, sigma


def rank_one_profile(trapdoor, params, which):
    """Exact rank-one inverse-metric geometry without constructing any CDFs."""
    dimension, quality, r_squared, sigma = params.stage(which)
    r = rational_matrix(trapdoor, "trapdoor")
    if r.dimensions() != (dimension-1, 1) or any(x.denominator() != 1 for x in r.list()):
        raise ValueError("Need a signed integer one-column trapdoor of the stage dimension")
    norm = sum(int(x)**2 for x in r.list())
    if norm > quality:
        return {"status": "quality_rejected", "norm_squared": norm, "quality_squared": quality}
    a = [int(x) for x in r.column(0)]+[1]
    denominators, widths = [], []
    for i in range(dimension):
        after = sigma-params.gamma*sum(x*x for x in a[i+1:])
        current = sigma-params.gamma*sum(x*x for x in a[i:])
        assert after > 0 and current > 0
        denominators.append(lcm(1, *(after//gcd(after, params.gamma*a[i]*a[j])
            for j in range(i+1, dimension))))
        widths.append(r_squared*sigma*current/after)
    return {"status": "qualified", "norm_squared": norm, "quality_squared": quality,
        "center_denominators": denominators, "center_classes": sum(denominators),
        "coordinate_widths_squared": [str(x) for x in widths],
        "resource_scope": "entire qualified rank-one class, not selected successful keys"}


def sampling_class_certificate(params, which):
    """Uniform numerical/resource bound for EVERY qualified one-column R.

    Uses directed MPFR/MPFI rounding. The loose ulp budget and partition bound
    are derived in round nine; independent tests check the emitted local tables.
    """
    dimension, quality, r_squared, sigma = params.stage(which)
    v_min = r_squared*(sigma-params.gamma*(quality+1))
    v_max = r_squared*sigma
    centers_max = (dimension-1)*sigma+1
    if not 1 <= v_min <= v_max <= 4096 or centers_max > params.max_center_classes:
        raise ValueError("Public class does not cover every qualified trapdoor within reference resources")
    field = RealIntervalField(params.precision_bits)
    h, points = params.max_radius, 2*params.max_radius+2
    relative_argument = max(QQ(1), QQ((h+2)**2)/v_min)
    e = 0
    while QQ(2)**e < relative_argument:
        e += 1
    if params.precision_bits < e+24:
        raise ValueError("Insufficient public precision for the uniform rounding budget")
    weight_width = QQ(2)**(e+8-params.precision_bits)
    ratio = (-field.pi()*field(QQ(2*(h+1)+1)/v_max)).exp()
    if interval_bounds(1-ratio)[0] < QQ(1)/2:
        raise ValueError("Uniform geometric-tail denominator not certified >=1/2")
    tail = 2*(-field.pi()*field((QQ((h+1)**2)-QQ(1)/4)/v_max)).exp()/(1-ratio)
    tail_upper = outward_upper(tail)
    tail_target = QQ(1)/2**params.tail_bits
    if tail_upper+32*weight_width > tail_target:
        raise ValueError("Uniform radius cannot achieve the public tail target")
    theta_a = (-field.pi()*field(v_min)).exp()
    theta = outward_upper(2*theta_a/(1-theta_a**3))
    norm_interval_width = tail_target+8*(points+1)*weight_width
    distortion = theta+norm_interval_width
    if distortion >= QQ(1)/2:
        raise ValueError("Uniform normalizer lower bound not positive")
    partition_ratio = (1+distortion)/(1-distortion)
    nearest_plane = min(QQ(1), (partition_ratio**dimension-1)/2)
    scalar_error = tail_target+points*(QQ(1)/2**params.mass_bits+weight_width)+QQ(1)/2**params.max_trials
    perturbation_error = min(QQ(1), nearest_plane+dimension*scalar_error)
    gadget = GeneralModulusGadgetSampler(2, r_squared*params.gamma,
        max_center_classes=params.max_center_classes, **params.table_options)
    epsilon = QQ(0)
    for scaled_width in (r_squared, r_squared*params.gamma/4):
        a = (-field.pi()*field(scaled_width)).exp()
        if interval_bounds(1-2*a)[0] <= 0:
            raise ValueError("Smoothing denominator not positive")
        epsilon = max(epsilon, outward_upper(2*a/(1-2*a)))
    if not 0 < epsilon <= QQ(1)/2:
        raise ValueError("MP12 smoothing not certified")
    convolution = min(QQ(1), 4*epsilon/(1-epsilon)**2)
    total = min(QQ(1), convolution+perturbation_error+QQ(gadget.certificate()["tv_upper_including_abort"]))
    return {"stage": which, "q": 2, "n": 1, "w": 1, "dimension": dimension,
        "quality_squared": quality, "r_squared": str(r_squared), "Sigma_scalar": sigma,
        "Sigma_G_scalar": params.gamma, "spherical_width_squared": str(v_max),
        "coordinate_width_squared_range": [str(v_min), str(v_max)],
        "center_classes_uniform_max": centers_max, "max_center_classes": params.max_center_classes,
        "uniform_relative_weight_interval_width": str(weight_width),
        "uniform_normalizer_interval_width": str(norm_interval_width),
        "uniform_geometric_tail_upper": str(tail_upper),
        "uniform_scalar_tv_upper": str(outward_upper(scalar_error)),
        "uniform_nearest_plane_tv_upper": str(outward_upper(nearest_plane)),
        "uniform_perturbation_tv_upper": str(outward_upper(perturbation_error)),
        "MP12_epsilon_upper": str(epsilon),
        "uniform_SampleD_tv_upper": str(outward_upper(total)),
        "public_tape_bytes": public_tape_bytes(dimension+1, params.table_options),
        "resource_rejection_given_quality_upper": "0",
        "rounding_assumption": "directed correctly-rounded rational conversion, pi, arithmetic and exp in Sage MPFR/MPFI, no overflow/underflow in this range",
        "coverage": "every signed integer rank-one trapdoor with norm_squared <= quality_squared",
        "security_claim": "none", "constant_time": False}


@dataclass(frozen=True)
class SamplerAdmission:
    status: str
    profile: dict
    sampler: object = None


def make_master_sampler(generated, params):
    if generated.q != 2 or generated.trapdoor.dimensions() != (1, 1) or generated.a_bar.dimensions() != (1, 1):
        raise ValueError("Connected class requires q=2,n=m_bar=w=1")
    bound = sampling_class_certificate(params, "master")
    profile = rank_one_profile(generated.trapdoor, params, "master")
    base = modular_matrix(generated.a_bar, 2, (1, 1), "base")
    tag = invertible_tag(generated.tag, 2, 1)
    public = modular_matrix(generated.public, 2, (1, 2), "generated public")
    expected = base.augment(tag-base*generated.trapdoor).apply_map(lambda x: x % 2)
    if public != expected:
        raise ValueError("Generated trapdoor relation does not hold")
    if profile["status"] != "qualified":
        return SamplerAdmission("master_quality_rejected", profile)
    sampler = MP12SampleD(2, generated.a_bar, generated.trapdoor,
        r_squared=params.master_r_squared, sigma_squared=bound["Sigma_scalar"],
        gadget_covariance=params.gamma, max_center_classes=params.max_center_classes, **params.table_options)
    assert sampler.public_matrix(generated.tag) == generated.public
    assert QQ(sampler.certificate()["tv_upper_including_abort"]) <= QQ(bound["uniform_SampleD_tv_upper"])
    return SamplerAdmission("admitted", profile, sampler)


def make_user_sampler(delegated, params):
    bound = sampling_class_certificate(params, "user")
    profile = rank_one_profile(delegated.trapdoor, params, "user")
    parent = modular_matrix(delegated.parent_public, 2, (1, 2), "parent public")
    extension = modular_matrix(delegated.extension, 2, (1, 1), "extension")
    if delegated.new_tag != matrix(ZZ, [[1]]):
        raise ValueError("Foo-Li connected class requires identity tag")
    if (parent*delegated.trapdoor+extension-matrix(ZZ, [[1]])).apply_map(lambda x: x % 2) != matrix(ZZ, [[0]]):
        raise ValueError("Delegated trapdoor relation does not hold")
    if profile["status"] != "qualified":
        return SamplerAdmission("user_quality_rejected", profile)
    _, _, r_squared, sigma = params.stage("user")
    sampler = MP12SampleD(2, parent, delegated.trapdoor, r_squared=r_squared,
        sigma_squared=sigma, gadget_covariance=params.gamma,
        max_center_classes=params.max_center_classes, **params.table_options)
    assert sampler.public_matrix() == parent.augment(extension)
    assert QQ(sampler.certificate()["tv_upper_including_abort"]) <= QQ(bound["uniform_SampleD_tv_upper"])
    return SamplerAdmission("admitted", profile, sampler)
