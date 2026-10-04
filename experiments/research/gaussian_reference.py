"""Finite-error Sage reference for one-dimensional and gadget Gaussians.

Research only: variable-time, finite-support, power-of-two gadget modulus only.
No TrapGen, perturbation sampler, SamplePre, IBS or HIBE is implemented here.
Run with the Python in WSL conda ~/miniconda3/envs/sage, with PYTHONPATH=src.
The distribution bounds assume independent uniform random-source bytes.
"""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
from fractions import Fraction
from hashlib import sha256
from itertools import accumulate, product
import json

from sage.all import QQ, RealIntervalField, ZZ

from ibme.core.randomness import SecureRandom


class SamplingAbort(RuntimeError):
    """The bounded uniform-integer rejection loop exhausted its attempts."""


def _int(value, name, *, minimum=None, maximum=None):
    if isinstance(value, bool) or not isinstance(value, (int, type(ZZ(0)))):
        raise ValueError(f"{name} must be an integer")
    value = int(value)
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} exceeds the reference resource limit {maximum}")
    return value


def _rational(value, name):
    # Do not silently interpret a binary float as an intended decimal parameter.
    if isinstance(value, bool) or not isinstance(value,
            (str, int, Fraction, type(QQ(0)), type(ZZ(0)))):
        raise ValueError(f"{name} requires an exact rational or rational string")
    try:
        return QQ(value)
    except (TypeError, ValueError, ZeroDivisionError) as exc:
        raise ValueError(f"Invalid exact rational {name}") from exc


def interval_bounds(value):
    """Exact rational endpoints, never QQ()'s approximate-real conversion."""
    return value.lower().exact_rational(), value.upper().exact_rational()


def interval_record(value):
    lower, upper = interval_bounds(value)
    return {"lower": str(lower), "upper": str(upper),
            "display": value.str(style="brackets")}


def draw_uniform_integer(rng, bound, *, max_trials=128):
    """Mask uniform bytes to bits, reject excess values; no modulo bias.

    With uniform independent bytes the failure probability is at most
    2^-max_trials. Conditional on success the returned integer is exactly uniform.
    This uses the repository's public read(n)->bytes randomness protocol.
    """
    bound = _int(bound, "bound", minimum=1)
    max_trials = _int(max_trials, "max_trials", minimum=1, maximum=4096)
    if not hasattr(rng, "read") or not callable(rng.read):
        raise ValueError("Random source must implement read(n)->bytes")
    bits = (bound - 1).bit_length()
    if bits == 0:
        return 0
    size, mask = (bits + 7) // 8, (1 << bits) - 1
    for _ in range(max_trials):
        data = rng.read(size)
        if not isinstance(data, (bytes, bytearray, memoryview)) or len(data) != size:
            raise ValueError("Random source returned an invalid byte count or type")
        value = int.from_bytes(data, "big") & mask
        if value < bound:
            return value
    raise SamplingAbort("Uniform-integer rejection limit reached")


@dataclass(frozen=True)
class GaussianTable:
    """Integer CDF with an explicit certificate against D_(a+hZ),s,c."""

    s: object
    center: object
    step: int
    residue: int
    tail_bits: int
    mass_bits: int
    precision_bits: int
    max_trials: int
    radius: int
    support: tuple[int, ...]
    masses: tuple[int, ...]
    cumulative: tuple[int, ...]
    relative_weight_lower: tuple
    relative_weight_upper: tuple
    tail_relative_upper: object
    quantization_tv_upper: object
    normalizer: object

    @property
    def total_mass(self):
        return self.cumulative[-1]

    @property
    def tail_tv_upper(self):
        # Relative weights use a nearest support point of weight one, so Z>=1.
        return min(QQ(1), self.tail_relative_upper)

    @property
    def abort_upper(self):
        return QQ(1) / (1 << self.max_trials)

    @property
    def tv_upper(self):
        return min(QQ(1), self.tail_tv_upper + self.quantization_tv_upper + self.abort_upper)

    def probability(self, value):
        try:
            i = self.support.index(value)
        except ValueError:
            return QQ(0)
        return QQ(self.masses[i]) / self.total_mass

    def sample(self, *, rng=None):
        rng = SecureRandom() if rng is None else rng
        ticket = draw_uniform_integer(rng, self.total_mass, max_trials=self.max_trials)
        return self.support[bisect_right(self.cumulative, ticket)]

    def config_record(self):
        return {"s": str(self.s), "center": str(self.center), "step": self.step,
                "residue": self.residue, "tail_bits": self.tail_bits,
                "mass_bits": self.mass_bits, "precision_bits": self.precision_bits,
                "max_trials": self.max_trials}

    def certificate(self):
        encoded = json.dumps({"config": self.config_record(), "support": self.support,
                              "masses": self.masses}, sort_keys=True, separators=(",", ":"))
        return {"config": self.config_record(), "support_range": [self.support[0], self.support[-1]],
                "support_count": len(self.support), "radius_in_index_space": self.radius,
                "zero_mass_points": sum(x == 0 for x in self.masses),
                "integer_total_mass": str(self.total_mass),
                "tail_tv_upper": str(self.tail_tv_upper),
                "quantization_and_interval_tv_upper": str(self.quantization_tv_upper),
                "random_rejection_abort_upper": str(self.abort_upper),
                "tv_upper_including_abort": str(self.tv_upper),
                "tv_upper_display": RealIntervalField(80)(self.tv_upper).str(style="brackets"),
                "infinite_unnormalized_mass_interval": interval_record(self.normalizer),
                "cdf_sha256": sha256(encoded.encode("utf-8")).hexdigest(),
                "security_claim": "none", "constant_time": False}


def build_gaussian_table(s, center=0, *, step=1, residue=0,
                         tail_bits=80, mass_bits=128, precision_bits=192,
                         max_trials=128, max_radius=512):
    """Construct certified finite weights exp(-pi*(x-c)^2/s^2).

    Interval pi/exp only: no symbolic-real or binary-float intermediates. Divide
    by the largest weight before integer quantization to avoid normalization
    underflow. Resource guards are part of this reference implementation's scope.
    """
    s, center = _rational(s, "s"), _rational(center, "center")
    step = _int(step, "step", minimum=1)
    residue = _int(residue, "residue") % step
    tail_bits = _int(tail_bits, "tail_bits", minimum=1, maximum=1024)
    mass_bits = _int(mass_bits, "mass_bits", minimum=1, maximum=2048)
    precision_bits = _int(precision_bits, "precision_bits", minimum=64, maximum=4096)
    max_trials = _int(max_trials, "max_trials", minimum=1, maximum=4096)
    max_radius = _int(max_radius, "max_radius", minimum=0, maximum=4096)
    if s <= 0 or not QQ(1)/64 <= s/step <= 64:
        raise ValueError("Reference scope requires 1/64 <= s/step <= 64")
    field = RealIntervalField(precision_bits)
    pi = field.pi()
    t = (center - residue) / step
    floor, ceil = int(t.floor()), int(t.ceil())
    closest = min((floor, ceil), key=lambda k: abs(residue + step*k - center))
    d0_squared = (residue + step*closest - center)**2

    def relative_weight(index):
        difference = (residue + step*index - center)**2 - d0_squared
        return (-pi * field(difference / s**2)).exp()

    def side_tail(first_index, distance_in_indices):
        ratio = (-pi * field(step**2 * (2*distance_in_indices + 1) / s**2)).exp()
        if interval_bounds(ratio)[1] >= 1:
            raise ValueError("Insufficient interval precision for geometric tail")
        return relative_weight(first_index) / (1 - ratio)

    tail_target = QQ(1) / (1 << tail_bits)
    for radius in range(max_radius + 1):
        low, high = floor - radius, ceil + radius
        left, right = low - 1, high + 1
        tails = side_tail(left, t-left) + side_tail(right, right-t)
        tail_upper = interval_bounds(tails)[1]
        if tail_upper <= tail_target:
            break
    else:
        raise ValueError("Tail target not achieved within max_radius")

    indices = range(low, high + 1)
    support = tuple(residue + step*k for k in indices)
    weights = [interval_bounds(relative_weight(k)) for k in indices]
    lowers, uppers = tuple(x[0] for x in weights), tuple(x[1] for x in weights)
    scale = 1 << mass_bits
    masses = tuple(int((scale*x).floor()) for x in lowers)
    total = sum(masses)
    if total <= 0:
        raise ValueError("Integer probability table has zero mass")
    lower_sum, upper_sum = sum(lowers, QQ(0)), sum(uppers, QQ(0))
    quant_tv = min(QQ(1), (upper_sum - QQ(total)/scale) / lower_sum)
    # Restore the true, infinite (unscaled) Gaussian partition function.
    pivot_weight = (-pi * field(d0_squared / s**2)).exp()
    normalizer = field(lower_sum, upper_sum + tail_upper) * pivot_weight
    return GaussianTable(s, center, step, residue, tail_bits, mass_bits, precision_bits,
        max_trials, radius, support, masses, tuple(accumulate(masses)), lowers, uppers,
        tail_upper, quant_tv, normalizer)


class PowerOfTwoGadgetSampler:
    """MP12 section 4.1 parity recurrence with certified finite-error scalar draws.

    Ideal parity recurrence is only approximately spherical Gaussian. The
    parity-normalizer ratio is explicitly included in the output TV certificate.
    """

    def __init__(self, q, s, **table_options):
        self.q = _int(q, "q", minimum=2)
        if self.q & (self.q-1):
            raise ValueError("This gadget reference supports q=2^k only")
        self.k = self.q.bit_length()-1
        if self.k > 32:
            raise ValueError("Reference gadget width limited to 32")
        self.tables = tuple(build_gaussian_table(s, step=2, residue=b, **table_options)
                            for b in (0, 1))

    def sample(self, syndrome, *, rng=None):
        syndrome = tuple(syndrome)
        if not syndrome or len(syndrome) > 128:
            raise ValueError("Syndrome dimension must be between 1 and 128")
        checked = [_int(u, "syndrome entry", minimum=0, maximum=self.q-1) for u in syndrome]
        rng = SecureRandom() if rng is None else rng
        out = []
        for u in checked:
            for _ in range(self.k):
                value = self.tables[u & 1].sample(rng=rng)
                out.append(value)
                u = (u-value)//2
        return tuple(out)

    def certificate(self, dimension=1):
        dimension = _int(dimension, "dimension", minimum=1, maximum=128)
        draws = dimension * self.k
        lower = min(interval_bounds(t.normalizer)[0] for t in self.tables)
        upper = max(interval_bounds(t.normalizer)[1] for t in self.tables)
        if lower <= 0:
            raise ValueError("Parity normalizer lower bound must be positive")
        ratio = upper/lower
        parity_bias = min(QQ(1), (ratio**draws-1)/2)
        scalar_error = min(QQ(1), draws*max(t.tv_upper for t in self.tables))
        total = min(QQ(1), parity_bias + scalar_error)
        return {"q": self.q, "n": dimension, "k": self.k,
                "s": str(self.tables[0].s), "scalar_draws_per_vector": draws,
                "parity_partition_ratio_upper": str(ratio),
                "ideal_parity_to_spherical_tv_upper": str(parity_bias),
                "finite_scalar_composition_tv_upper": str(scalar_error),
                "tv_upper_including_abort": str(total),
                "tv_upper_display": RealIntervalField(80)(total).str(style="brackets"),
                "bound_uniform_in_syndrome": True,
                "security_claim": "none", "constant_time": False}


def finite_gadget_distribution(sampler, syndrome, *, max_states=100000):
    """Exact PMF of ideal uniform-ticket CDF recurrence for one small block.

    Bounded random-draw aborts are excluded here and budgeted separately. This is
    not the actual gadget distribution conditional on surviving all random draws.
    """
    syndrome = _int(syndrome, "syndrome", minimum=0, maximum=sampler.q-1)
    support = sorted(set(sampler.tables[0].support) | set(sampler.tables[1].support))
    if len(support)**sampler.k > max_states:
        raise ValueError("Gadget enumeration exceeds max_states")
    distribution = {}
    for vector in product(support, repeat=sampler.k):
        u, probability = syndrome, QQ(1)
        for value in vector:
            if (u-value) & 1:
                probability = QQ(0)
                break
            probability *= sampler.tables[u & 1].probability(value)
            if probability == 0:
                break
            u = (u-value)//2
        if probability:
            distribution[vector] = probability
    return distribution
