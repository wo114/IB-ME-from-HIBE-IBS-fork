"""Single-source finite scalar Gaussian for matrix algorithms.

Uniform-box rejection, exact rational centers and directed MPFI weights are
migrated from first_suite without changing the equations. Matrix and legacy
resource profiles are explicitly distinct. Broad support is represented by
integer endpoints, never a materialized table; defaults use system bytes.
Squared width is s^2 in exp(-pi*(x-c)^2/s^2), not statistical variance.
No security admission, native RNG or constant-time claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar
from fractions import Fraction
import re

from sage.all import QQ, ZZ, RealIntervalField

from ibme.core.randomness import SecureRandom
from experiments.research.gaussian_reference import SamplingAbort, draw_uniform_integer, interval_bounds
from experiments.research.mp12_sampled_reference import FiniteByteTape
from experiments.research.first_suite.entropy import CheckedEntropy


def exact_integer(value, name, *, minimum=0, maximum=2**32):
    if isinstance(value, bool) or not isinstance(value, (int, type(ZZ(0)))):
        raise ValueError(f"{name} must be an exact integer")
    result = int(value)
    if not minimum <= result <= maximum:
        raise ValueError(f"{name} outside resource range")
    return result


def exact_rational(value, name, *, max_bits=8192):
    if isinstance(value, bool) or not isinstance(value, (str, int, Fraction, type(QQ(0)), type(ZZ(0)))):
        raise ValueError(f"{name} must be an exact rational")
    if isinstance(value, str):
        # Bound text before QQ may interpret a gigantic decimal exponent.
        text = value.strip()
        fraction = re.fullmatch(r"[+-]?[0-9]+(?:/[0-9]+)?", text)
        decimal = re.fullmatch(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?", text)
        if len(value) > 2 * max_bits + 4 or not (fraction or decimal):
            raise ValueError(f"{name} requires bounded exact rational text")
        exponent = re.search(r"[eE]([+-]?[0-9]+)$", text)
        if exponent and (len(exponent[1].lstrip("+-")) > 6 or abs(int(exponent[1])) > max_bits):
            raise ValueError(f"{name} exponent exceeds the public rational bit budget")
    try:
        result = QQ(value)
    except (ValueError, TypeError, ZeroDivisionError) as exc:
        raise ValueError(f"Invalid {name}") from exc
    if max(abs(int(result.numerator())).bit_length(), int(result.denominator()).bit_length()) > max_bits:
        raise ValueError(f"{name} exceeds the public rational bit budget")
    return result


def interval_upper(value):
    # No artificial minimum: small values are enclosed by capped exp explicitly.
    return interval_bounds(value)[1]


def capped_exp_minus_pi(value, field, cap_bits):
    """Rigorous enclosure, with safe clipping before expensive huge exponents."""
    value = QQ(value)
    if value < 0:
        raise ValueError("Negative exponent argument")
    if value >= cap_bits:
        # pi > ln(2), so exp(-pi*value) <= 2^-cap_bits. Prevent MPFR
        # underflow endpoints from becoming rationals with billion-bit denominators.
        return field(0, QQ(1)/2**cap_bits)
    return (-field.pi()*field(value)).exp()


@dataclass(frozen=True)
class MatrixFiniteOptions:
    tail_bits: int = 128
    mass_bits: int = 256
    precision_bits: int = 320
    gaussian_abort_bits: int = 128
    max_uniform_trials: int = 192
    max_gaussian_trials: int = 100000
    max_radius: int = 2**112
    rational_bits: int = 65536
    max_tape_bytes: int = 2**44
    RADIUS_CAP: ClassVar[int] = 2**112
    RATIONAL_CAP: ClassVar[int] = 65536
    TAPE_CAP: ClassVar[int] = 2**44

    def __post_init__(self):
        ranges = {"tail_bits": (8, 1024), "mass_bits": (32, 2048),
            "precision_bits": (96, 4096), "gaussian_abort_bits": (8, 1024),
            "max_uniform_trials": (1, 4096), "max_gaussian_trials": (1, 1000000),
            "max_radius": (1, self.RADIUS_CAP), "rational_bits": (128, self.RATIONAL_CAP),
            "max_tape_bytes": (1, self.TAPE_CAP)}
        for name, (low, high) in ranges.items():
            object.__setattr__(self, name, exact_integer(getattr(self, name), name,
                minimum=low, maximum=high))


@dataclass(frozen=True)
class FirstFiniteOptions(MatrixFiniteOptions):
    """Compatibility profile with its original fixed bounds and field order."""
    max_radius: int = 2**48
    rational_bits: int = 8192
    max_tape_bytes: int = 2**40
    RADIUS_CAP: ClassVar[int] = 2**48
    RATIONAL_CAP: ClassVar[int] = 8192
    TAPE_CAP: ClassVar[int] = 2**40


class MatrixFiniteGaussian:
    """D_Z,s,c via a uniform-box proposal and interval-rounded Bernoulli.

    One public width class covers every rational center within its input bit
    budget. No support enumeration is used while constructing or sampling.
    """

    MAX_SQUARED_WIDTH = 2**192
    OPTIONS_TYPE = MatrixFiniteOptions
    PROFILE_ID = "MATRIX-FINITE-DGS/1"

    def __init__(self, width_min_squared, width_max_squared, *, options=None):
        self.options = self.OPTIONS_TYPE() if options is None else options
        if not isinstance(self.options, self.OPTIONS_TYPE):
            raise ValueError(f"Need {self.OPTIONS_TYPE.__name__}")
        self.v_min = exact_rational(width_min_squared, "minimum squared width", max_bits=self.options.rational_bits)
        self.v_max = exact_rational(width_max_squared, "maximum squared width", max_bits=self.options.rational_bits)
        if not 1 <= self.v_min <= self.v_max <= self.MAX_SQUARED_WIDTH:
            raise ValueError("Public squared widths exceed the explicitly selected finite profile")
        opts = self.options
        self.field = RealIntervalField(opts.precision_bits)
        self.cap_bits = max(opts.mass_bits, opts.tail_bits, opts.precision_bits)+64
        e = (opts.mass_bits-1).bit_length()
        if opts.precision_bits < e+24:
            raise ValueError("Insufficient precision for the uniform weight rounding budget")
        self.weight_width = QQ(2)**(e+8-opts.precision_bits)
        self.tail_target = QQ(1)/2**opts.tail_bits

        def tail_at(radius):
            a = capped_exp_minus_pi((QQ((radius+1)**2)-QQ(1)/4)/self.v_max,
                self.field, self.cap_bits)
            ratio = capped_exp_minus_pi(QQ(2*(radius+1)+1)/self.v_max,
                self.field, self.cap_bits)
            denominator = 1-ratio
            if interval_bounds(denominator)[0] <= 0:
                return None
            return interval_upper(2*a/denominator)

        # Monotone true geometric-tail bound, evaluated with enclosing intervals.
        # A final upper endpoint check is authoritative; no assumption that
        # finite-precision endpoints themselves are strictly monotone is needed.
        high = opts.max_radius
        tail = tail_at(high)
        if tail is None or tail > self.tail_target:
            raise ValueError("Public radius cannot certify the tail target")
        low = 0
        while low+1 < high:
            middle = (low+high)//2
            trial = tail_at(middle)
            if trial is not None and trial <= self.tail_target:
                high = middle
            else:
                low = middle
        self.radius = high
        self.tail_upper = tail_at(high)
        assert self.tail_upper is not None and self.tail_upper <= self.tail_target
        self.max_support_count = 2*high+2
        a = capped_exp_minus_pi(self.v_min, self.field, self.cap_bits)
        self.theta = interval_upper(2*a/(1-a**3))
        if not 0 <= self.theta < 1:
            raise ValueError("Poisson normalizer bound not certified")
        self.quantization_error = self.max_support_count*(self.weight_width+QQ(1)/2**opts.mass_bits)
        normalizer_min = interval_bounds(self.field(self.v_min).sqrt()*(1-self.field(self.theta)))[0]
        self.acceptance_mass_lower = max(QQ(1), normalizer_min-self.tail_upper-self.quantization_error)
        self.acceptance_probability_lower = self.acceptance_mass_lower/self.max_support_count
        if not 0 < self.acceptance_probability_lower <= 1:
            raise ValueError("Invalid uniform acceptance lower bound")
        ln2_upper = interval_upper(self.field(2).log())
        self.gaussian_trials = int((opts.gaussian_abort_bits*ln2_upper/self.acceptance_probability_lower).ceil())+1
        if self.gaussian_trials > opts.max_gaussian_trials:
            raise ValueError("Public Gaussian rejection budget insufficient")
        self.abort_upper = QQ(1)/2**opts.gaussian_abort_bits + self.gaussian_trials*QQ(1)/2**opts.max_uniform_trials
        self.tv_upper = min(QQ(1), self.tail_upper+self.quantization_error+self.abort_upper)
        self.bernoulli_bytes = (opts.mass_bits+7)//8
        self.candidate_bytes = ((self.max_support_count-1).bit_length()+7)//8
        self.random_tape_bytes = self.gaussian_trials*(opts.max_uniform_trials*self.candidate_bytes+self.bernoulli_bytes)
        if self.random_tape_bytes > opts.max_tape_bytes:
            raise ValueError("Public scalar tape exceeds resource budget")

    def checked_inputs(self, width_squared, center):
        width = exact_rational(width_squared, "squared width", max_bits=self.options.rational_bits)
        center = exact_rational(center, "center", max_bits=self.options.rational_bits)
        if not self.v_min <= width <= self.v_max:
            raise ValueError("Width outside the public class")
        shift = int(center.floor())
        fractional = center-shift
        closest = 0 if fractional <= QQ(1)/2 else 1
        low, high = -self.radius, self.radius+int(fractional != 0)
        return width, shift, fractional, closest, low, high

    def integer_weight(self, value, width, fractional, closest):
        argument = ((value-fractional)**2-(closest-fractional)**2)/width
        assert argument >= 0
        if argument >= self.options.mass_bits:
            return 0  # True relative weight <2^-b, already in quantization budget.
        weight = capped_exp_minus_pi(argument, self.field, self.cap_bits)
        lower = interval_bounds(weight)[0]
        mass = int((2**self.options.mass_bits*lower).floor())
        assert 0 <= mass <= 2**self.options.mass_bits
        return mass

    def sample(self, width_squared, center=0, *, rng=None):
        width, shift, fractional, closest, low, high = self.checked_inputs(width_squared, center)
        rng = CheckedEntropy(SecureRandom() if rng is None else rng, self.random_tape_bytes)
        for _ in range(self.gaussian_trials):
            value = low+draw_uniform_integer(rng, high-low+1,
                max_trials=self.options.max_uniform_trials)
            mass = self.integer_weight(value, width, fractional, closest)
            data = rng.read(self.bernoulli_bytes)
            if not isinstance(data, (bytes, bytearray, memoryview)) or len(data) != self.bernoulli_bytes:
                raise ValueError("Invalid Bernoulli random byte source")
            ticket = int.from_bytes(data, "big") & ((1 << self.options.mass_bits)-1)
            if ticket < mass:
                return shift+value
        raise SamplingAbort("Online Gaussian rejection budget exhausted; no retry or fallback")

    def sample_from_tape(self, width_squared, center, tape):
        self.checked_inputs(width_squared, center)
        source = FiniteByteTape(tape)
        if len(source.data) != self.random_tape_bytes:
            raise ValueError("Scalar tape must have the public fixed length")
        return self.sample(width_squared, center, rng=source)

    def finite_distribution(self, width_squared, center=0, *, max_points=4096):
        """Normalized integer weights; abort excluded, enumeration only for QA."""
        width, shift, fractional, closest, low, high = self.checked_inputs(width_squared, center)
        limit = exact_integer(max_points, "enumeration limit", minimum=1)
        if high-low+1 > limit:
            raise ValueError("Audit enumeration exceeds max_points")
        masses = {shift+x: self.integer_weight(x, width, fractional, closest) for x in range(low, high+1)}
        total = sum(masses.values())
        assert total > 0
        return {x: QQ(m)/total for x, m in masses.items() if m}

    def certificate(self):
        return {"profile": self.PROFILE_ID, "algorithm": "finite uniform-box rejection Gaussian, independent wide profile",
            "squared_width_class": [str(self.v_min), str(self.v_max)],
            "uniform_in_rational_center": True, "rational_input_bit_budget": self.options.rational_bits,
            "radius": self.radius, "max_support_count": self.max_support_count,
            "support_or_centers_precomputed": 0, "CDF_tables": 0,
            "tail_upper": str(self.tail_upper), "relative_weight_interval_width_upper": str(self.weight_width),
            "integer_weight_quantization_tv_upper": str(self.quantization_error),
            "Poisson_theta_upper": str(self.theta),
            "acceptance_mass_lower": str(self.acceptance_mass_lower),
            "acceptance_probability_lower": str(self.acceptance_probability_lower),
            "max_gaussian_trials": self.gaussian_trials, "abort_upper": str(self.abort_upper),
            "tv_upper_including_abort": str(self.tv_upper), "public_tape_bytes": self.random_tape_bytes,
            "tape_exhaustion_at_public_length_upper": "0", "finite_options": dict(self.options.__dict__),
            "rounding_assumption": "correctly-rounded directed rational conversion, pi, arithmetic and exp in MPFR/MPFI; exponents explicitly clipped before underflow",
            "randomness": "independent uniform bytes; fixed test seeds are not security evidence",
            "production_random_api": True, "native_Sage_rng_used": False, "constant_time": False, "security_claim": "none"}
