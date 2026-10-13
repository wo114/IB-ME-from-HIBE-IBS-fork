"""Numerical Peikert SampleF operations and polynomial-block Schur sampling.

The convention is exp(-pi*(x-c)^T*Sigma^-1*(x-c)); physical continuous
variance is Sigma/(2*pi). SampleF draws a continuous normal with shape
Sigma-r^2 I and then uses the existing finite D_Z,r sampler for randomized
integer rounding at EXACT QQ centers. Uniform midpoint tickets, Box--Muller,
and fixed-precision real factors approximate the continuous stage. Their
combined TV/precision error is NOT certified; no security admission follows.

sample_p is a generic last-polynomial-block-first Schur sampler using SampleF
at each leaf. The special isotropic p2 step of paper Algorithm 3 can instead
be drawn with sample_scalar_vector before sampling its upper Schur shape.
Plans and their shape/mean data are sensitive process-local state. Public
certificates deliberately omit private shapes, means, factors and samples.
"""
from copy import deepcopy
from dataclasses import dataclass
from fractions import Fraction
from functools import lru_cache
from math import isqrt, lcm
import re

from sage.all import QQ, ZZ, RealField, identity_matrix, matrix, vector

from ibme.core.errors import RandomnessError
from ibme.core.randomness import SecureRandom
from experiments.research.gaussian_reference import SamplingAbort
from experiments.research.online_gaussian_reference import OnlineOptions, OnlineScalarGaussian


@dataclass(frozen=True)
class FullSamplingOptions:
    precision_bits: int = 192
    ticket_bits: int = 128
    tail_bits: int = 24
    mass_bits: int = 64
    gaussian_abort_bits: int = 24
    max_uniform_trials: int = 64
    max_gaussian_trials: int = 100000
    max_radius: int = 2**30
    max_dimension: int = 128
    rational_bits: int = 8192
    max_coefficient_bits: int = 1024
    max_entropy_bytes: int = 256*1024*1024

    def __post_init__(self):
        limits = {
            "precision_bits": (96, 2048), "ticket_bits": (32, 512),
            "tail_bits": (8, 1024), "mass_bits": (32, 2048),
            "gaussian_abort_bits": (8, 1024), "max_uniform_trials": (1, 4096),
            "max_gaussian_trials": (1, 1000000), "max_radius": (1, 2**30),
            "max_dimension": (1, 128), "rational_bits": (128, 8192),
            "max_coefficient_bits": (16, 8192), "max_entropy_bytes": (1, 256*1024*1024),
        }
        for name, (low, high) in limits.items():
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError("invalid exact public full-sampling option: " + name)
        if self.precision_bits < self.ticket_bits+32 or self.precision_bits < self.mass_bits+32:
            raise ValueError("real/interval precision must exceed ticket and mass bits by 32")

    def online_options(self):
        return OnlineOptions(tail_bits=self.tail_bits, mass_bits=self.mass_bits,
            precision_bits=self.precision_bits, gaussian_abort_bits=self.gaussian_abort_bits,
            max_uniform_trials=self.max_uniform_trials, max_gaussian_trials=self.max_gaussian_trials,
            max_radius=self.max_radius, rational_bits=self.rational_bits,
            max_tape_bytes=self.max_entropy_bytes)


def _options(options):
    result = FullSamplingOptions() if options is None else options
    if not isinstance(result, FullSamplingOptions):
        raise TypeError("explicit FullSamplingOptions required")
    return result


def _rational(value, options):
    if isinstance(value, bool) or not isinstance(value, (int, Fraction, str, type(ZZ(0)), type(QQ(0)))):
        raise ValueError("bounded exact rational required")
    if isinstance(value, str):
        if len(value) > 2*options.rational_bits+4 or not re.fullmatch(r"[+-]?[0-9]+(?:/[0-9]+)?", value):
            raise ValueError("bounded plain integer/fraction text required")
    try:
        result = QQ(value)
    except (ValueError, TypeError, ZeroDivisionError) as exc:
        raise ValueError("invalid private exact rational") from exc
    if max(abs(int(result.numerator())).bit_length(), int(result.denominator()).bit_length()) > options.rational_bits:
        raise ValueError("private rational resource limit exceeded")
    return result


def _center(center, dimension, options):
    try:
        if isinstance(center, (str, bytes, bytearray, memoryview)) or len(center) != dimension:
            raise ValueError("exact finite mean-vector dimension required")
        return tuple(_rational(x, options) for x in center)
    except TypeError as exc:
        raise ValueError("exact finite mean-vector required") from exc


def _shape(covariance, options):
    if hasattr(covariance, "dimensions"):
        dimensions = covariance.dimensions()
        if len(dimensions) != 2 or dimensions[0] != dimensions[1] or not 1 <= dimensions[0] <= options.max_dimension:
            raise ValueError("private shape exceeds public dimension limit")
        rows = covariance.rows()
    elif isinstance(covariance, (list, tuple)):
        rows = covariance
    else:
        raise ValueError("finite exact square shape required")
    if not 1 <= len(rows) <= options.max_dimension:
        raise ValueError("private shape exceeds public dimension limit")
    dimension = len(rows)
    if any(len(row) != dimension for row in rows):
        raise ValueError("square shape required")
    result = matrix(QQ, [[_rational(x, options) for x in row] for row in rows])
    if result != result.transpose():
        raise ValueError("symmetric private shape required")
    result.set_immutable()
    return result


def _width(width_squared, options):
    width = _rational(width_squared, options)
    if not 1 <= width <= 10**12:
        raise ValueError("fixed integer-Gaussian width outside public online profile")
    return width


@lru_cache(maxsize=16)
def _scalar(width, options):
    # Only PUBLIC width/options are cached. Never cache a secret shape or mean.
    return OnlineScalarGaussian(width, width, options=options.online_options())


class _ByteBudget:
    __slots__ = ("_source", "_limit", "bytes_used")
    def __init__(self, rng, limit):
        self._source = SecureRandom() if rng is None else rng
        if not callable(getattr(self._source, "read", None)):
            raise RandomnessError("random source must provide read(n)")
        self._limit, self.bytes_used = limit, 0

    def read(self, size):
        if type(size) is not int or size < 0:
            raise RandomnessError("invalid entropy read size")
        if self.bytes_used+size > self._limit:
            raise SamplingAbort("full sampler entropy budget exhausted; no fallback")
        data = self._source.read(size)
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise RandomnessError("invalid entropy byte type")
        try:
            count = data.nbytes if isinstance(data, memoryview) else len(data)
            if count != size:
                raise RandomnessError("random source returned wrong byte count")
            raw = bytes(data)
        except (ValueError, TypeError) as exc:
            raise RandomnessError("invalid or released entropy view") from exc
        if len(raw) != size:
            raise RandomnessError("entropy byte count changed during conversion")
        self.bytes_used += size
        return raw


def _ldl(shape, options):
    """Exact LDL admission, before any real operation or entropy consumption."""
    dimension = shape.nrows()
    lower, diagonal = identity_matrix(QQ, dimension), []
    for i in range(dimension):
        pivot = _rational(shape[i, i]-sum(lower[i, k]**2*diagonal[k] for k in range(i)), options)
        if pivot <= 0:
            raise ValueError("leaf shape minus r^2 I must be strictly positive definite")
        diagonal.append(pivot)
        for j in range(i+1, dimension):
            lower[j, i] = _rational((shape[j, i]-sum(lower[j, k]*lower[i, k]*diagonal[k]
                                                   for k in range(i)))/pivot, options)
    lower.set_immutable()
    return lower, tuple(diagonal)


def _normal_tickets(dimension, field, options, source):
    """Two independent uniform midpoint tickets per Box--Muller pair."""
    size, bits, result = (options.ticket_bits+7)//8, options.ticket_bits, []
    for _ in range((dimension+1)//2):
        tickets = [int.from_bytes(source.read(size), "big") & ((1 << bits)-1) for _ in range(2)]
        u = field(QQ(2*tickets[0]+1)/2**(bits+1))
        v = field(QQ(2*tickets[1]+1)/2**(bits+1))
        radius = (-2*u.log()).sqrt()
        angle = 2*field.pi()*v
        result.extend((radius*angle.cos(), radius*angle.sin()))
    return tuple(result[:dimension])


def _ceil_sqrt(value):
    whole = int(QQ(value).ceil())
    root = isqrt(whole)
    return root+int(root*root < whole)


def _check_output_bound(bound, options):
    if abs(int(QQ(bound).ceil())).bit_length() > options.max_coefficient_bits:
        raise ValueError("all-path signed output resource bound exceeded")


def _mean_bound(offset, coefficients, output_bounds, bits):
    """Admit every exact affine mean over the bounded future integer draws."""
    denominator = int(offset.denominator())
    for coefficient in coefficients:
        denominator = lcm(denominator, int(coefficient.denominator()))
        if denominator.bit_length() > bits:
            raise ValueError("exact mean leaves insufficient numerical rational headroom")
    upper = abs(offset)+sum(abs(x)*bound for x, bound in zip(coefficients, output_bounds))
    numerator = abs(int((denominator*upper).ceil()))
    if denominator.bit_length() > bits or numerator.bit_length() > bits:
        raise ValueError("exact mean leaves insufficient numerical rational headroom")
    return upper


def _public_report(algorithm, dimension, block_size, width, options, scalar, tickets, budget):
    return {
        "algorithm": algorithm, "dimension": dimension, "block_size": block_size,
        "rounding_width_squared": str(width), "precision_bits": options.precision_bits,
        "ticket_bits": options.ticket_bits, "continuous_ticket_count": tickets,
        "public_entropy_upper_bytes": budget, "finite_uniform_grid": True,
        "continuous_stage_tv_certified": False, "real_precision_error_certified": False,
        "rounding_scalar_tv_upper_including_abort": str(scalar.tv_upper),
        "full_target_tv_upper_including_abort": None,
        "independent_uniform_bytes_assumed": True,
        "constant_time": False, "security_claim": "none", "backend_admitted": False,
    }


class _SampleFPlan:
    __slots__ = ("_options", "_dimension", "_center", "_width", "_scalar", "_factor", "_field",
                 "_noise_bounds", "_tickets", "_budget", "_report", "_mean_bits")

    def __init__(self, covariance, center, rounding_width_squared, options=None):
        self._options = options = _options(options)
        shape = _shape(covariance, options)
        self._dimension = dimension = shape.nrows()
        self._center = _center(center, dimension, options)
        self._width = width = _width(rounding_width_squared, options)
        self._scalar = scalar = _scalar(width, options)
        residual = shape-width*identity_matrix(QQ, dimension)
        lower, diagonal = _ldl(residual, options)
        self._field = field = RealField(options.precision_bits)
        # This is a high-precision Cholesky factor obtained from exact LDL.
        # Transform STANDARD normals, hence divide shape by 2*pi.
        self._factor = tuple(tuple(field(lower[i, j])*(field(diagonal[j])/(2*field.pi())).sqrt()
                                   for j in range(i+1)) for i in range(dimension))
        factor_denominator_bits = max(int(x.exact_rational().denominator()).bit_length()
                                      for row in self._factor for x in row)
        # An explicit conservative numerical-resource reserve, not a TV proof.
        # Keep room for the normal grid, real operations and dyadic addition.
        reserve = factor_denominator_bits+2*options.ticket_bits+(dimension+2)*options.precision_bits+32
        self._mean_bits = options.rational_bits-reserve
        if self._mean_bits < 16:
            raise ValueError("numerical factors exceed the rational resource reserve")
        for mean in self._center:
            _mean_bound(mean, (), (), self._mean_bits)
        # Midpoint uniforms imply bounded normal radius. This generous integer
        # envelope gates output size; it is not a bound on numerical TV error.
        self._noise_bounds = tuple(2*(options.ticket_bits+1)*dimension*_ceil_sqrt(residual[i, i])
                                  + scalar.radius+2 for i in range(dimension))
        for mean, bound in zip(self._center, self._noise_bounds):
            _check_output_bound(abs(mean)+bound, options)
        self._tickets = tickets = 2*((dimension+1)//2)
        self._budget = budget = tickets*((options.ticket_bits+7)//8)+dimension*scalar.random_tape_bytes
        if budget > options.max_entropy_bytes:
            raise ValueError("whole SampleF entropy upper bound exceeds public budget")
        self._report = _public_report("Peikert continuous Gaussian and fixed-width Gaussian rounding",
            dimension, dimension, width, options, scalar, tickets, budget)

    def __repr__(self):
        return "SampleFPlan(private_shape_and_mean=<redacted>, full_TV_certified=False)"

    def public_certificate(self):
        return deepcopy(self._report)

    def _draw(self, center, source):
        normal = _normal_tickets(self._dimension, self._field, self._options, source)
        output = []
        for i in range(self._dimension):
            try:
                shift = sum((coefficient*normal[j] for j, coefficient in enumerate(self._factor[i])),
                            self._field(0)).exact_rational()
                # Never put an exact large/rational mean through RealField.
                # Only the continuous displacement is converted to dyadic QQ.
                rounding_center = _rational(center[i]+shift, self._options)
            except (ValueError, TypeError, OverflowError) as exc:
                raise SamplingAbort("continuous arithmetic resource failure; no redraw") from exc
            value = int(self._scalar.sample(self._width, rounding_center, rng=source))
            if abs(value).bit_length() > self._options.max_coefficient_bits:
                raise SamplingAbort("signed output resource failure; no redraw")
            output.append(value)
        return tuple(output)

    def sample(self, *, rng=None):
        return self._draw(self._center, _ByteBudget(rng, self._budget))


class _SamplePPlan:
    __slots__ = ("_options", "_center", "_dimension", "_block_size", "_steps", "_budget", "_report")

    def __init__(self, covariance, center, block_size, rounding_width_squared, options=None):
        self._options = options = _options(options)
        shape = _shape(covariance, options)
        self._dimension = dimension = shape.nrows()
        if type(block_size) is not int or not 1 <= block_size <= dimension or dimension % block_size:
            raise ValueError("block_size must partition the coefficient dimension")
        self._block_size, self._center = block_size, _center(center, dimension, options)
        width = _width(rounding_width_squared, options)
        current, steps = shape, []
        offsets = vector(QQ, self._center)
        affine = matrix(QQ, dimension, dimension)
        output_bounds = [QQ(0)]*dimension
        # Prepare every Schur leaf and all private mean/output envelopes before
        # reading the LAST block's first ticket. No late shape admission.
        for end in range(dimension, 0, -block_size):
            start = end-block_size
            leaf_shape = current[start:end, start:end]
            leaf = _SampleFPlan(leaf_shape, (0,)*block_size, width, options)
            for j, noise in enumerate(leaf._noise_bounds):
                mean_upper = _mean_bound(offsets[start+j], tuple(affine.row(start+j)),
                                         output_bounds, leaf._mean_bits)
                output_bounds[start+j] = mean_upper+noise
                _check_output_bound(output_bounds[start+j], options)
            if start:
                cross = current[:start, start:end]
                update = cross*leaf_shape.inverse()
                upper = current[:start, :start]-update*cross.transpose()
                current = _shape(upper, options)
                for x in update.list():
                    _rational(x, options)
                # Symbolic QQ means c_head+K*(integer_block-c_block) admit all
                # future paths before drawing, including their denominators.
                offsets = offsets[:start]-update*offsets[start:end]
                affine = affine[:start, :]-update*affine[start:end, :]
                for i in range(start):
                    for j in range(block_size):
                        affine[i, start+j] += update[i, j]
                for x in tuple(offsets)+tuple(affine.list()):
                    _rational(x, options)
                update.set_immutable()
            else:
                update = None
            steps.append((start, end, leaf, update))
        self._steps = tuple(steps)
        self._budget = budget = sum(leaf._budget for _, _, leaf, _ in steps)
        if budget > options.max_entropy_bytes:
            raise ValueError("whole block sampler entropy upper bound exceeds public budget")
        tickets = sum(leaf._tickets for _, _, leaf, _ in steps)
        self._report = _public_report("last-polynomial-block-first Schur with SampleF leaves",
            dimension, block_size, width, options, steps[0][2]._scalar, tickets, budget)

    def __repr__(self):
        return "SamplePPlan(private_blocks_and_means=<redacted>, full_TV_certified=False)"

    def public_certificate(self):
        return deepcopy(self._report)

    def sample(self, *, rng=None):
        source = _ByteBudget(rng, self._budget)
        center, output = self._center, [0]*self._dimension
        for start, end, leaf, update in self._steps:
            drawn = leaf._draw(center[start:end], source)
            output[start:end] = drawn
            if start:
                residual = vector(QQ, [drawn[j]-center[start+j] for j in range(self._block_size)])
                shifted = vector(QQ, center[:start])+update*residual
                try:
                    center = tuple(_rational(x, self._options) for x in shifted)
                except ValueError as exc:
                    raise SamplingAbort("adaptive mean resource failure; no redraw") from exc
        return tuple(output)


def prepare_f(covariance, center, rounding_width_squared, *, options=None):
    return _SampleFPlan(covariance, center, rounding_width_squared, options)


def prepare_p(covariance, center, block_size, rounding_width_squared, *, options=None):
    return _SamplePPlan(covariance, center, block_size, rounding_width_squared, options)


def sample_f(covariance, center, rounding_width_squared, *, rng=None, options=None):
    return prepare_f(covariance, center, rounding_width_squared, options=options).sample(rng=rng)


def sample_p(covariance, center, block_size, rounding_width_squared, *, rng=None, options=None):
    return prepare_p(covariance, center, block_size, rounding_width_squared, options=options).sample(rng=rng)


def sample_scalar_vector(width_squared, center, *, rng=None, options=None):
    """Independent fixed-width integer Gaussian draws for p2 and signing u."""
    opts = _options(options)
    try:
        dimension = len(center)
    except TypeError as exc:
        raise ValueError("finite scalar-vector mean required") from exc
    if not 1 <= dimension <= opts.max_dimension:
        raise ValueError("scalar-vector dimension exceeds public limit")
    means, width = _center(center, dimension, opts), _width(width_squared, opts)
    scalar = _scalar(width, opts)
    for mean in means:
        _check_output_bound(abs(mean)+scalar.radius+1, opts)
    budget = dimension*scalar.random_tape_bytes
    if budget > opts.max_entropy_bytes:
        raise ValueError("scalar-vector entropy upper bound exceeds public budget")
    source = _ByteBudget(rng, budget)
    output = tuple(int(scalar.sample(width, mean, rng=source)) for mean in means)
    if any(abs(x).bit_length() > opts.max_coefficient_bits for x in output):
        raise SamplingAbort("scalar-vector output resource failure; no redraw")
    return output
