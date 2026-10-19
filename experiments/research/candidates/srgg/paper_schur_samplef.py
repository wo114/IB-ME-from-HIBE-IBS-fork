"""Original-order Algorithms 3--4 at Table 4 dimensions, finite arithmetic.

Discrete lower block, reverse ring Schur, continuous ring Gaussian, then
fixed-width discrete Gaussian rounding. The Fourier/dyadic approximation is
explicit and is NOT the previously certified joint law. Its complete TV bound
and comparison with the author's omitted sampling implementation remain open.
"""
from copy import deepcopy

from sage.all import ComplexField, QQ

from ibme.core.randomness import SecureRandom
from experiments.research.gaussian_reference import SamplingAbort
from .aggregate_budget import AggregateByteSource, batch_certificate
from .paper_schur_fourier import FourierSchurPlan, forward, inverse, conjugate_extension, _midpoint
from .structured_samplef import SeriesOptions
from .wide_scalar import WideScalarGaussian


class RingSampleF:
    """One ring leaf: FFT factor of f-r^2; finite Gaussian coefficient rounding."""
    def __init__(self, stage, geometry, options, scalar):
        self.geometry, self.options, self.scalar = geometry, options, scalar
        self.field = field = ComplexField(options.precision_bits)
        intervals = stage.pivot_spectrum[0].parent()
        factors = [((value-geometry.rounding_squared)/(2*intervals.pi())).sqrt()
                   for value in stage.pivot_spectrum]
        self.factors = tuple(field(_midpoint(value)) for value in factors)
        maximum = max(value.upper().exact_rational() for value in factors)
        # Conservative operational guard for every bounded normal ticket.
        # A runtime invariant failure aborts the call; it never redraws a root.
        self.noise_cap = 8*geometry.degree*(options.ticket_bits+1)*maximum+scalar.radius+2

    def __repr__(self):
        return "RingSampleF(private_shape_and_factor=<redacted>)"

    def factor_apply(self, coefficients):
        if len(coefficients) != self.geometry.degree:
            raise ValueError("ring coefficient dimension mismatch")
        transformed = forward(coefficients, self.field)
        factors = conjugate_extension(self.factors)
        return tuple(value.real() for value in inverse(
            tuple(x*f for x, f in zip(transformed, factors)), self.field))

    def draw(self, center, normal_source, rounding_source):
        n, opt, field = self.geometry.degree, self.options, self.field(0).real().parent()
        normal, size, bits = [], (opt.ticket_bits+7)//8, opt.ticket_bits
        for _ in range(n//2):
            tickets = [int.from_bytes(normal_source.read(size), "big") & ((1 << bits)-1) for _ in range(2)]
            u, v = (field(QQ(2*ticket+1)/2**(bits+1)) for ticket in tickets)
            radius, angle = (-2*u.log()).sqrt(), 2*field.pi()*v
            normal.extend((radius*angle.cos(), radius*angle.sin()))
        if any(abs(value) > 4*(bits+1) for value in normal):
            raise SamplingAbort("source-Schur normal ticket numerical invariant failed")
        shifts = self.factor_apply(normal)
        # Keep the exact affine mean outside RealField. Only the numerical
        # displacement is converted to an exact binary rational.
        centers = tuple(center[i]+shift.exact_rational() for i, shift in enumerate(shifts))
        for original, shifted in zip(center, centers):
            if abs(shifted-original)+self.scalar.radius+1 > self.noise_cap:
                raise SamplingAbort("source-Schur leaf numerical output invariant failed")
            self.scalar.checked_inputs(self.geometry.rounding_squared, shifted)
        return tuple(int(self.scalar.sample(self.geometry.rounding_squared, value, rng=rounding_source))
                     for value in centers)


class PaperSchurSampleF:
    def __init__(self, geometry, *, options=None, scalar_options=None):
        self.geometry = g = geometry
        self.options = opt = SeriesOptions() if options is None else options
        if not isinstance(opt, SeriesOptions):
            raise ValueError("explicit SeriesOptions required")
        self.dimension = (g.upper_polynomials+g.lower_polynomials)*g.degree
        if self.dimension > opt.max_dimension:
            raise ValueError("source-Schur coefficient dimension budget exceeded")
        self.plan = FourierSchurPlan(g, precision_bits=opt.precision_bits,
                                    dyadic_bits=opt.vector_dyadic_bits)
        self.lower_scalar = WideScalarGaussian(g.lower_scalar, g.lower_scalar, options=scalar_options)
        self.rounding_scalar = WideScalarGaussian(g.rounding_squared, g.rounding_squared, options=scalar_options)
        self.leaves = tuple(RingSampleF(stage, g, opt, self.rounding_scalar) for stage in self.plan.stages)
        self.lower_batch = batch_certificate(self.lower_scalar, g.lower_polynomials*g.degree,
            error_bits=opt.aggregate_abort_bits, max_bytes=opt.max_entropy_bytes)
        self.rounding_batch = batch_certificate(self.rounding_scalar, g.upper_polynomials*g.degree,
            error_bits=opt.aggregate_abort_bits, max_bytes=opt.max_entropy_bytes)
        self.ticket_bytes = g.upper_polynomials*g.degree*((opt.ticket_bits+7)//8)
        self.byte_cap = self.ticket_bytes+self.lower_batch["selected_cap_bytes"]+self.rounding_batch["selected_cap_bytes"]
        if not (self.lower_batch["admitted"] and self.rounding_batch["admitted"]) or self.byte_cap > opt.max_entropy_bytes:
            raise ValueError("source-Schur whole entropy budget exceeded")
        # Preflight an envelope over all possible successful draws. The lower
        # source is zero-centered. Later differences p_i-c_i have the leaf cap.
        lower_cap = self.lower_scalar.radius+1
        bounds = [abs(g.noise_squared/g.lower_scalar)*sum(
            sum(abs(c) for c in poly.list()) for poly in row)*lower_cap for row in g.witness]
        for stage, leaf in zip(self.plan.stages, self.leaves):
            total = bounds[-1]+leaf.noise_cap
            self.rounding_scalar.checked_inputs(g.rounding_squared, total)
            if int(total.ceil()+1).bit_length() > 240:
                raise ValueError("source-Schur all-path output exceeds the 256-bit object reserve")
            bounds = [bound+sum(abs(x) for x in gain.list())*leaf.noise_cap+QQ(1)/2**opt.vector_dyadic_bits
                      for bound, gain in zip(bounds[:-1], stage.gains)]
        self._certificate = {**self.plan.public_metadata(),
            "algorithm": "paper Algorithm 3 discrete p2, descending ring Schur, Algorithm 4 continuous plus discrete rounding",
            "dimension": self.dimension, "density_convention": "exp(-pi (x-c)^t Sigma^-1 (x-c)); covariance Sigma/(2*pi)",
            "lower_step_is_discrete_gaussian": True, "parameter_widths_changed": False,
            "continuous_leaf_mechanism": "midpoint Box-Muller, negacyclic Fourier square root, finite D_Z,r rounding",
            "algorithm4_d_symbol_interpreted_as_input_f": True,
            "lower_batch": self.lower_batch, "rounding_batch": self.rounding_batch,
            "continuous_fixed_ticket_bytes": self.ticket_bytes, "whole_entropy_cap_bytes": self.byte_cap,
            "fixed_witness_residual_positive_definiteness_certified": True,
            "finite_center_numerical_tv_upper": None, "full_target_integer_tv_upper_including_abort": None,
            "joint_sampler_law_certificate_reused": False, "author_sampler_bitwise_reproduction": False,
            "independent_uniform_bytes_assumed": True, "constant_time": False,
            "scope": "source control flow and finite functional implementation; complete numerical/Schur/fiber/signature laws remain separate"}

    def __repr__(self):
        return "PaperSchurSampleF(private_witness_centers_and_plans=<redacted>)"

    def public_certificate(self):
        return deepcopy(self._certificate)

    def sample(self, *, rng=None):
        g = self.geometry
        source = AggregateByteSource(SecureRandom() if rng is None else rng, self.byte_cap)
        lower_source = AggregateByteSource(source, self.lower_batch["selected_cap_bytes"])
        normal_source = AggregateByteSource(source, self.ticket_bytes)
        rounding_source = AggregateByteSource(source, self.rounding_batch["selected_cap_bytes"])
        lower = tuple(tuple(int(self.lower_scalar.sample(g.lower_scalar, 0, rng=lower_source))
                            for _ in range(g.degree)) for _ in range(g.lower_polynomials))
        centers, upper = self.plan.initial_center(lower), [None]*g.upper_polynomials
        for stage, leaf in zip(self.plan.stages, self.leaves):
            try:
                value = leaf.draw(centers[-1], normal_source, rounding_source)
                upper[stage.index] = value
                centers = self.plan.update_center(stage, centers, value)
            except (ValueError, OverflowError, ArithmeticError) as error:
                raise SamplingAbort("source-Schur arithmetic admission failed; no fallback or redraw") from error
        result = tuple(value for poly in tuple(upper)+lower for value in poly)
        if any(abs(value).bit_length() > 256 for value in result):
            raise SamplingAbort("source-Schur output object resource invariant failed")
        return result
