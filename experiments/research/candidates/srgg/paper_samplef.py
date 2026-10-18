"""Anisotropic SampleF at supplied SRGG paper shapes, without changing them.

All input shapes use density exp(-pi (x-c)^t Sigma^-1 (x-c)); their
continuous covariance is Sigma/(2*pi), NOT Sigma.  A caller interpreting
reported physical standard deviations must perform that conversion explicitly.
The fixed witness is checked once; this component never resamples a witness,
increases a width, or substitutes the old factor-two signature geometry.

For R=Sigma_p-r^2 I, start with rational L_i >= sqrt(target_i-r^2)
and optionally center its spectral interval by an exact rational rescaling.
Always R=L(I-H)L, H=I-L^-1 diag(target-r^2)L^-1+nu L^-1 T T* L^-1.
H products and the square-root series use exact rational negacyclic products.
Only n/2 small module Fourier Gram matrices use directed intervals.  They
certify a PRIVATE, witness-specific contraction; no n-by-n matrix is formed.
The finite sampler approximates D_(Z^D,Sigma_p,c), with the finite numerical,
rounding and scalar errors separately reported.  This is not a security proof.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, fields
from fractions import Fraction

from sage.all import ComplexIntervalField, QQ, RealField, RealIntervalField

from ibme.core.randomness import SecureRandom
from experiments.research.gaussian_reference import SamplingAbort
from .aggregate_budget import AggregateByteSource, batch_certificate
from .convolution_bridge import center_normalizer_certificate
from .psf_bridge import _upper
from .structured_geometry import StructuredGeometry
from .structured_samplef import SeriesOptions, _bounded, _fraction, series_certificate
from .wide_scalar import WideScalarGaussian


class WitnessGeometryError(ValueError):
    """The fixed witness has a certified nonpositive residual direction."""


@dataclass(frozen=True)
class PaperSeriesOptions(SeriesOptions):
    """Paper-only computation reserve; leaves the old optimization profile intact."""
    max_terms: int = 8192

    def __post_init__(self):
        _bounded(self.max_terms, "paper max_terms", 1, 8192)
        ordinary = {item.name: getattr(self, item.name) for item in fields(SeriesOptions)}
        ordinary["max_terms"] = min(self.max_terms, 1024)
        SeriesOptions(**ordinary)  # Reuse every other original exact resource gate.


def _ldl_status(gram, bound, field):
    """Certify positive/negative direction, or return genuinely inconclusive."""
    size, lower, pivots = len(gram), [], []
    for i in range(size):
        row = [field(0)]*size
        for j in range(i):
            value = -gram[i][j]
            for k in range(j):
                value -= row[k]*lower[j][k].conjugate()*pivots[k]
            row[j] = value/pivots[j]
        pivot = field(bound).real()-gram[i][i].real()
        for j in range(i):
            pivot -= abs(row[j])**2*pivots[j]
        if pivot.upper() < 0:
            return "negative"
        if pivot.lower() <= 0:
            return "inconclusive"
        row[i] = field(1)
        lower.append(row)
        pivots.append(pivot)
    return "positive"


def _negacyclic_spectrum(poly, degree, field):
    """Interval radix-two Fourier evaluation at exp(pi*i*(2k+1)/n)."""
    real = field.real_field()
    twist_angle = real.pi()/degree
    twist = field(twist_angle.cos(), twist_angle.sin())
    factor, data = field(1), []
    for i in range(degree):
        data.append(field(poly[i])*factor)
        factor *= twist
    j = 0
    for i in range(1, degree):
        bit = degree >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            data[i], data[j] = data[j], data[i]
    length = 2
    while length <= degree:
        angle = 2*real.pi()/length
        unit = field(angle.cos(), angle.sin())
        for start in range(0, degree, length):
            factor = field(1)
            for k in range(length//2):
                left, right = data[start+k], factor*data[start+k+length//2]
                data[start+k], data[start+k+length//2] = left+right, left-right
                factor *= unit
        length *= 2
    return data[:degree//2]


def _fourier_weighted_bound(geometry, diagonal, residual, precision):
    """Bound ||sqrt(nu) L^-1 T||^2 for this fixed private witness only."""
    g, n = geometry, geometry.degree
    field = ComplexIntervalField(precision)
    real = field.real_field()
    maximum = QQ(0)
    spectra = [[_negacyclic_spectrum(poly, n, field) for poly in row] for row in g.witness]
    # Real negacyclic operators have conjugate Fourier blocks with equal norm.
    for k in range(n//2):
        evaluated = [[poly[k] for poly in row] for row in spectra]
        columns = g.lower_polynomials
        gram = [[field(0) for _ in range(columns)] for _ in range(columns)]
        for i in range(columns):
            for j in range(i+1):
                value = sum((row[i].conjugate()*row[j]/diagonal[t]**2
                             for t, row in enumerate(evaluated)), field(0))
                if i == j:
                    value += 1/diagonal[g.upper_polynomials+i]**2
                gram[i][j] = g.noise_squared*value
                gram[j][i] = gram[i][j].conjugate()
        high = max(QQ((gram[i][i].real()+sum(
            (abs(gram[i][j]) for j in range(columns) if i != j), real(0))).upper())
                   for i in range(columns))
        # The Gershgorin bound is often sufficient. Tighten difficult fixed
        # witnesses with verified small-module LDL, not an unchecked eigensolver.
        if high > QQ(3)/4:
            low = QQ(0)
            for _ in range(20):
                middle = (low+high)/2
                if _ldl_status(gram, middle, field) == "positive":
                    high = middle
                else:
                    low = middle
        if high+max(1-value/scale**2 for value, scale in zip(residual, diagonal)) >= 1:
            # Failed upper bounds do not justify key rejection. Only an actual
            # negative direction for the ORIGINAL residual licenses that result.
            exact_gram = [[field(0) for _ in range(columns)] for _ in range(columns)]
            for i in range(columns):
                for j in range(i+1):
                    value = sum((row[i].conjugate()*row[j]/residual[t]
                                 for t, row in enumerate(evaluated)), field(0))
                    if i == j:
                        value += 1/residual[g.upper_polynomials+i]
                    exact_gram[i][j] = g.noise_squared*value
                    exact_gram[j][i] = exact_gram[i][j].conjugate()
            if _ldl_status(exact_gram, 1, field) == "negative":
                raise WitnessGeometryError("fixed witness has a certified negative Fourier residual direction")
        maximum = max(maximum, high)
    return maximum


class PaperSampleF:
    """Prepared sampler for an exact anisotropic shape and a fixed witness."""

    def __init__(self, geometry, *, center=None, options=None, scalar_options=None):
        if not isinstance(geometry, StructuredGeometry):
            raise ValueError("validated StructuredGeometry required")
        self.geometry = g = geometry
        self.options = opt = SeriesOptions() if options is None else options
        if not isinstance(opt, SeriesOptions):
            raise ValueError("explicit SeriesOptions required")
        self.dimension = dimension = (g.upper_polynomials+g.lower_polynomials)*g.degree
        _bounded(dimension, "coefficient dimension", 2, opt.max_dimension)
        self.width = g.rounding_squared
        residual = tuple(x-self.width for x in g.top_squared+(g.lower_squared,)*g.lower_polynomials)
        if min(residual) <= 0:
            raise WitnessGeometryError("fixed witness has a nonpositive residual diagonal")
        if self.width < 1:
            raise ValueError("density rounding shape>=1 required by this finite implementation")
        # Outward dyadic L is computational whitening, not a replacement shape.
        intervals = RealIntervalField(opt.precision_bits)
        grid = 2**opt.vector_dyadic_bits
        self.diagonal = tuple(QQ((QQ(intervals(value).sqrt().upper())*grid).ceil())/grid
                              for value in residual)
        self.diagonal_error = tuple(1-value/scale**2 for value, scale in zip(residual, self.diagonal))
        weighted = _fourier_weighted_bound(g, self.diagonal, residual, opt.precision_bits)
        rho = _fraction(max(self.diagonal_error)+weighted)
        if not 0 < rho < 1:
            raise ValueError("fixed witness contraction certificate inconclusive; no automatic redraw permitted")
        # Center the certified spectral interval with one EXACT rational
        # whitening rescaling. It changes neither R nor the Gaussian target.
        # Initially spec(H) is in [0,rho]. For q^2 approximately 1-rho/2,
        # spec(I-(I-H)/q^2) is bounded in absolute value by the expression below.
        # This halves the slow binomial tail near rho=1; no eigensolver or
        # additional cryptographic assumption is involved.
        if rho > Fraction(1, 2):
            q = QQ((QQ(intervals(1-QQ(rho.numerator)/rho.denominator/2).sqrt().upper())*grid).ceil())/grid
            q_squared = _fraction(q*q)
            rho = max(abs(1-1/q_squared), abs(1-(1-rho)/q_squared))
            self.diagonal = tuple(q*value for value in self.diagonal)
            self.diagonal_error = tuple(1-value/scale**2 for value, scale in zip(residual, self.diagonal))
        scale_interval = 1/(2*intervals.pi()).sqrt()
        lo, hi = (QQ(endpoint) for endpoint in scale_interval.endpoints())
        self.scale = (lo+hi)/2
        self.series = series_certificate(dimension=dimension, rho=rho,
            # sqrt(I-H) can now have norm sqrt(1+rho)<2. Doubling all
            # propagated error terms is a conservative lift of the old bound.
            scale_upper=2*_fraction(max(self.diagonal)*hi),
            scale_error=2*_fraction(max(self.diagonal)*(hi-lo)/2), options=opt)
        self.series["assumptions"][-1] = "verified ||H||<=rho<1, ||sqrt(I-H)||<2 and r>=1; Peikert continuous branch applies"
        self.terms = self.series["terms"]
        if self.terms*2*(g.upper_polynomials*g.lower_polynomials+g.lower_polynomials) > opt.max_ring_products:
            raise ValueError("anisotropic series ring-product work exceeds explicit budget")
        self.scalar = WideScalarGaussian(self.width, self.width, options=scalar_options)
        batch = batch_certificate(self.scalar, dimension, error_bits=opt.aggregate_abort_bits,
                                  max_bytes=opt.max_entropy_bytes)
        fixed_bytes = 2*((dimension+1)//2)*((opt.ticket_bits+7)//8)
        self.byte_cap = batch["selected_cap_bytes"]+fixed_bytes
        if not batch["admitted"] or self.byte_cap > opt.max_entropy_bytes:
            raise ValueError("whole anisotropic sampler entropy cap exceeds explicit budget")
        if center is None:
            center = (0,)*dimension
        if not isinstance(center, (tuple, list)) or len(center) != dimension:
            raise ValueError("exact coefficient center of full dimension required")
        self.center = tuple(QQ(_fraction(x).numerator)/_fraction(x).denominator for x in center)
        if any(max(abs(int(x.numerator())).bit_length(), int(x.denominator()).bit_length()) > opt.max_center_bits
               for x in self.center):
            raise ValueError("center exceeds exact rational-bit budget")
        self.noise_cap = 2*max(self.diagonal)*hi*(4*dimension*(opt.ticket_bits+1)+QQ(
            self.series["operator_vector_rounding_l2_error_upper"]))
        for x in self.center:
            den_bits = (int(x.denominator()).bit_length()+int(self.scale.denominator()).bit_length()
                        +max(int(t.denominator()).bit_length() for t in self.diagonal)
                        +opt.vector_dyadic_bits+2*self.terms)
            magnitude_bits = int((abs(x)+self.noise_cap).ceil()+1).bit_length()
            if den_bits+magnitude_bits+2 > self.scalar.options.rational_bits:
                raise ValueError("anisotropic center exceeds scalar rational reserve")
            self.scalar.checked_inputs(self.width, abs(x)+self.noise_cap)
        smooth = center_normalizer_certificate(dimension, _fraction(self.width), 80)
        epsilon = smooth["relative_error_upper_exact"]
        rounding_tv = Fraction(1) if epsilon is None or Fraction(epsilon) > Fraction(1, 2) else min(
            Fraction(1), 8*Fraction(epsilon))
        numerical = Fraction(self.series["finite_center_to_ideal_continuous_rounding_tv_upper"])
        # Do not export witness-dependent rho, series length or numerical TV.
        # The common coarse bound hides those private preparation diagnostics.
        public_numerical = Fraction(1, 2**96) if numerical <= Fraction(1, 2**96) else Fraction(1)
        total = _upper(public_numerical+Fraction(batch["scalar_kernel_tv_including_aggregate_exact"])+rounding_tv)
        self._certificate = {
            "algorithm": "anisotropic joint SampleF; rational whitening and exact ring sqrt series",
            "density_convention": "exp(-pi (x-c)^t Sigma^-1 (x-c)); covariance Sigma/(2*pi)",
            "degree": g.degree, "dimension": dimension,
            "target_top_squared": list(map(str, g.top_squared)),
            "target_lower_squared": str(g.lower_squared), "rounding_squared": str(self.width),
            "noise_squared": str(g.noise_squared), "parameter_widths_changed": False,
            "witness_redraws": 0, "witness_specific_spectral_plan": True,
            "witness_dependent_diagnostics_redacted": True,
            "fixed_witness_residual_positive_definiteness_certified": True,
            "finite_center_numerical_tv_upper": str(public_numerical),
            "finite_arithmetic_assumptions": deepcopy(self.series["assumptions"]),
            "spectral_method": "directed-interval negacyclic FFT; small Hermitian Gram Gershgorin/LDL",
            "scalar_batch": batch, "rounding_normalizer": smooth,
            "peikert_ideal_rounding_to_discrete_target_tv_upper": str(rounding_tv),
            "full_target_integer_tv_upper_including_abort": str(total),
            "reference": "D_(Z^D,Sigma_p,c), Sigma_p=diag(target)-noise T T*",
            "continuous_fixed_ticket_bytes": fixed_bytes,
            "whole_entropy_cap_bytes": self.byte_cap,
            "dense_coefficient_matrix_materialized": False,
            "legacy_sequential_schur_law_equal": False,
            "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False,
        }

    def __repr__(self):
        return "PaperSampleF(private_witness_center_and_plans=<redacted>)"

    def public_certificate(self):
        """No private Fourier norm, contraction, series count, center or witness."""
        return deepcopy(self._certificate)

    def h_apply(self, polynomials):
        g = self.geometry
        full = g._vector(polynomials, len(self.diagonal))
        whitened = tuple(poly/scale for poly, scale in zip(full, self.diagonal))
        gram = g.factor_apply(g.factor_adjoint_apply(whitened))
        return tuple(delta*x+g.noise_squared*y/scale for delta, x, y, scale in zip(
            self.diagonal_error, full, gram, self.diagonal))

    def sqrt_series_apply(self, polynomials):
        """Return sqrt(I-H)x approximately; diagonal L is applied separately."""
        g, n = self.geometry, self.geometry.degree
        current = g._vector(polynomials, len(self.diagonal))
        output = current
        coefficient, grid = QQ(1)/2, 2**self.options.vector_dyadic_bits
        for term in range(1, self.terms+1):
            applied = self.h_apply(current)
            current = tuple(g._ring([QQ((value[i]*grid+QQ(1)/2).floor())/grid for i in range(n)])
                            for value in applied)
            output = tuple(x-coefficient*y for x, y in zip(output, current))
            coefficient *= QQ(2*term-1)/(2*(term+1))
        return output

    def residual_factor_apply(self, polynomials):
        return tuple(scale*poly for scale, poly in zip(self.diagonal, self.sqrt_series_apply(polynomials)))

    def sample(self, *, rng=None):
        source = AggregateByteSource(SecureRandom() if rng is None else rng, self.byte_cap)
        field, opt = RealField(self.options.precision_bits), self.options
        size, bits = (opt.ticket_bits+7)//8, opt.ticket_bits
        normal = []
        for _ in range((self.dimension+1)//2):
            tickets = [int.from_bytes(source.read(size), "big") & ((1 << bits)-1) for _ in range(2)]
            u, v = (field(QQ(2*ticket+1)/2**(bits+1)) for ticket in tickets)
            radius, angle = (-2*u.log()).sqrt(), 2*field.pi()*v
            normal.extend((radius*angle.cos(), radius*angle.sin()))
        if any(abs(x) > 4*(bits+1) for x in normal):
            raise SamplingAbort("Box-Muller numerical invariant failed")
        n, grid = self.geometry.degree, 2**opt.vector_dyadic_bits
        polynomials = tuple(self.geometry._ring([QQ((x.exact_rational()*grid+QQ(1)/2).floor())/grid
                            for x in normal[i:i+n]]) for i in range(0, self.dimension, n))
        transformed = self.residual_factor_apply(polynomials)
        centers = tuple(mean+self.scale*poly[i] for poly, means in zip(transformed,
                        (self.center[j:j+n] for j in range(0, self.dimension, n)))
                        for i, mean in enumerate(means))
        for original, shifted in zip(self.center, centers):
            if abs(shifted-original) > self.noise_cap:
                raise SamplingAbort("anisotropic all-path output invariant failed")
            self.scalar.checked_inputs(self.width, shifted)
        return tuple(int(self.scalar.sample(self.width, center, rng=source)) for center in centers)
