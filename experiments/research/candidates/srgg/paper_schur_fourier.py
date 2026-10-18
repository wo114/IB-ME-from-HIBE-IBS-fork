"""Bounded interval Fourier realization of the paper's ring Schur steps.

This is the numerical alternative to the exact QQ reference, not a joint
SampleF replacement. Every Fourier Schur pivot/gain is enclosed before any
entropy is read. Gains are explicitly quantized to dyadic ring polynomials;
centers are rounded after each update. Those changes require an additional
distribution comparison: positivity and gain enclosures alone do not prove it.
"""
from dataclasses import dataclass, field

from sage.all import ComplexIntervalField, QQ

from .paper_samplef import _ldl_status, _negacyclic_spectrum, WitnessGeometryError
from .structured_geometry import StructuredGeometry


def fft(values, field, *, inverse=False):
    """Radix-two DFT with positive forward sign and normalized inverse."""
    data, n = list(values), len(values)
    if n < 2 or n & (n-1):
        raise ValueError("power-of-two Fourier length at least two required")
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            data[i], data[j] = data[j], data[i]
    real, length = field(0).real().parent(), 2
    while length <= n:
        angle = (-2 if inverse else 2)*real.pi()/length
        unit = field(angle.cos(), angle.sin())
        for start in range(0, n, length):
            factor = field(1)
            for k in range(length//2):
                left, right = data[start+k], factor*data[start+k+length//2]
                data[start+k], data[start+k+length//2] = left+right, left-right
                factor *= unit
        length *= 2
    return tuple(x/n for x in data) if inverse else tuple(data)


def forward(values, field):
    n, real = len(values), field(0).real().parent()
    angle = real.pi()/n
    twist, factor = field(angle.cos(), angle.sin()), field(1)
    data = []
    for value in values:
        data.append(field(value)*factor)
        factor *= twist
    return fft(data, field)


def inverse(values, field):
    n, real = len(values), field(0).real().parent()
    angle = -real.pi()/n
    twist, factor, data = field(angle.cos(), angle.sin()), field(1), []
    for value in fft(values, field, inverse=True):
        data.append(value*factor)
        factor *= twist
    return tuple(data)


def conjugate_extension(half):
    return tuple(half)+tuple(x.conjugate() for x in reversed(half))


def _midpoint(interval):
    low, high = (x.exact_rational() for x in interval.endpoints())
    return (low+high)/2


@dataclass(frozen=True, repr=False)
class FourierSchurStage:
    index: int
    pivot_spectrum: tuple = field(repr=False)
    gains: tuple = field(repr=False)

    def __repr__(self):
        return "FourierSchurStage(private_pivot_and_gains=<redacted>)"


class FourierSchurPlan:
    def __init__(self, geometry, *, precision_bits=768, dyadic_bits=256):
        if not isinstance(geometry, StructuredGeometry):
            raise ValueError("validated StructuredGeometry required")
        if (type(precision_bits) is not int or not 192 <= precision_bits <= 2048 or
                type(dyadic_bits) is not int or not 64 <= dyadic_bits <= 512 or
                precision_bits < dyadic_bits+64):
            raise ValueError("bounded Fourier precision with dyadic headroom required")
        g, n, rows = geometry, geometry.degree, geometry.upper_polynomials
        if n > 512 or rows > 16 or g.lower_polynomials > 16:
            raise ValueError("source-Schur resource limit exceeded")
        self.geometry, self.degree = g, n
        self.precision_bits, self.dyadic_bits = precision_bits, dyadic_bits
        self.field = cfield = ComplexIntervalField(precision_bits)
        spectra = [[_negacyclic_spectrum(poly, n, cfield) for poly in row] for row in g.witness]
        matrices = []
        for k in range(n//2):
            evaluated = [[entry[k] for entry in row] for row in spectra]
            # Check the ORIGINAL full residual Sigma_p-r^2 I. This licenses
            # Algorithm 1's rejection only on a certified negative direction.
            cols = g.lower_polynomials
            residual = g.top_squared+(g.lower_squared,)*cols
            gram = [[cfield(0) for _ in range(cols)] for _ in range(cols)]
            for i in range(cols):
                for j in range(i+1):
                    value = sum((row[i].conjugate()*row[j]/(residual[t]-g.rounding_squared)
                                 for t, row in enumerate(evaluated)), cfield(0))
                    if i == j:
                        value += 1/(g.lower_squared-g.rounding_squared)
                    gram[i][j] = g.noise_squared*value
                    gram[j][i] = gram[i][j].conjugate()
            status = _ldl_status(gram, 1, cfield)
            if status == "negative":
                raise WitnessGeometryError("source-Schur certified negative full residual direction")
            if status != "positive":
                raise ValueError("source-Schur residual interval inconclusive; no redraw")
            scale = g.noise_squared*g.lower_squared/g.lower_scalar
            current = [[cfield(int(i == j)*g.top_squared[i])-scale*sum(
                (evaluated[i][t]*evaluated[j][t].conjugate() for t in range(cols)), cfield(0))
                for j in range(rows)] for i in range(rows)]
            matrices.append(current)
        stages, grid, gain_error = [], 2**dyadic_bits, QQ(0)
        for index in reversed(range(rows)):
            pivots, gain_spectra = [], [[] for _ in range(index)]
            updated = []
            for current in matrices:
                pivot = current[index][index]
                if not pivot.imag().contains_zero():
                    raise ValueError("source-Schur Hermitian diagonal invariant failed")
                f = pivot.real()
                if (f-g.rounding_squared).lower() <= 0:
                    raise ValueError("source-Schur leaf rounding floor not certified; no redraw")
                pivots.append(f)
                gains = [current[i][index]/f for i in range(index)]
                for row, gain in zip(gain_spectra, gains):
                    row.append(gain)
                updated.append([[current[i][j]-gains[i]*current[index][j]
                                 for j in range(index)] for i in range(index)])
            gain_polys = []
            for spectrum in gain_spectra:
                coefficients = inverse(conjugate_extension(spectrum), cfield)
                rounded = []
                for coefficient in coefficients:
                    if not coefficient.imag().contains_zero():
                        raise ValueError("source-Schur real gain invariant failed")
                    value = QQ((_midpoint(coefficient.real())*grid+QQ(1)/2).floor())/grid
                    error = abs(coefficient.real()-value).upper().exact_rational()
                    gain_error = max(gain_error, error)
                    rounded.append(value)
                gain_polys.append(g._ring(rounded))
            stages.append(FourierSchurStage(index, tuple(pivots), tuple(gain_polys)))
            matrices = updated
        if gain_error > QQ(1)/2**128:
            raise ValueError("source-Schur gain enclosure misses the public precision target")
        self.stages, self.sampling_order = tuple(stages), tuple(reversed(range(rows)))
        self.output_order = tuple(range(rows))

    def __repr__(self):
        return "FourierSchurPlan(private_witness_and_plans=<redacted>)"

    def initial_center(self, lower):
        return self.geometry.conditioned_center(lower)

    def update_center(self, stage, centers, sampled):
        g, grid = self.geometry, 2**self.dyadic_bits
        if not any(stage is item for item in self.stages) or len(centers) != stage.index+1:
            raise ValueError("stage/center mismatch")
        delta = g._poly(sampled)-centers[-1]
        result = []
        for center, gain in zip(centers[:-1], stage.gains):
            value = (center+gain*delta) % g._modulus
            result.append(g._ring([QQ((value[i]*grid+QQ(1)/2).floor())/grid for i in range(g.degree)]))
        return tuple(result)

    def public_metadata(self):
        return {"method": "directed interval Fourier Schur; dyadic gains and adaptive centers",
                "degree": self.degree, "upper_polynomials": self.geometry.upper_polynomials,
                "lower_polynomials": self.geometry.lower_polynomials,
                "sampling_order": list(self.sampling_order), "output_order": list(self.output_order),
                "precision_bits": self.precision_bits,
                "dyadic_bits": self.dyadic_bits, "full_residual_positive_definiteness_certified": True,
                "gain_coefficient_absolute_error_upper": "1/"+str(2**128),
                "per_update_center_quantization_absolute_error_upper": "1/"+str(2**(self.dyadic_bits+1)),
                "witness_dependent_diagnostics_redacted": True, "dense_coefficient_matrix_materialized": False,
                "numerical_chain_to_exact_chain_tv_upper": None,
                "security_claim": "none", "parameters_are_formal": False, "backend_admitted": False}
