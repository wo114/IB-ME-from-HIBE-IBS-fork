"""Finite-error non-spherical perturbation and MP12 Algorithm 3 references.

Research only: exact rational geometry, certified scalar CDFs, variable time,
small-dimension/all-center resource caps. No TrapGen, IBS backend or security
level. The stated distribution bounds assume independent uniform source bytes.
Run in WSL conda ~/miniconda3/envs/sage with PYTHONPATH=src.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from math import lcm
from types import MappingProxyType
import json

from sage.all import GF, QQ, ZZ, RealIntervalField, identity_matrix, matrix, vector

from ibme.core.randomness import SecureRandom
from .gaussian_reference import (SamplingAbort, build_gaussian_table_squared,
    interval_bounds)
from .general_gadget_reference import (CenterFamily, GeneralModulusGadgetSampler,
    _exact_rational, _integer, finite_general_gadget_distribution)


TABLE_OPTIONS = {"tail_bits", "mass_bits", "precision_bits", "max_trials", "max_radius"}


def rational_matrix(value, name):
    """Check every entry before conversion; binary floats are not parameters."""
    try:
        rows = list(value.rows()) if hasattr(value, "rows") else list(value)
        checked = [[_exact_rational(x, name) for x in row] for row in rows]
    except (TypeError, AttributeError) as exc:
        raise ValueError(f"{name} must be a rectangular exact matrix") from exc
    if not checked or not checked[0] or any(len(row) != len(checked[0]) for row in checked):
        raise ValueError(f"{name} must be a nonempty rectangular matrix")
    if max(len(checked), len(checked[0])) > 16:
        raise ValueError(f"{name} exceeds the dimension resource limit 16")
    result = matrix(QQ, checked)
    result.set_immutable()
    return result


def psd_pivots(value, *, strict=False):
    """Exact rational Schur-complement certificate, including zero pivots.

    A zero diagonal in a PSD remainder must have a zero row. No rounded
    eigenvalues or silently accepted near-zero negative pivots are used.
    """
    value = rational_matrix(value, "symmetric matrix")
    if value.nrows() != value.ncols() or value != value.transpose():
        raise ValueError("Need a symmetric square matrix")
    work = matrix(QQ, value.nrows(), value.ncols(), value.list())
    pivots = []
    for i in range(value.nrows()):
        pivot = work[i, i]
        if pivot < 0 or (strict and pivot == 0):
            raise ValueError("Matrix is not positive definite" if strict else "Matrix is not positive semidefinite")
        if pivot == 0:
            if any(work[i, j] != 0 for j in range(i+1, value.nrows())):
                raise ValueError("Zero PSD pivot has a nonzero remaining row")
        else:
            for j in range(i+1, value.nrows()):
                for k in range(i+1, value.nrows()):
                    work[j, k] -= work[j, i]*work[i, k]/pivot
        pivots.append(pivot)
    return tuple(pivots)


def matrix_record(value):
    return [[str(x) for x in row] for row in value.rows()]


def outward_upper(value, *, precision_bits=192):
    """Compact dyadic upper endpoint; tiny positive values may be enlarged."""
    endpoint = RealIntervalField(precision_bits)(value).upper().exact_rational()
    return max(endpoint, QQ(1)/2**512) if endpoint > 0 else endpoint


def table_byte_bound(table):
    bits = (table.total_mass-1).bit_length()
    return table.max_trials*((bits+7)//8)


class FiniteByteTape:
    """Read a finite supplied tape without reseeding, expansion or fallback."""

    def __init__(self, data):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise ValueError("Random tape must be bytes")
        self.data, self.position = bytes(data), 0

    def read(self, size):
        size = _integer(size, "read size")
        if self.position+size > len(self.data):
            raise SamplingAbort("Finite random tape exhausted; no entropy fallback")
        result = self.data[self.position:self.position+size]
        self.position += size
        return result


class NonSphericalGaussianSampler:
    """Randomized nearest plane on Z^d in the exact inverse covariance metric.

    covariance is the squared Gaussian parameter C in exp(-pi*x^T*C^-1*x),
    not the probability covariance C/(2*pi). All possible integer-path center
    classes are admitted together. There is no continuous Gaussian/Cholesky
    precision assumption or reuse of sampled perturbations.
    """

    def __init__(self, covariance, *, max_center_classes=4096, **table_options):
        if set(table_options)-TABLE_OPTIONS:
            raise ValueError("Only finite-table options are supported")
        self.covariance = rational_matrix(covariance, "covariance")
        self.pivots = psd_pivots(self.covariance, strict=True)
        self.dimension = self.covariance.nrows()
        self.inverse = self.covariance.inverse()
        self.inverse.set_immutable()
        columns = list(identity_matrix(QQ, self.dimension).columns())
        orthogonal, norms = [], []
        mu = [[QQ(0)]*self.dimension for _ in range(self.dimension)]
        for j, column in enumerate(columns):
            current = column
            for i in range(j):
                mu[j][i] = (column*self.inverse*orthogonal[i])/norms[i]
                current = current-mu[j][i]*orthogonal[i]
            norm = current*self.inverse*current
            assert norm > 0
            current.set_immutable()
            orthogonal.append(current)
            norms.append(norm)
        self.orthogonal, self.norm_squared = tuple(orthogonal), tuple(norms)
        self.mu = tuple(tuple(row) for row in mu)
        denominators = tuple(lcm(1, *(int(mu[j][i].denominator())
            for j in range(i+1, self.dimension))) for i in range(self.dimension))
        maximum = _integer(max_center_classes, "max_center_classes", minimum=1, maximum=20000)
        if sum(denominators) > maximum:
            raise ValueError("All-center precomputation exceeds max_center_classes; no partial certificate")
        families = []
        for i, denominator in enumerate(denominators):
            tables = {QQ(j)/denominator: build_gaussian_table_squared(1/norms[i],
                QQ(j)/denominator, **table_options) for j in range(denominator)}
            lower = min(interval_bounds(t.normalizer)[0] for t in tables.values())
            upper = max(interval_bounds(t.normalizer)[1] for t in tables.values())
            if lower <= 0:
                raise ValueError("All-center normalizer lower bound must be positive")
            digest = sha256(json.dumps([(str(c), t.certificate()["cdf_sha256"])
                for c, t in tables.items()], separators=(",", ":")).encode()).hexdigest()
            families.append(CenterFamily(denominator, MappingProxyType(tables), lower,
                upper, max(t.tv_upper for t in tables.values()), digest))
        self.families, self.max_center_classes = tuple(families), maximum
        self.random_tape_bytes = sum(max(table_byte_bound(t) for t in f.tables.values())
            for f in self.families)
        config = self.families[0].tables[QQ(0)].config_record()
        self.table_options = {**{key: config[key] for key in
            ("tail_bits", "mass_bits", "precision_bits", "max_trials")},
            "max_radius": int(table_options.get("max_radius", 512))}

    def coordinate_table(self, index, later_coefficients):
        index = _integer(index, "coordinate index", maximum=self.dimension-1)
        later_coefficients = tuple(later_coefficients)
        if len(later_coefficients) != self.dimension-index-1:
            raise ValueError("Later coefficient dimensions do not match")
        checked = []
        for x in later_coefficients:
            if isinstance(x, bool) or not isinstance(x, (int, type(ZZ(0)))):
                raise ValueError("Later coefficients must be signed integers")
            checked.append(int(x))
        center = -sum((self.mu[j][index]*checked[j-index-1]
            for j in range(index+1, self.dimension)), QQ(0))
        shift = int(center.floor())
        fractional = center-shift
        assert (fractional*self.families[index].denominator).denominator() == 1
        return center, shift, self.families[index].tables[fractional]

    def sample(self, *, rng=None):
        rng = SecureRandom() if rng is None else rng
        coefficients = [0]*self.dimension
        for i in reversed(range(self.dimension)):
            _, shift, table = self.coordinate_table(i, coefficients[i+1:])
            coefficients[i] = shift+table.sample(rng=rng)
        return tuple(coefficients)

    def certificate(self):
        ratio = QQ(1)
        for f in self.families:
            ratio *= f.normalizer_upper/f.normalizer_lower
        nearest_plane = min(QQ(1), (ratio-1)/2)
        scalar = min(QQ(1), sum((f.max_scalar_tv for f in self.families), QQ(0)))
        abort = min(QQ(1), sum((max(t.abort_upper for t in f.tables.values())
            for f in self.families), QQ(0)))
        return {"dimension": self.dimension, "squared_parameter_matrix": matrix_record(self.covariance),
            "exact_spd_schur_pivots": [str(x) for x in self.pivots],
            "inverse_metric_gram_schmidt_squared_norms": [str(x) for x in self.norm_squared],
            "center_class_denominators": [f.denominator for f in self.families],
            "center_classes_checked": sum(f.denominator for f in self.families),
            "all_center_cdf_sha256": [f.cdf_digest for f in self.families],
            "center_families": [f.record(1/self.norm_squared[i])
                for i, f in enumerate(self.families)],
            "finite_table_options": self.table_options,
            "ideal_nearest_plane_to_nonspherical_tv_upper": str(outward_upper(nearest_plane)),
            "finite_scalar_composition_tv_upper": str(outward_upper(scalar)),
            "random_rejection_abort_upper": str(abort),
            "tv_upper_including_abort": str(outward_upper(min(QQ(1), nearest_plane+scalar))),
            "fixed_random_tape_bytes": self.random_tape_bytes,
            "uniform_in_all_integer_paths": True, "output_space_includes_abort": True,
            "max_center_classes": self.max_center_classes, "security_claim": "none", "constant_time": False}


def finite_nonspherical_distribution(sampler, *, max_states=100000):
    """Exact rational ideal-ticket PMF, with abort budgeted separately."""
    maximum = _integer(max_states, "max_states", minimum=1)
    law, coefficients, visited = {}, [0]*sampler.dimension, 0

    def visit(i, probability):
        nonlocal visited
        if i < 0:
            law[tuple(coefficients)] = probability
            return
        _, shift, table = sampler.coordinate_table(i, coefficients[i+1:])
        for value, mass in zip(table.support, table.masses):
            if not mass:
                continue
            visited += 1
            if visited > maximum:
                raise ValueError("Enumeration exceeds max_states; no partial PMF")
            coefficients[i] = shift+value
            visit(i-1, probability*QQ(mass)/table.total_mass)

    visit(sampler.dimension-1, QQ(1))
    return law


@dataclass(frozen=True)
class SampleDTrace:
    output: tuple[int, ...]
    perturbation: tuple[int, ...]
    gadget_preimage: tuple[int, ...]
    gadget_syndrome: tuple[int, ...]


class MP12SampleD:
    """MP12 Algorithm 3 for prime q, scalar Sigma and scalar Sigma_G.

    Trapdoor convention: A=[Abar | H*G-Abar*R], J=[R;I]. To sample for
    Foo-Li F=[A | A*R_id+G], supply Abar=A and R=-R_id. No key generation
    or uniformity claim is made for a caller-supplied Abar/R.
    """

    def __init__(self, q, a_bar, trapdoor, *, r_squared, sigma_squared,
                 gadget_covariance=5, max_center_classes=4096, **table_options):
        self.q = _integer(q, "q", minimum=2, maximum=2**32)
        if not ZZ(self.q).is_prime():
            raise ValueError("This project reference requires prime q")
        self.a_bar = rational_matrix(a_bar, "a_bar")
        self.trapdoor = rational_matrix(trapdoor, "trapdoor")
        if any(x.denominator() != 1 or not 0 <= x < self.q for x in self.a_bar.list()):
            raise ValueError("a_bar entries must be canonical integers in [0,q)")
        if any(x.denominator() != 1 for x in self.trapdoor.list()):
            raise ValueError("Trapdoor entries must be signed integers")
        self.n, self.m_bar = self.a_bar.dimensions()
        self.k = (self.q-1).bit_length()
        self.w, self.dimension = self.n*self.k, self.m_bar+self.n*self.k
        if self.dimension > 16 or self.trapdoor.dimensions() != (self.m_bar, self.w):
            raise ValueError("Trapdoor/gadget dimensions do not match or exceed limit 16")
        self.r_squared = _exact_rational(r_squared, "r_squared")
        self.sigma_squared = _exact_rational(sigma_squared, "sigma_squared")
        self.gadget_covariance = _exact_rational(gadget_covariance, "gadget_covariance")
        if self.r_squared <= 0 or self.sigma_squared <= 0 or self.gadget_covariance < 2:
            raise ValueError("Need positive widths and Sigma_G>=2*I")
        self.j = self.trapdoor.stack(identity_matrix(QQ, self.w))
        self.j.set_immutable()
        jjt = self.j*self.j.transpose()
        sigma = self.sigma_squared*identity_matrix(QQ, self.dimension)
        self.covariance_margin = sigma-(self.gadget_covariance+2)*jjt
        self.covariance_margin.set_immutable()
        self.margin_pivots = psd_pivots(self.covariance_margin)
        self.perturbation_covariance = sigma-self.gadget_covariance*jjt
        self.perturbation_covariance.set_immutable()
        psd_pivots(self.perturbation_covariance, strict=True)
        self.gadget = GeneralModulusGadgetSampler(self.q,
            self.r_squared*self.gadget_covariance, max_center_classes=max_center_classes,
            **table_options)
        precision = self.gadget.families[0].tables[QQ(0)].precision_bits
        field = RealIntervalField(precision)

        def smoothing_upper(width_over_gs_squared):
            a = (-field.pi()*field(width_over_gs_squared)).exp()
            denominator = 1-2*self.w*a
            if interval_bounds(denominator)[0] <= 0:
                raise ValueError("Smoothing condition not certified")
            return outward_upper(2*self.w*a/denominator, precision_bits=precision)

        self.epsilon_j = smoothing_upper(self.r_squared)
        self.epsilon_g = smoothing_upper(self.r_squared*self.gadget_covariance /
            max(self.gadget.geometry.norm_squared))
        self.epsilon = max(self.epsilon_j, self.epsilon_g)
        if not 0 < self.epsilon <= QQ(1)/2:
            raise ValueError("MP12 smoothing error must be certified <=1/2")
        self.perturbation = NonSphericalGaussianSampler(
            self.r_squared*self.perturbation_covariance,
            max_center_classes=max_center_classes, **table_options)
        self.g = matrix(ZZ, self.n, self.w)
        for b in range(self.n):
            for i in range(self.k):
                self.g[b, b*self.k+i] = (1 << i) % self.q
        self.g.set_immutable()
        gadget_bytes = self.n*sum(max(table_byte_bound(t) for t in f.tables.values())
            for f in self.gadget.families)
        self.required_tape_bytes = self.perturbation.random_tape_bytes+gadget_bytes
        # Every lower-quantized relative weight is <=2^mass_bits; every table
        # has at most 2*max_radius+2 support points. Allocate from PUBLIC table
        # configuration, not this key's CDF masses/center denominators. Thus a
        # fixed RO codomain can be used across all admitted keys of a stage.
        options = self.perturbation.table_options
        mass_upper = (1 << options["mass_bits"])*(2*options["max_radius"]+2)
        bytes_per_attempt = ((mass_upper-1).bit_length()+7)//8
        self.random_tape_bytes = (self.dimension+self.w)*options["max_trials"]*bytes_per_attempt
        assert self.required_tape_bytes <= self.random_tape_bytes
        if self.random_tape_bytes > 16*1024*1024:
            raise ValueError("Random tape exceeds 16 MiB reference resource limit")

    def _tag(self, tag):
        value = identity_matrix(QQ, self.n) if tag is None else rational_matrix(tag, "tag")
        if value.dimensions() != (self.n, self.n) or any(x.denominator() != 1 or
            not 0 <= x < self.q for x in value.list()):
            raise ValueError("Tag dimensions or canonical modular entries do not match")
        residue = matrix(GF(self.q), value)
        if not residue.is_invertible():
            raise ValueError("Tag must be invertible modulo q")
        return value, residue.inverse()

    def public_matrix(self, tag=None):
        tag, _ = self._tag(tag)
        result = self.a_bar.augment(tag*self.g-self.a_bar*self.trapdoor)
        result = matrix(ZZ, self.n, self.dimension, [ZZ(x) % self.q for x in result.list()])
        result.set_immutable()
        return result

    def sample_trace(self, syndrome, *, tag=None, rng=None):
        syndrome = tuple(syndrome)
        if len(syndrome) != self.n:
            raise ValueError("Syndrome dimension does not match")
        target = vector(ZZ, [_integer(x, "syndrome", maximum=self.q-1) for x in syndrome])
        _, tag_inverse = self._tag(tag)
        a = self.public_matrix(tag)
        rng = SecureRandom() if rng is None else rng
        p = vector(ZZ, self.perturbation.sample(rng=rng))
        v = tag_inverse*vector(GF(self.q), target-a*p)
        v = tuple(int(x) for x in v)
        z = self.gadget.sample(v, rng=rng)
        x = p+self.j*vector(ZZ, z)
        out = tuple(int(xi) for xi in x)
        assert tuple(int(xi) % self.q for xi in a*vector(ZZ, out)) == tuple(target)
        return SampleDTrace(out, tuple(int(xi) for xi in p), z, v)

    def sample(self, syndrome, *, tag=None, rng=None):
        return self.sample_trace(syndrome, tag=tag, rng=rng).output

    def sample_from_tape(self, syndrome, tape, *, tag=None):
        rng = FiniteByteTape(tape)
        if len(rng.data) != self.random_tape_bytes:
            raise ValueError("Tape length must equal the certified fixed length")
        return self.sample(syndrome, tag=tag, rng=rng)

    def certificate(self):
        p = self.perturbation.certificate()
        g = self.gadget.certificate(self.n)
        convolution = min(QQ(1), 4*self.epsilon/(1-self.epsilon)**2)
        total = min(QQ(1), convolution+QQ(p["tv_upper_including_abort"])+
            QQ(g["tv_upper_including_abort"]))
        abort = min(QQ(1), (self.dimension+self.w)*QQ(1)/
            2**self.perturbation.table_options["max_trials"])
        return {"algorithm": "MP12 Algorithm 3, finite reference adaptation",
            "q": self.q, "n": self.n, "m_bar": self.m_bar, "w": self.w,
            "output_dimension": self.dimension, "a_bar": matrix_record(self.a_bar),
            "trapdoor_R": matrix_record(self.trapdoor),
            "r_squared": str(self.r_squared), "Sigma_scalar": str(self.sigma_squared),
            "Sigma_G_scalar": str(self.gadget_covariance),
            "spherical_target_width_squared": str(self.r_squared*self.sigma_squared),
            "Sigma_p": matrix_record(self.perturbation_covariance),
            "Sigma_minus_J_2I_plus_SigmaG_JT": matrix_record(self.covariance_margin),
            "exact_psd_margin_schur_pivots": [str(x) for x in self.margin_pivots],
            "smoothing_epsilon_J_upper": str(self.epsilon_j),
            "smoothing_epsilon_G_upper": str(self.epsilon_g),
            "MP12_smoothing_epsilon_upper": str(self.epsilon),
            "ideal_MP12_convolution_tv_upper": str(outward_upper(convolution)),
            "perturbation": p,
            "gadget": {key: g[key] for key in ("center_classes_checked", "s_squared",
                "finite_table_options", "tv_upper_including_abort", "uniform_in_syndrome_and_all_integer_paths", "center_families")},
            "gadget_all_center_cdf_sha256": [f.cdf_digest for f in self.gadget.families],
            "tv_upper_including_abort": str(outward_upper(total)),
            "tv_upper_display": RealIntervalField(80)(total).str(style="brackets"),
            "random_rejection_abort_upper": str(abort),
            "fixed_random_tape_bytes": self.random_tape_bytes,
            "fixed_tape_bits": 8*self.random_tape_bytes,
            "required_tape_bytes_max_over_this_key_centers": self.required_tape_bytes,
            "tape_length_depends_only_on_public_dimensions_and_table_options": True,
            "tape_exhaustion_probability_at_certified_length": "0",
            "uniform_in_all_syndromes_and_invertible_tags": True,
            "trapdoor_scope": "every admitted fixed trapdoor with the recorded exact covariance/table certificate; no coverage of rejected geometries",
            "output_space_includes_abort": True, "zero_vector_policy": "not rejected; this is a Gaussian sampler, not an IBS verifier",
            "fresh_perturbation_per_call": True, "constant_time": False,
            "security_claim": "none", "randomness_assumption": "independent uniform bytes; fixed seeds used only in tests"}


def finite_sampled_distribution(sampler, syndrome, *, tag=None, max_states=100000):
    """Exact ideal-ticket full Algorithm 3 PMF for one small gadget block.

    Does not condition on rejection success. The abort coupling cost remains
    in the certificate; guards never return a partial probability law.
    """
    if sampler.n != 1:
        raise ValueError("Full PMF enumeration supports one gadget block only")
    if sampler.dimension > 4 or sampler.q > 17:
        raise ValueError("Full PMF enumeration requires dimension<=4 and q<=17")
    maximum = _integer(max_states, "max_states", minimum=1)
    target = _integer(syndrome, "syndrome", maximum=sampler.q-1)
    _, inverse = sampler._tag(tag)
    a = sampler.public_matrix(tag)
    p_law = finite_nonspherical_distribution(sampler.perturbation, max_states=maximum)
    z_laws = {u: finite_general_gadget_distribution(sampler.gadget, u, max_states=maximum)
        for u in range(sampler.q)}
    law, visited = {}, 0
    for p, p_probability in p_law.items():
        v = int((inverse*vector(GF(sampler.q), [target-(a*vector(ZZ, p))[0]]))[0])
        for z, z_probability in z_laws[v].items():
            visited += 1
            if visited > maximum:
                raise ValueError("Enumeration exceeds max_states; no partial PMF")
            x = tuple(int(xi) for xi in vector(ZZ, p)+sampler.j*vector(ZZ, z))
            law[x] = law.get(x, QQ(0))+p_probability*z_probability
    return law
