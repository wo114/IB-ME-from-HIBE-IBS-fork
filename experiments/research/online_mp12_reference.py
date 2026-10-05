"""Online GPV gadget/perturbation and full MP12 reference, no center tables.

Exact rational geometry; bounded online scalar rejection; public stage tapes.
Research only, variable time, no IBS/HIBE backend or security level. Run in WSL
conda ~/miniconda3/envs/sage with PYTHONPATH=src.
"""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from math import lcm

from sage.all import GF, QQ, ZZ, identity_matrix, matrix, vector

from ibme.core.randomness import SecureRandom
from .general_gadget_reference import gadget_basis
from .mp12_sampled_reference import FiniteByteTape, SampleDTrace, matrix_record
from .mp12_trapdoor_chain import GeneratedTrapdoor, DelegatedTrapdoor
from .online_gaussian_reference import (OnlineOptions, OnlineScalarGaussian,
    capped_exp_minus_pi, exact_integer, exact_rational, interval_upper)
from .gaussian_reference import draw_uniform_integer, interval_bounds


MAX_DIMENSION = 128


def exact_matrix(value, name):
    try:
        rows = list(value.rows()) if hasattr(value, "rows") else list(value)
        checked = [[exact_rational(x, name) for x in row] for row in rows]
    except (TypeError, AttributeError) as exc:
        raise ValueError(f"Invalid {name}") from exc
    if not checked or not checked[0] or any(len(row) != len(checked[0]) for row in checked):
        raise ValueError("Need a nonempty rectangular matrix")
    if max(len(checked), len(checked[0])) > MAX_DIMENSION:
        raise ValueError("Matrix exceeds dimension cap 128")
    result = matrix(QQ, checked)
    result.set_immutable()
    return result


def exact_psd_pivots(value, *, strict=False):
    value = exact_matrix(value, "symmetric matrix")
    if value.nrows() != value.ncols() or value != value.transpose():
        raise ValueError("Need a symmetric square matrix")
    work = matrix(QQ, value.nrows(), value.ncols(), value.list())
    pivots = []
    for i in range(value.nrows()):
        pivot = work[i, i]
        if pivot < 0 or (strict and pivot == 0):
            raise ValueError("Matrix not PSD/SPD")
        if pivot == 0:
            if any(work[i, j] for j in range(i+1, value.nrows())):
                raise ValueError("Zero PSD pivot has nonzero row")
        else:
            for j in range(i+1, value.nrows()):
                for k in range(i+1, value.nrows()):
                    work[j, k] -= work[j, i]*work[i, k]/pivot
        pivots.append(pivot)
    return tuple(pivots)


def modular_matrix(value, q, shape, name):
    value = exact_matrix(value, name)
    if value.dimensions() != shape or any(x.denominator() != 1 or not 0 <= x < q for x in value.list()):
        raise ValueError(f"Invalid canonical modular {name}")
    result = matrix(ZZ, value)
    result.set_immutable()
    return result


def tag_matrix(tag, q, n):
    value = modular_matrix(identity_matrix(ZZ, n) if tag is None else tag, q, (n, n), "tag")
    if not matrix(GF(q), value).is_invertible():
        raise ValueError("Tag is singular modulo q")
    return value


def path_resource_bounds(mu, offset, target_max, radius, rational_bits):
    """Bound every possible later coefficient before any sampling starts.

    Centers have denominators dividing a known LCM. Absolute coefficients obey
    a backwards deterministic finite-support recurrence, so numerator bounds
    can be admitted without enumerating paths or fractional center classes.
    """
    dimension = len(mu)
    coefficients = [0]*dimension
    denominators, numerator_bits = [0]*dimension, [0]*dimension
    for i in reversed(range(dimension)):
        denominator = lcm(int(offset[i].denominator()),
            *(int(mu[j][i].denominator()) for j in range(i+1, dimension)))
        center_bound = abs(offset[i])*target_max+sum((abs(mu[j][i])*coefficients[j]
            for j in range(i+1, dimension)), QQ(0))
        numer_bound = denominator*(int(center_bound.ceil())+1)
        bits = int(numer_bound).bit_length()
        if max(int(denominator).bit_length(), bits) > rational_bits:
            raise ValueError("All-path rational center resource bound exceeds public budget")
        coefficients[i] = int(center_bound.ceil())+radius+2
        denominators[i], numerator_bits[i] = denominator, bits
    return {"center_denominators": denominators, "max_center_numerator_bits": max(numerator_bits),
        "max_center_denominator_bits": max(int(x).bit_length() for x in denominators),
        "integer_coefficient_absolute_bounds": coefficients,
        "all_finite_sampler_paths_admitted": True, "center_classes_precomputed": 0}


def nearest_plane_bound(scalar, draws):
    # Directed intervals give a compact upper endpoint, rather than a huge
    # rational powered denominator. Extra enclosure error is conservative.
    theta = scalar.field(scalar.theta)
    return max(QQ(0), min(QQ(1), interval_upper((((1+theta)/(1-theta))**draws-1)/2)))


def public_tape_guard(size, options):
    if size > options.max_tape_bytes:
        raise ValueError("Public vector tape exceeds resource budget")
    return size


class OnlineGadgetSampler:
    def __init__(self, q, s_squared, *, options=None, order="forward"):
        self.geometry = gadget_basis(q, order=order)
        self.q, self.k = self.geometry.q, self.geometry.k
        self.s_squared = exact_rational(s_squared, "gadget squared width")
        widths = [self.s_squared/x for x in self.geometry.norm_squared]
        self.scalar = OnlineScalarGaussian(min(widths), max(widths), options=options)
        self.widths = tuple(widths)
        self.resources = path_resource_bounds(self.geometry.mu, self.geometry.offset_projection,
            self.q-1, self.scalar.radius, self.scalar.options.rational_bits)
        self.random_tape_bytes = public_tape_guard(self.k*self.scalar.random_tape_bytes, self.scalar.options)

    def center(self, index, syndrome, later):
        index = exact_integer(index, "coordinate", maximum=self.k-1)
        syndrome = exact_integer(syndrome, "syndrome", maximum=self.q-1)
        later = tuple(later)
        if len(later) != self.k-index-1:
            raise ValueError("Later coefficient dimensions mismatch")
        if any(isinstance(x, bool) or not isinstance(x, (int, type(ZZ(0)))) for x in later):
            raise ValueError("Later coefficients must be signed integers")
        return -(syndrome*self.geometry.offset_projection[index]+sum((self.geometry.mu[j][index]*later[j-index-1]
            for j in range(index+1, self.k)), QQ(0)))

    def sample(self, syndrome, *, rng=None):
        targets = tuple(syndrome)
        if not 1 <= len(targets) <= MAX_DIMENSION:
            raise ValueError("Syndrome dimension outside reference range")
        targets = [exact_integer(x, "syndrome", maximum=self.q-1) for x in targets]
        public_tape_guard(len(targets)*self.random_tape_bytes, self.scalar.options)
        rng = SecureRandom() if rng is None else rng
        output = []
        for target in targets:
            coefficients = [0]*self.k
            for i in reversed(range(self.k)):
                coefficients[i] = self.scalar.sample(self.widths[i], self.center(i, target, coefficients[i+1:]), rng=rng)
            out = self.geometry.basis*vector(ZZ, coefficients)
            out[0] += target
            output.extend(int(x) for x in out)
        return tuple(output)

    def sample_from_tape(self, syndrome, tape):
        targets = tuple(syndrome)
        if not 1 <= len(targets) <= MAX_DIMENSION:
            raise ValueError("Invalid syndrome dimension")
        for target in targets:
            exact_integer(target, "syndrome", maximum=self.q-1)
        source = FiniteByteTape(tape)
        length = public_tape_guard(len(targets)*self.random_tape_bytes, self.scalar.options)
        if len(source.data) != length:
            raise ValueError("Gadget tape must have the public fixed length")
        return self.sample(targets, rng=source)

    def certificate(self, dimension=1):
        dimension = exact_integer(dimension, "dimension", minimum=1, maximum=MAX_DIMENSION)
        draws = dimension*self.k
        nearest = nearest_plane_bound(self.scalar, draws)
        error = min(QQ(1), draws*self.scalar.tv_upper)
        return {"q": self.q, "n": dimension, "k": self.k, "s_squared": str(self.s_squared),
            "squared_coordinate_widths": [str(x) for x in self.widths],
            "basis": self.geometry.record(), "path_resources": deepcopy(self.resources),
            "scalar": self.scalar.certificate(), "scalar_draws_per_vector": draws,
            "ideal_nearest_plane_to_spherical_tv_upper": str(nearest),
            "finite_scalar_composition_tv_upper": str(error),
            "tv_upper_including_abort": str(min(QQ(1), interval_upper(self.scalar.field(nearest+error)))),
            "uniform_in_all_syndromes_and_integer_paths": True,
            "centers_or_CDFs_precomputed": 0,
            "public_tape_bytes": public_tape_guard(dimension*self.random_tape_bytes, self.scalar.options),
            "security_claim": "none", "constant_time": False}


class OnlineNonSphericalSampler:
    def __init__(self, covariance, scalar):
        if not isinstance(scalar, OnlineScalarGaussian):
            raise ValueError("Need a public scalar class")
        self.scalar = scalar
        self.covariance = exact_matrix(covariance, "covariance")
        self.dimension = self.covariance.nrows()
        self.pivots = exact_psd_pivots(self.covariance, strict=True)
        eye = identity_matrix(QQ, self.dimension)
        exact_psd_pivots(self.covariance-scalar.v_min*eye)
        exact_psd_pivots(scalar.v_max*eye-self.covariance)
        self.inverse = self.covariance.inverse()
        self.inverse.set_immutable()
        orthogonal, norms = [], []
        mu = [[QQ(0)]*self.dimension for _ in range(self.dimension)]
        for j, e in enumerate(eye.columns()):
            current = e
            for i in range(j):
                # Exact LDL/Gram recurrence avoids repeated dense metric
                # matrix-vector products. Same geometry, cubic arithmetic.
                mu[j][i] = (self.inverse[j, i]-sum((mu[j][k]*mu[i][k]*norms[k]
                    for k in range(i)), QQ(0)))/norms[i]
                current -= mu[j][i]*orthogonal[i]
            norm = self.inverse[j, j]-sum((mu[j][k]**2*norms[k] for k in range(j)), QQ(0))
            assert norm > 0 and scalar.v_min <= 1/norm <= scalar.v_max
            exact_rational(1/norm, "coordinate squared width", max_bits=scalar.options.rational_bits)
            current.set_immutable()
            orthogonal.append(current)
            norms.append(norm)
        self.mu, self.norm_squared = tuple(tuple(x) for x in mu), tuple(norms)
        self.orthogonal = tuple(orthogonal)
        self.resources = path_resource_bounds(self.mu, (QQ(0),)*self.dimension, 0,
            scalar.radius, scalar.options.rational_bits)
        self.random_tape_bytes = public_tape_guard(self.dimension*scalar.random_tape_bytes, scalar.options)

    def center(self, index, later):
        index = exact_integer(index, "coordinate", maximum=self.dimension-1)
        later = tuple(later)
        if len(later) != self.dimension-index-1:
            raise ValueError("Later coefficient dimensions mismatch")
        if any(isinstance(x, bool) or not isinstance(x, (int, type(ZZ(0)))) for x in later):
            raise ValueError("Later coefficients must be signed integers")
        return -sum((self.mu[j][index]*later[j-index-1]
            for j in range(index+1, self.dimension)), QQ(0))

    def sample(self, *, rng=None):
        rng = SecureRandom() if rng is None else rng
        coefficients = [0]*self.dimension
        for i in reversed(range(self.dimension)):
            coefficients[i] = self.scalar.sample(1/self.norm_squared[i], self.center(i, coefficients[i+1:]), rng=rng)
        return tuple(coefficients)

    def certificate(self):
        nearest = nearest_plane_bound(self.scalar, self.dimension)
        error = min(QQ(1), self.dimension*self.scalar.tv_upper)
        return {"dimension": self.dimension, "squared_parameter_matrix": matrix_record(self.covariance),
            "inverse_metric_gram_schmidt_squared_norms": [str(x) for x in self.norm_squared],
            "path_resources": deepcopy(self.resources), "scalar": self.scalar.certificate(),
            "ideal_nearest_plane_to_nonspherical_tv_upper": str(nearest),
            "finite_scalar_composition_tv_upper": str(error),
            "tv_upper_including_abort": str(min(QQ(1), interval_upper(self.scalar.field(nearest+error)))),
            "public_tape_bytes": self.random_tape_bytes, "centers_or_CDFs_precomputed": 0,
            "uniform_in_all_integer_paths": True, "security_claim": "none", "constant_time": False}


class OnlineMP12SampleD:
    """Complete MP12 Algorithm 3 using online Gaussian conditional kernels."""

    def __init__(self, q, a_bar, trapdoor, *, r_squared, sigma_squared,
            perturbation_scalar, gadget_covariance=5):
        self.q = exact_integer(q, "q", minimum=2)
        if not ZZ(self.q).is_prime():
            raise ValueError("Need prime q")
        self.a_bar, self.trapdoor = exact_matrix(a_bar, "base"), exact_matrix(trapdoor, "trapdoor")
        if any(x.denominator() != 1 or not 0 <= x < self.q for x in self.a_bar.list()):
            raise ValueError("Base must use canonical modular integers")
        if any(x.denominator() != 1 for x in self.trapdoor.list()):
            raise ValueError("Trapdoor must contain signed integers")
        self.n, self.m_bar = self.a_bar.dimensions()
        self.k = (self.q-1).bit_length()
        self.w, self.dimension = self.n*self.k, self.m_bar+self.n*self.k
        if self.dimension > MAX_DIMENSION or self.trapdoor.dimensions() != (self.m_bar, self.w):
            raise ValueError("Trapdoor dimensions mismatch/exceed reference cap")
        self.r_squared = exact_rational(r_squared, "r_squared")
        self.sigma_squared = exact_rational(sigma_squared, "Sigma scalar")
        self.gadget_covariance = exact_rational(gadget_covariance, "Sigma_G scalar")
        if self.r_squared <= 0 or self.sigma_squared <= 0 or self.gadget_covariance < 2:
            raise ValueError("Invalid squared parameters")
        if not isinstance(perturbation_scalar, OnlineScalarGaussian):
            raise ValueError("Need a public perturbation class")
        self.j = self.trapdoor.stack(identity_matrix(QQ, self.w))
        self.j.set_immutable()
        jjt = self.j*self.j.transpose()
        sigma = self.sigma_squared*identity_matrix(QQ, self.dimension)
        self.margin = sigma-(self.gadget_covariance+2)*jjt
        self.margin_pivots = exact_psd_pivots(self.margin)
        self.perturbation_covariance = sigma-self.gadget_covariance*jjt
        self.perturbation = OnlineNonSphericalSampler(self.r_squared*self.perturbation_covariance,
            perturbation_scalar)
        self.gadget = OnlineGadgetSampler(self.q, self.r_squared*self.gadget_covariance,
            options=perturbation_scalar.options)
        field = perturbation_scalar.field

        def smoothing(width):
            a = capped_exp_minus_pi(width, field, perturbation_scalar.cap_bits)
            denominator = 1-2*self.w*a
            if interval_bounds(denominator)[0] <= 0:
                raise ValueError("MP12 smoothing denominator not positive")
            return interval_upper(2*self.w*a/denominator)

        self.epsilon = max(smoothing(self.r_squared), smoothing(self.r_squared*self.gadget_covariance/
            max(self.gadget.geometry.norm_squared)))
        if not 0 < self.epsilon <= QQ(1)/2:
            raise ValueError("MP12 smoothing not certified <=1/2")
        self.g = matrix(ZZ, self.n, self.w)
        for i in range(self.n):
            for j in range(self.k):
                self.g[i, i*self.k+j] = (1 << j) % self.q
        self.g.set_immutable()
        self.random_tape_bytes = public_tape_guard(self.perturbation.random_tape_bytes+
            self.n*self.gadget.random_tape_bytes, perturbation_scalar.options)

    def public_matrix(self, tag=None):
        h = tag_matrix(tag, self.q, self.n)
        result = self.a_bar.augment(h*self.g-self.a_bar*self.trapdoor).apply_map(lambda x: ZZ(x) % self.q)
        result.set_immutable()
        return result

    def sample_trace(self, syndrome, *, tag=None, rng=None):
        targets = tuple(syndrome)
        if len(targets) != self.n:
            raise ValueError("Syndrome dimensions mismatch")
        target = vector(ZZ, [exact_integer(x, "syndrome", maximum=self.q-1) for x in targets])
        h = tag_matrix(tag, self.q, self.n)
        rng = SecureRandom() if rng is None else rng
        p = vector(ZZ, self.perturbation.sample(rng=rng))
        a = self.public_matrix(h)
        v = matrix(GF(self.q), h).inverse()*vector(GF(self.q), target-a*p)
        v = tuple(int(x) for x in v)
        z = self.gadget.sample(v, rng=rng)
        x = tuple(int(v) for v in p+self.j*vector(ZZ, z))
        assert tuple(int(v) % self.q for v in a*vector(ZZ, x)) == tuple(target)
        return SampleDTrace(x, tuple(int(x) for x in p), z, v)

    def sample(self, syndrome, *, tag=None, rng=None):
        return self.sample_trace(syndrome, tag=tag, rng=rng).output

    def sample_from_tape(self, syndrome, tape, *, tag=None):
        targets = tuple(syndrome)
        if len(targets) != self.n:
            raise ValueError("Syndrome dimensions mismatch")
        for target in targets:
            exact_integer(target, "syndrome", maximum=self.q-1)
        tag_matrix(tag, self.q, self.n)
        source = FiniteByteTape(tape)
        if len(source.data) != self.random_tape_bytes:
            raise ValueError("SampleD tape must have the public fixed length")
        return self.sample(targets, tag=tag, rng=source)

    def certificate(self):
        p, g = self.perturbation.certificate(), self.gadget.certificate(self.n)
        convolution = min(QQ(1), 4*self.epsilon/(1-self.epsilon)**2)
        total = min(QQ(1), interval_upper(self.perturbation.scalar.field(
            convolution+QQ(p["tv_upper_including_abort"])+QQ(g["tv_upper_including_abort"]))))
        return {"algorithm": "MP12 Algorithm 3 with online project Gaussian adaptation",
            "q": self.q, "n": self.n, "w": self.w, "output_dimension": self.dimension,
            "r_squared": str(self.r_squared), "Sigma_scalar": str(self.sigma_squared),
            "Sigma_G_scalar": str(self.gadget_covariance),
            "spherical_target_width_squared": str(self.r_squared*self.sigma_squared),
            "MP12_smoothing_epsilon_upper": str(self.epsilon),
            "ideal_MP12_convolution_tv_upper": str(convolution),
            "perturbation": p, "gadget": g, "tv_upper_including_abort": str(total),
            "public_tape_bytes": self.random_tape_bytes,
            "tape_length_depends_only_on_supplied_public_width_classes_and_dimensions": True,
            "uniform_in_all_syndromes_and_invertible_tags": True,
            "center_or_CDF_tables_precomputed": 0, "security_claim": "none", "constant_time": False}


def quality_stage(dimension, quality_squared, r_squared=9, gamma=5, *, options=None):
    """Public resource/width class for ALL integer R with ||R||_F^2 <= Q.

    Dimension includes the bottom identity. Sigma and gamma are integers here;
    a determinant/center-size bound admits all possible finite sampling paths.
    This does not prove a generated trapdoor meets the quality threshold.
    """
    dimension = exact_integer(dimension, "dimension", minimum=1, maximum=MAX_DIMENSION)
    quality = exact_integer(quality_squared, "quality squared", maximum=10**12)
    gamma = exact_integer(gamma, "gamma", minimum=2, maximum=128)
    r_squared = exact_rational(r_squared, "r_squared")
    sigma = (gamma+2)*(quality+1)
    if sigma > 2**40:
        raise ValueError("Public integer Sigma exceeds determinant resource proof")
    scalar = OnlineScalarGaussian(r_squared*(sigma-gamma*(quality+1)), r_squared*sigma, options=options)
    denominator_upper = ZZ(sigma)**dimension
    mu_upper = int((scalar.v_max/scalar.v_min).ceil())
    coefficient_upper = (scalar.radius+2)*(1+dimension*mu_upper)**dimension
    numerator_bits = int(denominator_upper*(coefficient_upper+1)).bit_length()
    width_bits = int(denominator_upper).bit_length()+max(abs(int(r_squared.numerator())).bit_length(),
        int(r_squared.denominator()).bit_length())
    if max(numerator_bits, width_bits) > scalar.options.rational_bits:
        raise ValueError("Entire qualified class exceeds rational-center resource proof")
    return scalar, {"dimension": dimension, "quality_squared": quality, "Sigma_scalar": sigma,
        "r_squared": str(r_squared), "gamma": gamma,
        "all_qualified_trapdoors_covered": True,
        "uniform_center_numerator_bit_upper": numerator_bits,
        "uniform_center_denominator_bit_upper": int(denominator_upper).bit_length(),
        "uniform_coordinate_width_rational_bit_upper": width_bits,
        "scalar": scalar.certificate(), "security_claim": "none"}


def sampler_for_quality(q, a_bar, trapdoor, quality_squared, *, r_squared=9, gamma=5, options=None):
    base, r = exact_matrix(a_bar, "base"), exact_matrix(trapdoor, "trapdoor")
    q = exact_integer(q, "q", minimum=2)
    if not ZZ(q).is_prime():
        raise ValueError("Need prime q")
    w = base.nrows()*(q-1).bit_length()
    if r.dimensions() != (base.ncols(), w) or any(x.denominator() != 1 for x in r.list()):
        raise ValueError("Signed integer trapdoor dimensions mismatch")
    if any(x.denominator() != 1 or not 0 <= x < q for x in base.list()):
        raise ValueError("Base must use canonical modular integers")
    scalar, stage = quality_stage(base.ncols()+w, quality_squared, r_squared, gamma, options=options)
    norm = sum(int(x)**2 for x in r.list())
    if norm > stage["quality_squared"]:
        return {"status": "quality_rejected", "norm_squared": norm, "stage": stage}, None
    sampler = OnlineMP12SampleD(q, base, r, r_squared=r_squared, sigma_squared=stage["Sigma_scalar"],
        perturbation_scalar=scalar, gadget_covariance=gamma)
    assert sampler.perturbation.resources["max_center_numerator_bits"] <= stage["uniform_center_numerator_bit_upper"]
    return {"status": "admitted", "norm_squared": norm, "stage": stage}, sampler


class OnlineGaussianGenTrap:
    """Gaussian MP12 Algorithm 1 without the old dimension/table restrictions."""

    def __init__(self, q, n, m_bar, width_squared=1, *, options=None):
        self.q = exact_integer(q, "q", minimum=2)
        if not ZZ(self.q).is_prime():
            raise ValueError("Need prime q")
        self.n = exact_integer(n, "n", minimum=1, maximum=MAX_DIMENSION)
        self.m_bar = exact_integer(m_bar, "m_bar", minimum=1, maximum=MAX_DIMENSION)
        self.w = self.n*(self.q-1).bit_length()
        if self.m_bar+self.w > MAX_DIMENSION:
            raise ValueError("Generation dimensions exceed reference cap")
        self.scalar = OnlineScalarGaussian(width_squared, width_squared, options=options)
        self.width_squared = exact_rational(width_squared, "generation width")
        self.gadget = matrix(ZZ, self.n, self.w)
        k = self.w//self.n
        for i in range(self.n):
            for j in range(k):
                self.gadget[i, i*k+j] = (1 << j) % self.q
        self.gadget.set_immutable()
        matrix_bytes = self.n*self.m_bar*self.scalar.options.max_uniform_trials*(((self.q-1).bit_length()+7)//8)
        self.random_tape_bytes = public_tape_guard(matrix_bytes+self.m_bar*self.w*self.scalar.random_tape_bytes,
            self.scalar.options)

    def generate(self, *, tag=None, rng=None):
        h = tag_matrix(tag, self.q, self.n)
        rng = SecureRandom() if rng is None else rng
        base = matrix(ZZ, self.n, self.m_bar, [draw_uniform_integer(rng, self.q,
            max_trials=self.scalar.options.max_uniform_trials) for _ in range(self.n*self.m_bar)])
        r = matrix(ZZ, self.m_bar, self.w, [self.scalar.sample(self.width_squared, rng=rng)
            for _ in range(self.m_bar*self.w)])
        public = base.augment(h*self.gadget-base*r).apply_map(lambda x: x % self.q)
        for value in (base, r, public):
            value.set_immutable()
        assert (public*r.stack(identity_matrix(ZZ, self.w))-h*self.gadget).apply_map(lambda x: x % self.q).is_zero()
        return GeneratedTrapdoor(self.q, base, public, r, self.gadget, h)

    def generate_from_tape(self, tape, *, tag=None):
        tag_matrix(tag, self.q, self.n)
        source = FiniteByteTape(tape)
        if len(source.data) != self.random_tape_bytes:
            raise ValueError("Generation tape must have the public fixed length")
        return self.generate(tag=tag, rng=source)


def delegate_stream(parent, extension, *, rng=None, parent_tag=None, new_tag=None):
    """Same disjoint w*B tape as Algorithm 4, retain only one column band.

    Hashes cover each FULL band, including its unused suffix. Independent bytes
    and frozen stream chunking preserve the original fixed-tape semantics.
    """
    extension = modular_matrix(extension, parent.q, (parent.n, parent.w), "extension")
    h = tag_matrix(new_tag, parent.q, parent.n)
    public = parent.public_matrix(parent_tag)
    targets = (h*parent.g-extension).apply_map(lambda x: x % parent.q)
    rng = SecureRandom() if rng is None else rng
    columns, syndromes, hashes = [], [], []
    for j in range(parent.w):
        data = rng.read(parent.random_tape_bytes)
        # Each sample_from_tape validates full byte type/length before sampling.
        syndrome = tuple(int(x) for x in targets.column(j))
        columns.append(parent.sample_from_tape(syndrome, data, tag=parent_tag))
        hashes.append(sha256(data).hexdigest())
        syndromes.append(syndrome)
    r = matrix(ZZ, columns).transpose()
    r.set_immutable()
    assert (public*r-h*parent.g+extension).apply_map(lambda x: x % parent.q).is_zero()
    error = min(QQ(1), parent.w*QQ(parent.certificate()["tv_upper_including_abort"]))
    return DelegatedTrapdoor(public, extension, h, r, tuple(syndromes), parent.random_tape_bytes, error), hashes
