"""PUBLIC TEST GPV bridge to Sage's native DGS integer sampler.

This independent comparison profile deliberately has NO finite TV certificate,
no bounded scalar rejection/entropy ledger and no production random API. It
does not inherit certificates/admission from the existing finite CHKP sampler.
Existing dimensions/options/tape/cache caps remain unchanged. All runs require
an explicit public test seed; sampling is isolated in Sage's seeded context.
"""

from dataclasses import dataclass, field

from sage.all import GF, QQ, ZZ, RealField, matrix, vector, seed
from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler

from experiments.research.chkp_basis import KernelBasis
from experiments.research.chkp_tobasis import to_basis
from experiments.research.gaussian_reference import SamplingAbort
from experiments.research.ibme_joint_parameters import smoothing_factor

MAX_DIMENSION = 256
MAX_BATCH = 256
PRECISION = 192
TAU = 12


@dataclass(frozen=True, repr=False)
class NativePublicBatch:
    public: object
    targets: tuple
    preimages: tuple = field(repr=False)
    security_claim: str = field(default="none", init=False)
    backend_admitted: bool = field(default=False, init=False)


class NativePublicGPV:
    security_claim = "none"
    backend_admitted = False

    def __init__(self, basis, width_squared, *, public_test_fixture=False, epsilon_bits=32):
        if public_test_fixture is not True or not isinstance(basis, KernelBasis):
            raise ValueError("explicit public teaching fixture required")
        d = basis.public.ncols
        if not 1 <= d <= MAX_DIMENSION or type(epsilon_bits) is not int or not 2 <= epsilon_bits <= 64:
            raise ValueError("native comparison dimension/error budget rejected")
        if isinstance(width_squared, (bool, float)):
            raise ValueError("exact squared width required")
        width = QQ(width_squared)
        if not 0 < width <= 2**80:
            raise ValueError("native comparison width rejected")
        rows = matrix(ZZ, basis.basis_rows)
        if any(abs(int(x)).bit_length() > 1024 for x in rows.list()):
            raise ValueError("native comparison basis arithmetic budget rejected")
        orthogonal, _ = matrix(QQ, rows.transpose()).gram_schmidt()
        lengths = tuple(row.dot_product(row) for row in orthogonal.rows())
        if width < 4*max(lengths)*smoothing_factor(d, epsilon_bits):
            raise ValueError("native comparison width fails the C1-exec sufficient rule")
        self.basis, self.dimension, self.width_squared = basis, d, width
        self._columns = tuple(rows.columns())
        self._weights = tuple(row / length for row, length in zip(orthogonal.rows(), lengths))
        rr = RealField(PRECISION)
        # exp(-pi*x^2/s^2) = exp(-x^2/(2*sigma^2)); Sage uses sigma.
        self.sigmas = tuple((rr(width/length)/(2*rr.pi())).sqrt() for length in lengths)
        a = matrix(GF(basis.public.q), basis.public.rows)
        self._pivots = tuple(a.pivots())
        self._inverse = a.matrix_from_columns(self._pivots).inverse()
        self.draws = 0

    def _targets(self, targets):
        if not isinstance(targets, (tuple, list)) or not 1 <= len(targets) <= MAX_BATCH:
            raise ValueError("native public batch needs 1..256 fixed targets")
        n, q = self.basis.public.nrows, self.basis.public.q
        for row in targets:
            if not isinstance(row, (tuple, list)) or len(row) != n or any(type(x) is not int or not 0 <= x < q for x in row):
                raise ValueError("bad native public target")
        return tuple(tuple(row) for row in targets)

    def _draw(self, target):
        q = self.basis.public.q
        t = vector(ZZ, self.dimension)
        solved = self._inverse * vector(GF(q), target)
        for i, pivot in enumerate(self._pivots):
            t[pivot] = ZZ(solved[i])
        center, v = -t, vector(ZZ, self.dimension)
        for i in reversed(range(self.dimension)):
            projected = center.dot_product(self._weights[i])
            if max(abs(int(projected.numerator())).bit_length(), int(projected.denominator()).bit_length()) > 8192:
                raise SamplingAbort("native comparison center bit budget exhausted")
            scalar = DiscreteGaussianDistributionIntegerSampler(
                self.sigmas[i], c=projected, tau=TAU, algorithm="uniform+online", precision="mp")
            z = scalar()
            step = z*self._columns[i]
            center -= step
            v += step
        result = tuple(int(x) for x in t+v)
        a = self.basis.public.rows
        if tuple(sum(ai*x for ai, x in zip(row, result)) % q for row in a) != target:
            raise ArithmeticError("native GPV output equation failed")
        self.draws += 1
        return result

    def sample_batch(self, targets, *, test_seed):
        checked = self._targets(targets)
        if type(test_seed) is not int or not 0 <= test_seed < 2**256:
            raise ValueError("explicit bounded public test seed required")
        with seed(test_seed):
            out = tuple(self._draw(row) for row in checked)
        return NativePublicBatch(self.basis.public, checked, out)

    def randomize_public_basis(self, *, test_seed, max_vectors):
        if type(max_vectors) is not int or not self.dimension <= max_vectors <= 512:
            raise ValueError("bounded native RandBasis attempts required")
        if type(test_seed) is not int or not 0 <= test_seed < 2**256:
            raise ValueError("explicit bounded public test seed required")
        chosen, zero = [], (0,)*self.basis.public.nrows
        norm_limit = self.width_squared*self.dimension
        with seed(test_seed):
            for count in range(1, max_vectors+1):
                candidate = vector(ZZ, self._draw(zero))
                if candidate.dot_product(candidate) > norm_limit:
                    raise SamplingAbort("native RandBasis norm abort; no retry")
                if matrix(ZZ, chosen + [candidate]).rank() > len(chosen):
                    chosen.append(candidate)
                if len(chosen) == self.dimension:
                    basis = to_basis(matrix(ZZ, chosen).transpose(), self.basis)
                    return basis, count
        raise SamplingAbort("native RandBasis rank abort; no retry")

    def certificate(self):
        return dict(profile="SAGE-DGS-PUBLIC-COMPARISON/1", dimension=self.dimension,
                    width_squared=str(self.width_squared), precision_bits=PRECISION, tau=TAU,
                    native_algorithm="uniform+online; MPFR", scalar_tv_upper=None,
                    whole_sampler_tv_upper=None, worst_random_tape_bytes=None,
                    scalar_rejection_is_bounded=False, test_randomness_only=True,
                    production_random_api=False, security_claim="none", backend_admitted=False)
