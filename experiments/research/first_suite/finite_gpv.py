"""Independent first-suite finite GPV with system CSPRNG and wide scalar profile.

GPV08 (2008-08-25 author version), section 4.2, PDF pp. 15--17:
descending randomized nearest plane with c=-t, then return t+v, where
A*t=y (mod q). The scalar oracle is the project's bounded online Gaussian,
not GPV's ideal oracle and NOT the MP12 vector/perturbation sampler.

The project's T2 contract (2026-10-09), C1-exec and C2-exec/C3, supplies
the conservative finite width and TV bounds. These finite adaptations are
not verbatim GPV theorems. All GS/coset arithmetic is exact ZZ/QQ; scalar
rounding/truncation/abort errors remain in each scalar's actual certificate.
All adaptive rational centers are admitted BEFORE entropy is consumed.

Variable time, bounded research dimensions, no security level or backend
admission. Certificates contain basis-dependent diagnostic profiles: publish
them only for PUBLIC TEST BASES, not as a secret-key serialization format.
"""

from __future__ import annotations

from itertools import islice
from math import lcm
import re

from sage.all import QQ, ZZ, matrix, vector

from ibme.core.randomness import SecureRandom
from experiments.research.chkp_basis import KernelBasis, ModMatrixReference, _full_rank_field, _integer, _rows
from .finite_gaussian import (
    FiniteByteTape, FirstFiniteOptions, FirstFiniteGaussian, exact_integer, exact_rational,
)
from .entropy import CheckedEntropy


MAX_DIMENSION = 256
MAX_INPUT_BITS = 1024


def _bit_length(value):
    return abs(int(value)).bit_length()


def _bounded_rational(value, name, bits):
    # Guard text BEFORE QQ parses it (notably unbounded decimal exponents).
    if isinstance(value, str):
        if len(value) > 2 * bits + 4:
            raise ValueError(f"{name} exceeds the rational text resource limit")
        value = value.strip()
        if not re.fullmatch(r"[+-]?[0-9]+(?:/[0-9]+)?", value):
            raise ValueError(f"{name} requires integer or fraction text")
    return exact_rational(value, name, max_bits=bits)


def _bounded_basis(basis, max_dimension, bits):
    """Bound and type-check ALL input entries before field/GS/determinant work."""
    if not isinstance(basis, KernelBasis) or not isinstance(basis.public, ModMatrixReference):
        raise ValueError("Need a validated KernelBasis")
    public = basis.public
    rows, a_rows = basis.basis_rows, public.rows
    if not isinstance(rows, (tuple, list)) or not isinstance(a_rows, (tuple, list)):
        raise ValueError("Basis/public rows must be finite sequences")
    dimension, n = len(rows), len(a_rows)
    if not 1 <= n <= dimension <= max_dimension:
        raise ValueError("Basis exceeds the dimension resource limit")
    for group in (rows, a_rows):
        if any(not isinstance(row, (tuple, list)) or len(row) != dimension for row in group):
            raise ValueError("Invalid basis/public matrix dimensions")
    q = _integer(public.q)
    if q < 2 or _bit_length(q) > bits:
        raise ValueError("Modulus exceeds the input bit resource limit")
    # _rows rejects bool, float and implicit finite-field lifts in the basis.
    rows = _rows(rows)
    a_rows = _rows(a_rows, modulus=q)
    if any(_bit_length(x) > bits for group in (rows, a_rows) for row in group for x in row):
        raise ValueError("Matrix entry exceeds the input bit resource limit")
    if any(not 0 <= x < q for row in a_rows for x in row):
        raise ValueError("Public entries must be canonical residues")
    # Revalidate containment/completeness only AFTER the cheap resource gate.
    return KernelBasis(ModMatrixReference(a_rows, q), rows)


def _gs_geometry(rows, bits):
    columns = tuple(matrix(ZZ, rows).columns())
    orthogonal, squared, weights = [], [], []
    for column in columns:
        current = vector(QQ, column)
        for g, norm in zip(orthogonal, squared):
            current -= (current.dot_product(g) / norm) * g
            for entry in current:
                _bounded_rational(entry, "GS intermediate", bits)
        norm = _bounded_rational(current.dot_product(current), "GS squared length", bits)
        if norm <= 0:
            raise ValueError("Basis must have full integer rank")
        weight = tuple(_bounded_rational(x / norm, "GS weight", bits) for x in current)
        current.set_immutable()
        column.set_immutable()
        orthogonal.append(current)
        squared.append(norm)
        weights.append(weight)
    return columns, tuple(squared), tuple(weights)


def _admit_paths(columns, weights, scalars, q, bits):
    """Deterministic envelope for EVERY syndrome and EVERY non-aborted path.

    Residual c starts at -t with |c_j| <= q-1 and remains integral. Thus
    c'_i=sum_j c_j*w_ij has denominator dividing lcm_j den(w_ij), and a
    reduced numerator no larger than ceil(den * sum_j M_j*|w_ij|).
    The scalar support gives |z_i| <= ceil(|c'_i|_upper)+radius_i+1.
    Update M_j <- M_j + |z_i|_upper*|b_ji| in descending order. Reject
    the whole input if ANY possible center exceeds the scalar bit budget.
    This is conservative: rejection is not a cryptographic impossibility.
    """
    dimension = len(columns)
    bounds = [q - 1] * dimension
    steps = [None] * dimension
    for i in reversed(range(dimension)):
        denominator = 1
        for w in weights[i]:
            denominator = lcm(denominator, int(w.denominator()))
            if _bit_length(denominator) > bits:
                raise ValueError("Adaptive center denominator exceeds rational bit budget")
        upper = sum((QQ(m) * abs(w) for m, w in zip(bounds, weights[i])), QQ(0))
        numerator = int((upper * denominator).ceil())
        if _bit_length(numerator) > bits:
            raise ValueError("Adaptive center numerator exceeds rational bit budget")
        z_bound = int(upper.ceil()) + scalars[i].radius + 1
        bounds = [m + z_bound * abs(int(b)) for m, b in zip(bounds, columns[i])]
        if max(map(_bit_length, bounds + [z_bound])) > bits:
            raise ValueError("GPV residual/coefficient exceeds the arithmetic bit budget")
        # Private diagnostics for testing the induction, never raw certificate data.
        steps[i] = (denominator, numerator, z_bound, tuple(bounds))
    return tuple(steps)


class FirstFiniteGPV:
    """Sample the zero-centered Gaussian on {x in Z^D : A*x=y mod q}.

    width_squared is s^2 in exp(-pi*||x||^2/s^2), not statistical variance.
    Canonical syndromes are exact integers in [0,q); matching prime-field
    elements are allowed, foreign fields need explicit caller-chosen lifts.
    A successful output solves the equation exactly. SamplingAbort and RNG
    errors propagate; there is no outer retry, zero fallback, or rejection of
    zero. The TV bound includes scalar abort, assuming independent uniform
    bytes. Arbitrary failing/malformed entropy providers are not that model.

    Per-coordinate exact-width classes avoid a huge global rejection box for
    skew bases. Scalars and other admitted state must not be mutated by users.
    max_dimension may lower, but not override, the research independent profile hard limit 256.
    """

    def __init__(self, basis: KernelBasis, width_squared, *, epsilon_bits=32,
                 options: FirstFiniteOptions | None = None, max_dimension=256):
        opts = FirstFiniteOptions() if options is None else options
        if not isinstance(opts, FirstFiniteOptions):
            raise ValueError("Need FirstFiniteOptions")
        limit = exact_integer(max_dimension, "max_dimension", minimum=1, maximum=MAX_DIMENSION)
        self.epsilon_bits = exact_integer(epsilon_bits, "epsilon_bits", minimum=2, maximum=4096)
        input_bits = min(MAX_INPUT_BITS, opts.rational_bits)
        self.width_squared = _bounded_rational(width_squared, "width_squared", input_bits)
        if self.width_squared <= 0:
            raise ValueError("width_squared must be positive")
        self.basis = _bounded_basis(basis, limit, input_bits)
        self.dimension = self.basis.public.ncols
        self._columns, lengths, self._weights = _gs_geometry(self.basis.basis_rows, opts.rational_bits)
        scale = 1 << self.epsilon_bits
        self._smoothing_factor = (2 * self.dimension * (1 + scale) - 1).bit_length()
        if self.width_squared < 4 * max(lengths) * self._smoothing_factor:
            raise ValueError("Width fails the T2 C1-exec sufficient condition")
        self._widths = tuple(_bounded_rational(self.width_squared / length,
                            "scalar squared width", opts.rational_bits) for length in lengths)
        # Check every coordinate before constructing any expensive scalar profile.
        if any(not 1 <= v <= 2**80 for v in self._widths):
            raise ValueError("Scalar squared width outside independent finite profile 1..2^80")
        self.scalars = tuple(FirstFiniteGaussian(v, v, options=opts) for v in self._widths)
        self.random_tape_bytes = sum(s.random_tape_bytes for s in self.scalars)
        if self.random_tape_bytes > opts.max_tape_bytes:
            raise ValueError("Whole GPV tape exceeds the resource budget")
        self._path_resources = _admit_paths(self._columns, self._weights, self.scalars,
                                            self.basis.public.q, opts.rational_bits)
        a, self._pivots = _full_rank_field(self.basis.public)
        self._field = a.base_ring()
        self._pivot_inverse = a.matrix_from_columns(self._pivots).inverse()
        self._pivot_inverse.set_immutable()
        denominator = scale - 2 * self.dimension - 1
        self.geometry_tv = min(QQ(1), QQ(self.dimension) / denominator) if denominator > 0 else QQ(1)
        self.scalar_tv = sum((s.tv_upper for s in self.scalars), QQ(0))
        self.tv_upper = min(QQ(1), self.geometry_tv + self.scalar_tv)
        self._max_dimension, self._input_bits = limit, input_bits

    def _syndrome(self, syndrome):
        if isinstance(syndrome, (str, bytes, bytearray, memoryview)):
            raise ValueError("Syndrome must be a finite vector of exact residues")
        try:
            # Bounded consumption rejects wrong length even for an iterator.
            values = tuple(islice(iter(syndrome), self.basis.public.nrows + 1))
        except TypeError as exc:
            raise ValueError("Syndrome must be a finite vector of exact residues") from exc
        if len(values) != self.basis.public.nrows:
            raise ValueError("Wrong syndrome dimension")
        q = self.basis.public.q
        values = tuple(_integer(x, modulus=q) for x in values)
        if any(not 0 <= x < q for x in values):
            raise ValueError("Syndrome must contain canonical residues in [0,q)")
        return values

    def _lift(self, syndrome):
        solved = self._pivot_inverse * vector(self._field, syndrome)
        t = [0] * self.dimension
        for i, pivot in enumerate(self._pivots):
            t[pivot] = int(solved[i])
        return vector(ZZ, t)

    def sample(self, syndrome, *, rng=None) -> tuple[int, ...]:
        target = self._syndrome(syndrome)
        t = self._lift(target)
        center, v = -t, vector(ZZ, self.dimension)
        source = CheckedEntropy(SecureRandom() if rng is None else rng, self.random_tape_bytes)
        for i in reversed(range(self.dimension)):
            projected = sum((x * w for x, w in zip(center, self._weights[i])), QQ(0))
            z = self.scalars[i].sample(self._widths[i], projected, rng=source)
            step = z * self._columns[i]
            center -= step
            v += step
        return tuple(int(x) for x in t + v)

    def sample_from_tape(self, syndrome, tape) -> tuple[int, ...]:
        target = self._syndrome(syndrome)
        if not isinstance(tape, (bytes, bytearray, memoryview)):
            raise ValueError("GPV tape must have the public fixed length")
        size = tape.nbytes if isinstance(tape, memoryview) else len(tape)
        if size != self.random_tape_bytes:
            raise ValueError("GPV tape must have the public fixed length")
        return self.sample(target, rng=FiniteByteTape(tape))

    def certificate(self):
        """JSON-safe diagnostic copy, PUBLIC TEST EVIDENCE ONLY (see module doc)."""
        steps = self._path_resources
        return {
            "profile": "FIRST-SUITE-FINITE-GPV/1", "algorithm": "GPV08 section 4.2, descending general-column-basis SampleD",
            "source": "papers/2008_gpv_trapdoors_full.pdf, author 2008-08-25, pp.15-17",
            "finite_conditions": "T2 contract 2026-10-09, C1-exec, C2-exec, C3 (project adaptations)",
            "security_claim": "none", "backend_admitted": False, "constant_time": False,
            "public_test_evidence_only": True,
            "disclosure": "basis-dependent scalar width/resource diagnostics; no raw basis or samples",
            "dimension": self.dimension, "public_rows": self.basis.public.nrows,
            "q": str(self.basis.public.q), "width_squared": str(self.width_squared),
            "epsilon_bits": self.epsilon_bits, "integer_smoothing_factor": self._smoothing_factor,
            "C1_exec_verified": True, "complete_kernel_basis_verified": True,
            "coset_convention": "A*t=y, GPV center=-t, output=t+v",
            "per_coordinate_profiles": [s.certificate() for s in self.scalars],
            "coordinate_profile_order": "basis columns 0..D-1; sampling visits D-1..0",
            "geometry_tv_upper": str(self.geometry_tv), "scalar_tv_upper_sum": str(self.scalar_tv),
            "arithmetic_tv_upper": "0",
            "arithmetic_reason": "exact ZZ/QQ outside scalar; all adaptive centers pre-admitted",
            "tv_upper_including_abort": str(self.tv_upper),
            "random_tape_bytes": self.random_tape_bytes, "tape_exhaustion_at_public_length_upper": "0",
            "path_resources": {
                "all_canonical_syndromes": True, "all_nonaborted_paths": True,
                "initial_coordinate_abs_upper": str(self.basis.public.q - 1),
                "max_center_denominator_bits": max(_bit_length(s[0]) for s in steps),
                "max_center_numerator_bits": max(_bit_length(s[1]) for s in steps),
                "max_coefficient_bits": max(_bit_length(s[2]) for s in steps),
                "max_residual_bits": max(_bit_length(x) for s in steps for x in s[3]),
                "rational_bit_budget": self.scalars[0].options.rational_bits,
                "max_dimension": self._max_dimension, "input_bit_budget": self._input_bits,
                "centers_or_CDFs_precomputed": 0,
            },
            "production_random_api": True, "native_Sage_rng_used": False,
            "randomness": "independent uniform bytes; defaults to SecureRandom; seeded tests are not security evidence",
            "failure_semantics": "SamplingAbort and RNG errors propagate, no retries/fallback; invalid inputs rejected before sampling",
            "not_covered": ["arbitrary faulty entropy sources", "side channels", "GenBasis/RandBasis",
                            "HIBE correctness/noise", "security reduction or attack estimates"],
        }
