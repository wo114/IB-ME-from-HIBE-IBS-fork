"""General-basis GPV: exact equations, independent laws, resources and failures.

Small public test bases only (no cryptographic security claim). Run in the
prescribed WSL ~/miniconda3/envs/sage, not by counting a missing-Sage skip.
"""

from dataclasses import replace
from itertools import product, repeat
import json
from math import exp, pi

import pytest

pytest.importorskip("sage.all", reason="Use the prescribed WSL Sage environment")
from sage.all import GF, QQ, ZZ, identity_matrix, matrix, vector

from ibme.core.randomness import DeterministicRandom
from experiments.research import chkp_gpv as module
from experiments.research.chkp_basis import (
    KernelBasis, ModMatrixReference, complete_kernel_basis, ext_basis,
    gram_schmidt_squared_lengths,
)
from experiments.research.chkp_gpv import CHKPGPVSampler
from experiments.research.online_gaussian_reference import (
    FiniteByteTape, OnlineOptions, OnlineScalarGaussian, SamplingAbort,
)


class NoEntropy:
    def read(self, _):
        pytest.fail("Invalid input or scripted test consumed unexpected entropy")


def forbidden(*_, **__):
    pytest.fail("Rejected input reached expensive work, fallback or next coordinate")


def sufficient_width(basis, bits=8):
    dim = basis.public.ncols
    k = (2 * dim * (1 + (1 << bits)) - 1).bit_length()
    return 4 * max(gram_schmidt_squared_lengths(basis.basis_rows)) * k


@pytest.fixture
def basis():
    # GS squares 5 and 9/5. Off-diagonal inner product -1 gives genuinely
    # nonorthogonal adaptive fractional centers, not a product Gaussian.
    return KernelBasis(ModMatrixReference([[1, 1]], 3), [[2, -1], [1, 1]])


@pytest.fixture
def sampler(basis):
    return CHKPGPVSampler(basis, sufficient_width(basis), epsilon_bits=8)


def test_pinned_width_condition_geometry_and_individual_scalar_certificates(sampler):
    assert sampler.width_squared == 220 and sampler.dimension == 2
    assert sampler.epsilon_bits == 8
    assert tuple(s.v_min for s in sampler.scalars) == (QQ(44), QQ(1100) / 9)
    assert all(s.v_min == s.v_max for s in sampler.scalars)
    assert sampler.geometry_tv == QQ(2) / 251
    assert sampler.scalar_tv == sum(s.tv_upper for s in sampler.scalars)
    assert sampler.tv_upper == min(1, sampler.geometry_tv + sampler.scalar_tv)
    assert sampler.random_tape_bytes == sum(s.random_tape_bytes for s in sampler.scalars)
    cert = sampler.certificate()
    assert json.loads(json.dumps(cert)) == cert
    assert cert["arithmetic_tv_upper"] == "0"
    assert cert["C1_exec_verified"] and cert["complete_kernel_basis_verified"]
    assert cert["public_test_evidence_only"] and not cert["backend_admitted"]
    assert cert["security_claim"] == "none" and not cert["constant_time"]
    assert len(cert["per_coordinate_profiles"]) == 2
    assert not any(key in cert for key in ("basis_rows", "basis", "samples", "syndrome"))
    cert["per_coordinate_profiles"][0]["finite_options"]["mass_bits"] = 1
    assert sampler.certificate()["per_coordinate_profiles"][0]["finite_options"]["mass_bits"] == 128


@pytest.mark.parametrize("q,rows", [(2, [[1, 1]]), (3, [[1, 2]]),
    (5, [[0, 1, 2], [1, 0, 3]]), (17, [[0, 2, 5]])])
def test_equations_all_syndromes_for_small_nonorthogonal_bases(q, rows):
    public = ModMatrixReference(rows, q)
    canonical = complete_kernel_basis(public)
    dim = public.ncols
    change = identity_matrix(ZZ, dim)
    change[dim - 1, 0] = 1
    basis = KernelBasis(public, matrix(ZZ, canonical.basis_rows) * change)
    sampler = CHKPGPVSampler(basis, sufficient_width(basis), epsilon_bits=8)
    rng = DeterministicRandom(f"gpv-equation-{q}".encode())
    for target in product(range(q), repeat=public.nrows):
        x = sampler.sample(target, rng=rng)
        assert type(x) is tuple and all(type(z) is int for z in x)
        residue = matrix(ZZ, rows) * vector(ZZ, x)
        assert tuple(int(z) % q for z in residue) == target
        # Independent full-basis membership of x minus any canonical lift.
        field_a = matrix(GF(q), rows)
        lift = vector(ZZ, [int(z) for z in field_a.solve_right(vector(GF(q), target))])
        coords = matrix(QQ, basis.basis_rows).inverse() * (vector(ZZ, x) - lift)
        assert all(z.denominator() == 1 for z in coords)


def test_extbasis_two_levels_can_sample_zero_and_nonzero_targets(basis):
    levels = [basis]
    levels.append(ext_basis(levels[-1], ModMatrixReference([[1, 2]], 3)))
    levels.append(ext_basis(levels[-1], ModMatrixReference([[2, 0]], 3)))
    rng = DeterministicRandom(b"gpv-ext-two-levels")
    for level in levels:
        sampler = CHKPGPVSampler(level, sufficient_width(level), epsilon_bits=8)
        for y in range(3):
            x = sampler.sample((y,), rng=rng)
            assert int((matrix(ZZ, level.public.rows) * vector(ZZ, x))[0]) % 3 == y


def test_default_secure_rng_explicit_rng_and_fixed_seed_replay(sampler, monkeypatch):
    created = []
    def default():
        created.append(1)
        return DeterministicRandom(b"gpv-default-test-only")
    monkeypatch.setattr(module, "SecureRandom", default)
    expected = sampler.sample((1,), rng=DeterministicRandom(b"gpv-default-test-only"))
    assert created == []
    assert sampler.sample((1,)) == expected
    assert created == [1]
    sequences = []
    for seed in (b"gpv-replay", b"gpv-replay", b"gpv-different"):
        rng = DeterministicRandom(seed)
        sequences.append([sampler.sample((i % 3,), rng=rng) for i in range(12)])
    assert sequences[0] == sequences[1] and sequences[0] != sequences[2]


def test_one_dimensional_and_zero_are_not_rejected(monkeypatch):
    b = KernelBasis(ModMatrixReference([[1]], 3), [[-3]])
    sampler = CHKPGPVSampler(b, sufficient_width(b), epsilon_bits=8)
    for y in range(3):
        x = sampler.sample((y,), rng=DeterministicRandom(f"gpv-1d-{y}".encode()))
        assert x[0] % 3 == y
    monkeypatch.setattr(sampler.scalars[0], "sample", lambda *_, **__: 0)
    assert sampler.sample((0,), rng=NoEntropy()) == (0,)


def test_finite_tape_replay_and_stream_byte_budget(sampler, monkeypatch):
    monkeypatch.setattr(module, "SecureRandom", forbidden)
    tape = DeterministicRandom(b"gpv-tape").read(sampler.random_tape_bytes)
    stream = FiniteByteTape(tape)
    expected = sampler.sample((2,), rng=stream)
    assert 0 < stream.position <= sampler.random_tape_bytes
    assert expected == sampler.sample_from_tape((2,), tape)
    assert expected == sampler.sample_from_tape((2,), bytearray(tape))
    assert expected == sampler.sample_from_tape((2,), memoryview(tape))
    assert len(tape) % 4 == 0
    assert expected == sampler.sample_from_tape((2,), memoryview(tape).cast("I"))
    for bad in (b"", tape[:-1], tape + b"x", "not bytes"):
        with pytest.raises(ValueError, match="fixed length"):
            sampler.sample_from_tape((2,), bad)
    with pytest.raises(SamplingAbort, match="tape exhausted"):
        sampler.sample((2,), rng=FiniteByteTape(b""))


def test_multibyte_view_cannot_hide_excess_tape_bytes(sampler, monkeypatch):
    # len(view) counts elements, not bytes. Reject before the tape copy.
    bad = memoryview(bytearray(sampler.random_tape_bytes*4)).cast("I")
    assert len(bad) == sampler.random_tape_bytes
    monkeypatch.setattr(module, "FiniteByteTape", forbidden)
    with pytest.raises(ValueError, match="fixed length"):
        sampler.sample_from_tape((1,), bad)


@pytest.mark.parametrize("target", [None, 1, (), (0, 1), (True,), (1.0,), (-1,),
    (3,), (QQ(1) / 2,), "1", b"\x01", ([1],), (GF(5)(1),), (1 << 9000,)])
def test_bad_syndrome_before_entropy(sampler, target, monkeypatch):
    monkeypatch.setattr(module, "SecureRandom", forbidden)
    with pytest.raises(ValueError):
        sampler.sample(target, rng=NoEntropy())


def test_infinite_syndrome_iterator_rejected_in_bounded_time(sampler):
    with pytest.raises(ValueError, match="dimension"):
        sampler.sample(repeat(0), rng=NoEntropy())


def test_matching_field_syndrome_and_sage_integer(sampler):
    seed = b"gpv-matching-field"
    a = sampler.sample((GF(3)(2),), rng=DeterministicRandom(seed))
    b = sampler.sample(vector(ZZ, [2]), rng=DeterministicRandom(seed))
    assert a == b


@pytest.mark.parametrize("value", [0, -1, True, 1.0, float("inf"), QQ(1) / 100,
    "1e1000000000", "2.5", "1/0", "x" * 9000, 1 << 1025, GF(3)(1)])
def test_bad_widths_fail_closed(basis, value):
    with pytest.raises(ValueError):
        CHKPGPVSampler(basis, value, epsilon_bits=8)


@pytest.mark.parametrize("options", [{}, False, 1])
def test_options_type_is_not_silently_defaulted(basis, options):
    with pytest.raises(ValueError, match="OnlineOptions"):
        CHKPGPVSampler(basis, 220, options=options)


@pytest.mark.parametrize("bits", [True, 1, 0, 2.0, 4097, GF(3)(2)])
def test_epsilon_type_and_range(basis, bits):
    with pytest.raises(ValueError):
        CHKPGPVSampler(basis, 220, epsilon_bits=bits)


@pytest.mark.parametrize("dimension", [True, 1.0, 0, -1, 1, 193, 1 << 10000])
def test_dimension_limit(basis, dimension):
    with pytest.raises(ValueError):
        CHKPGPVSampler(basis, 220, epsilon_bits=8, max_dimension=dimension)


def test_exact_width_boundary_no_float_rounding(basis):
    required = sufficient_width(basis)
    CHKPGPVSampler(basis, required, epsilon_bits=8)
    with pytest.raises(ValueError, match="C1-exec"):
        CHKPGPVSampler(basis, required - QQ(1) / 2**100, epsilon_bits=8)


@pytest.mark.parametrize("dim,bad", [(2, 1 << 1025), (2, 1.0), (2, True),
                                  (2, GF(3)(0)), (193, 0)])
def test_whole_input_is_checked_before_expensive_algebra(monkeypatch, dim, bad):
    # Deliberately bypass dataclass construction to test the sampler's own
    # preflight order. Never use such objects as actual lattice certificates.
    public = object.__new__(ModMatrixReference)
    object.__setattr__(public, "q", 3)
    object.__setattr__(public, "rows", ((1,) + (0,) * (dim - 1),))
    basis = object.__new__(KernelBasis)
    rows = [[int(i == j) for j in range(dim)] for i in range(dim)]
    rows[-1][-1] = bad
    object.__setattr__(basis, "public", public)
    object.__setattr__(basis, "basis_rows", rows)
    monkeypatch.setattr(module, "_gs_geometry", forbidden)
    monkeypatch.setattr(module, "_full_rank_field", forbidden)
    with pytest.raises(ValueError):
        CHKPGPVSampler(basis, 220, epsilon_bits=8)


@pytest.mark.parametrize("value", [None, [[1]], object()])
def test_kernel_basis_type(value):
    with pytest.raises(ValueError, match="KernelBasis"):
        CHKPGPVSampler(value, 220)


def test_scalar_width_rational_size_checked_not_just_input_size():
    k = 1 << 35
    basis = KernelBasis(ModMatrixReference([[1, 0]], 3), [[3, 0], [k, 1]])
    with pytest.raises(ValueError, match="scalar squared width.*bit budget"):
        CHKPGPVSampler(basis, sufficient_width(basis), epsilon_bits=8,
                       options=OnlineOptions(rational_bits=128))


def test_adaptive_center_residual_budget_is_checked_before_sampling(monkeypatch):
    k = 1 << 124
    basis = KernelBasis(ModMatrixReference([[0, 1]], 3), [[1, k], [0, 3]])
    monkeypatch.setattr(module, "SecureRandom", forbidden)
    monkeypatch.setattr(OnlineScalarGaussian, "sample", forbidden)
    with pytest.raises(ValueError, match="(Adaptive center|residual/coefficient)"):
        CHKPGPVSampler(basis, sufficient_width(basis), epsilon_bits=8,
                       options=OnlineOptions(rational_bits=128))


def test_per_coordinate_classes_admit_skew_gs_without_global_box():
    q = 1009
    basis = KernelBasis(ModMatrixReference([[1, 0]], q), [[q, 0], [0, 1]])
    sampler = CHKPGPVSampler(basis, sufficient_width(basis), epsilon_bits=8)
    low, high = [s.v_min for s in sampler.scalars]
    assert high / low == q * q
    # This is the regression: a single global proposal wastes almost every draw.
    with pytest.raises(ValueError, match="Gaussian rejection budget"):
        OnlineScalarGaussian(low, high)
    for y in (0, 1, q - 1):
        x = sampler.sample((y,), rng=DeterministicRandom(f"gpv-skew-{y}".encode()))
        assert x[0] % q == y


def test_unsupported_coordinate_width_rejected_before_scalar_construction(monkeypatch):
    q = 1000003
    basis = KernelBasis(ModMatrixReference([[1, 0]], q), [[q, 0], [0, 1]])
    monkeypatch.setattr(module, "OnlineScalarGaussian", forbidden)
    with pytest.raises(ValueError, match="outside 1..10"):
        CHKPGPVSampler(basis, sufficient_width(basis), epsilon_bits=8)


@pytest.mark.parametrize("options,match", [
    (OnlineOptions(max_radius=1), "radius"),
    (OnlineOptions(max_gaussian_trials=1), "rejection budget"),
    (OnlineOptions(max_tape_bytes=1), "tape"),
])
def test_existing_scalar_hardcaps_not_relaxed(basis, options, match):
    with pytest.raises(ValueError, match=match):
        CHKPGPVSampler(basis, sufficient_width(basis), epsilon_bits=8, options=options)


def test_total_tape_budget_not_only_each_scalar(sampler):
    largest = max(s.random_tape_bytes for s in sampler.scalars)
    assert largest < sampler.random_tape_bytes
    with pytest.raises(ValueError, match="Whole GPV tape"):
        CHKPGPVSampler(sampler.basis, sampler.width_squared, epsilon_bits=8,
                       options=replace(OnlineOptions(), max_tape_bytes=largest))


@pytest.mark.parametrize("bad", [None, "wrong", b"", 1])
def test_rng_bad_read_result_propagates(sampler, bad):
    class Invalid:
        def read(self, _):
            return bad
    with pytest.raises(ValueError, match="Random source"):
        sampler.sample((0,), rng=Invalid())


def test_rng_exception_and_falsey_source_not_replaced(sampler, monkeypatch):
    monkeypatch.setattr(module, "SecureRandom", forbidden)
    class Failed:
        calls = 0
        def __bool__(self):
            return False
        def read(self, _):
            self.calls += 1
            raise OSError("test entropy failure")
    rng = Failed()
    with pytest.raises(OSError, match="entropy failure"):
        sampler.sample((0,), rng=rng)
    assert rng.calls == 1
    with pytest.raises(ValueError, match="read"):
        sampler.sample((0,), rng=object())


def test_uniform_and_gaussian_aborts_propagate_without_outer_retry(basis, monkeypatch):
    opts = OnlineOptions(tail_bits=8, mass_bits=32, precision_bits=96,
                         gaussian_abort_bits=8, max_uniform_trials=8)
    sampler = CHKPGPVSampler(basis, sufficient_width(basis), epsilon_bits=8, options=opts)
    monkeypatch.setattr(module, "SecureRandom", forbidden)
    monkeypatch.setattr(sampler.scalars[0], "sample", forbidden)
    last = sampler.scalars[-1]
    class RejectUniform:
        calls = 0
        def read(self, n):
            self.calls += 1
            return b"\xff" * n
    rng = RejectUniform()
    with pytest.raises(SamplingAbort, match="Uniform-integer"):
        sampler.sample((0,), rng=rng)
    assert rng.calls == opts.max_uniform_trials
    class RejectGaussian:
        reads = []
        def read(self, n):
            self.reads.append(n)
            return bytes(n) if n == last.candidate_bytes else b"\xff" * n
    rng = RejectGaussian()
    with pytest.raises(SamplingAbort, match="Gaussian rejection"):
        sampler.sample((0,), rng=rng)
    assert rng.reads == [last.candidate_bytes, last.bernoulli_bytes] * last.gaussian_trials
    assert sum(rng.reads) <= sampler.random_tape_bytes


def test_resource_envelope_contains_extreme_adaptive_paths(monkeypatch):
    basis = KernelBasis(ModMatrixReference([[1, 1, 0]], 3),
                        [[2, -1, 7], [1, 1, 5], [0, 0, 1]])
    sampler = CHKPGPVSampler(basis, sufficient_width(basis), epsilon_bits=8,
                            options=OnlineOptions(rational_bits=128))
    observed_fractional = False
    for y, choices in product(range(3), product((0, 1), repeat=3)):
        residual = -sampler._lift((y,))
        seen = []
        for i, scalar in enumerate(sampler.scalars):
            def scripted(width, center, *, rng=None, i=i, scalar=scalar):
                nonlocal residual, observed_fractional
                denominator, numerator, bound, after = sampler._path_resources[i]
                assert denominator % center.denominator() == 0
                assert abs(center.numerator()) <= numerator
                assert max(abs(int(center.numerator())).bit_length(),
                           int(center.denominator()).bit_length()) <= 128
                observed_fractional |= center.denominator() != 1
                _, shift, _, _, low, high = scalar.checked_inputs(width, center)
                z = shift + (high if choices[i] else low)
                assert abs(z) <= bound
                residual -= z * vector(ZZ, matrix(ZZ, basis.basis_rows).column(i))
                assert all(abs(x) <= limit for x, limit in zip(residual, after))
                seen.append(i)
                return z
            monkeypatch.setattr(scalar, "sample", scripted)
        result = sampler.sample((y,), rng=NoEntropy())
        assert seen == [2, 1, 0]
        assert result == tuple(int(-x) for x in residual)
    assert observed_fractional
    assert sampler.certificate()["path_resources"]["all_nonaborted_paths"]


def test_nonorthogonal_full_finite_path_law_against_independent_coset_grid(basis, monkeypatch):
    """Execute the actual recursion on every finite scalar-weight path.

    This diagnostic compares NORMALIZED finite scalar weights (abort excluded)
    to a directly enumerated coset Gaussian, not to another GPV implementation.
    Scalar abort is checked separately and included in the actual certificate.
    The grid has a negligible numerical tail for this public width; this test
    is not substituted for the analytic all-center error certificate.
    """
    opts = OnlineOptions(tail_bits=8, mass_bits=48, precision_bits=128,
                         gaussian_abort_bits=32, max_uniform_trials=32)
    sampler = CHKPGPVSampler(basis, 220, epsilon_bits=8, options=opts)
    target, prefix, calls = (2,), (), []
    cache, law = {}, {}
    class NeedDraw(Exception):
        def __init__(self, i, width, center):
            self.key = (i, width, center)
    for i, scalar in enumerate(sampler.scalars):
        def oracle(width, center, *, rng=None, i=i):
            position = len(calls)
            assert i == sampler.dimension - 1 - position
            calls.append(i)
            if position == len(prefix):
                raise NeedDraw(i, width, center)
            return prefix[position]
        monkeypatch.setattr(scalar, "sample", oracle)
    def walk(path, probability):
        nonlocal prefix, calls
        prefix, calls = path, []
        try:
            result = sampler.sample(target, rng=NoEntropy())
        except NeedDraw as request:
            key = request.key
            if key not in cache:
                i, width, center = key
                cache[key] = sampler.scalars[i].finite_distribution(width, center)
            for z, mass in cache[key].items():
                walk(path + (z,), probability * mass)
        else:
            assert result not in law  # Full basis: unique coefficient path.
            assert (result[0] + result[1]) % 3 == 2
            law[result] = probability
            assert len(law) < 10000
    walk((), QQ(1))
    assert sum(law.values()) == 1 and len(law) > 100
    assert any(center < 0 and center.denominator() != 1 for _, _, center in cache)
    # Independent target: exp(-pi*||x||^2/s^2) on A*x=2, no lift/GS here.
    weights = {(x, y): exp(-pi * (x*x + y*y) / 220)
               for x, y in product(range(-40, 41), repeat=2) if (x + y) % 3 == 2}
    total = sum(weights.values())
    reference = {x: w / total for x, w in weights.items()}
    distance = sum(abs(float(law.get(x, 0)) - reference.get(x, 0))
                   for x in set(law) | set(reference)) / 2
    assert distance < 0.005
    assert distance < float(sampler.tv_upper)
    # A wrong +t center or zero-center then +t shifts the distribution; the
    # equation alone cannot catch it, but this full law and moment do.
    mean_x = sum(x[0] * float(p) for x, p in law.items())
    assert abs(mean_x) < 0.02


@pytest.mark.parametrize("syndrome", [0, 2])
def test_empirical_1024_draws_per_syndrome(sampler, syndrome):
    """2048 real vector draws total, not oracle-scripted distribution paths.

    Deterministic seeds are reproducibility evidence only. Tolerances are
    loose diagnostics against independently normalized grid moments, NOT a
    TV proof. Tail here means ||x||^2 > s^2, not the RandBasis norm cutoff.
    """
    count, width = 1024, int(sampler.width_squared)
    rng = DeterministicRandom(f"chkp-gpv-empirical-{syndrome}".encode())
    samples = [sampler.sample((syndrome,), rng=rng) for _ in range(count)]
    assert all((x + y) % 3 == syndrome for x, y in samples)
    weights = {(x, y): exp(-pi * (x*x + y*y) / width)
               for x, y in product(range(-40, 41), repeat=2)
               if (x + y) % 3 == syndrome}
    total = sum(weights.values())
    target = {x: w / total for x, w in weights.items()}
    expected_means = [sum(x[i] * p for x, p in target.items()) for i in range(2)]
    expected_variances = [sum(x[i]**2 * p for x, p in target.items()) - expected_means[i]**2
                          for i in range(2)]
    means = [sum(x[i] for x in samples) / count for i in range(2)]
    variances = [sum((x[i] - means[i])**2 for x in samples) / count for i in range(2)]
    covariance = sum((x[0] - means[0]) * (x[1] - means[1]) for x in samples) / count
    tail_count = sum(x*x + y*y > width for x, y in samples)
    expected_tail = sum(p for (x, y), p in target.items() if x*x + y*y > width)
    assert all(abs(a - b) < 0.9 for a, b in zip(means, expected_means))
    assert all(abs(a - b) < 7 for a, b in zip(variances, expected_variances))
    assert abs(covariance) < 5.5
    assert abs(tail_count - count * expected_tail) < 6 * (count * expected_tail * (1 - expected_tail))**0.5 + 2
    print(json.dumps({
        "experiment": "CHKP GPV empirical public basis", "syndrome": syndrome,
        "vector_draws": count, "scalar_successful_draws": count * 2,
        "vector_aborts": 0, "equation_failures": 0, "width_squared": width,
        "q": 3, "dimension": 2, "epsilon_bits": 8,
        "seed": f"chkp-gpv-empirical-{syndrome}",
        "mean": means, "variance": variances, "covariance": covariance,
        "grid_expected_variance": expected_variances,
        "tail_event": "squared_norm > width_squared", "tail_count": tail_count,
        "grid_expected_tail_count": count * expected_tail, "security_claim": "none",
    }, sort_keys=True))
