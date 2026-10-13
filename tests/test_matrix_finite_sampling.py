"""A3 explicit wide profiles, unchanged legacy laws, real matrix consumers."""

from dataclasses import asdict
from fractions import Fraction
import importlib.util
from pathlib import Path
import sys
import math

import pytest
pytest.importorskip("sage.all", reason="prescribed WSL Sage required; skip is not pass")
from sage.all import GF, QQ, ZZ, matrix, identity_matrix

from ibme.core.errors import RandomnessError
from ibme.core.randomness import DeterministicRandom, SecureRandom
from ibme.lattice.research import KernelBasis, ModMatrixReference, FirstFiniteOptions, FirstFiniteGaussian, FirstFiniteGPV
from ibme.lattice.matrix_sampling import (MatrixFiniteOptions, MatrixFiniteGaussian, MatrixFiniteGPV,
    MatrixBasisLimits, matrix_to_basis, matrix_canonical_basis, MatrixFiniteRandBasis, matrix_checked_lll)
from experiments.research.chkp_basis import complete_kernel_basis


class NoEntropy:
    def read(self, count):
        raise AssertionError("inadmissible input consumed entropy")


@pytest.mark.parametrize("width", [2**96, 2**160, 2**192])
def test_wide_scalar_actual_gaussian_statistics_and_old_guard(width):
    with pytest.raises(ValueError):
        FirstFiniteGaussian(width, width)
    sampler = MatrixFiniteGaussian(width, width)
    cert = sampler.certificate()
    assert cert["profile"] == "MATRIX-FINITE-DGS/1"
    assert sampler.tail_upper <= QQ(1)/2**128
    assert sampler.tv_upper < QQ(1)/2**120
    assert cert["support_or_centers_precomputed"] == 0 and cert["CDF_tables"] == 0
    rng = DeterministicRandom(b"matrix-wide-statistics-" + str(width).encode())
    values = [sampler.sample(width, Fraction(1, 3), rng=rng) for _ in range(512)]
    mean = sum(values) / len(values)
    variance = width / (2 * math.pi)
    empirical = sum((x - mean)**2 for x in values) / len(values)
    assert abs(mean - 1/3) < 6 * math.sqrt(variance / len(values))
    assert 0.70 < empirical/variance < 1.30
    assert all(type(x) is int for x in values)
    assert all(abs(QQ(x)-QQ(1)/3) <= sampler.radius+1 for x in values)


def test_shared_scalar_matches_legacy_every_byte_in_overlap():
    args = dict(tail_bits=64, mass_bits=128, precision_bits=192, gaussian_abort_bits=64,
                max_uniform_trials=128, max_radius=2**48, rational_bits=8192, max_tape_bytes=2**40)
    old = FirstFiniteGaussian(9, 9, options=FirstFiniteOptions(**args))
    wide = MatrixFiniteGaussian(9, 9, options=MatrixFiniteOptions(**args))
    for center in ["0", "1/3", "-17/7"]:
        a, b = DeterministicRandom(b"matrix-scalar-overlap"), DeterministicRandom(b"matrix-scalar-overlap")
        assert old.finite_distribution(9, center) == wide.finite_distribution(9, center)
        assert [old.sample(9, center, rng=a) for _ in range(64)] == [wide.sample(9, center, rng=b) for _ in range(64)]
    assert old.checked_inputs("9", "1/1000") == old.checked_inputs(9, Fraction(1, 1000))
    with pytest.raises(ValueError):
        old.checked_inputs("9.0", "1/1000")  # prescribed Sage QQ also rejects this text


def test_default_entropy_is_real_and_injectable(monkeypatch):
    import ibme.lattice.matrix_sampling.scalar as module
    calls = []
    class Recorded:
        def __init__(self):
            self.source = SecureRandom()
        def read(self, size):
            calls.append(size)
            return self.source.read(size)
    monkeypatch.setattr(module, "SecureRandom", Recorded)
    sampler = MatrixFiniteGaussian(2**160, 2**160)
    assert type(sampler.sample(2**160, "1/3")) is int
    assert calls and sum(calls) <= sampler.random_tape_bytes
    assert not sampler.certificate()["native_Sage_rng_used"]


@pytest.mark.parametrize("change", [
    {"max_radius": 2**113}, {"rational_bits": 65537}, {"max_tape_bytes": 2**45},
    {"mass_bits": True}, {"precision_bits": 1.0},
])
def test_wide_options_are_bounded_exact_inputs(change):
    with pytest.raises(ValueError):
        MatrixFiniteOptions(**change)


def test_wide_limits_are_not_implicit_legacy_upgrades():
    expected = dict(tail_bits=128, mass_bits=256, precision_bits=320, gaussian_abort_bits=128,
        max_uniform_trials=192, max_gaussian_trials=100000, max_radius=2**48,
        rational_bits=8192, max_tape_bytes=2**40)
    assert asdict(FirstFiniteOptions()) == expected
    for change in [{"max_radius": 2**49}, {"rational_bits": 8193}, {"max_tape_bytes": 2**41}]:
        with pytest.raises(ValueError):
            FirstFiniteOptions(**change)
    with pytest.raises(ValueError):
        FirstFiniteGaussian(9, 9, options=MatrixFiniteOptions())
    with pytest.raises(ValueError):
        MatrixFiniteGaussian(2**193, 2**193)


@pytest.mark.parametrize("bad", [True, "1e99999999", "1/" + "0"*200000, 1.5])
def test_invalid_rational_rejected_before_parser_or_entropy(bad):
    sampler = MatrixFiniteGaussian(9, 9)
    with pytest.raises(ValueError):
        sampler.sample(9, bad, rng=NoEntropy())


def test_rng_errors_are_not_retried_or_substituted():
    class Bad:
        calls = 0
        def read(self, n):
            self.calls += 1
            return bytearray(n)
    bad = Bad()
    with pytest.raises(RandomnessError):
        MatrixFiniteGaussian(9, 9).sample(9, rng=bad)
    assert bad.calls == 1


def test_wide_gpv_real_coset_sampling_over_legacy_width():
    basis = complete_kernel_basis(ModMatrixReference(((1, 2),), 17))
    with pytest.raises(ValueError):
        FirstFiniteGPV(basis, 2**160, epsilon_bits=128)
    sampler = MatrixFiniteGPV(basis, 2**160, epsilon_bits=128)
    a = DeterministicRandom(b"matrix-wide-gpv-required")
    samples = [sampler.sample((7,), rng=a) for _ in range(8)]
    assert all((x[0] + 2*x[1]) % 17 == 7 for x in samples)
    assert len(set(samples)) == 8
    assert sampler.certificate()["profile"] == "MATRIX-FINITE-GPV/1"
    assert sampler.tv_upper < QQ(1)/2**120
    assert sampler.sample((3,))[0] is not None  # separate system-byte call


def test_wide_gpv_dimension_is_real_not_only_an_advertised_cap():
    basis = complete_kernel_basis(ModMatrixReference(((1,) + (0,)*256,), 3))
    with pytest.raises(ValueError):
        FirstFiniteGPV(basis, 2**18)
    sampler = MatrixFiniteGPV(basis, 2**18, epsilon_bits=128)
    sample = sampler.sample((1,), rng=DeterministicRandom(b"matrix-257-required"))
    assert len(sample) == 257 and sample[0] % 3 == 1
    assert all(type(x) is int for x in sample)


def test_wide_gpv_arithmetic_content_is_checked_before_entropy():
    basis = complete_kernel_basis(ModMatrixReference(((1, 2),), 17))
    with pytest.raises(ValueError, match="content"):
        MatrixFiniteGPV(basis, 2**18, max_arithmetic_content_bytes=1)
    with pytest.raises(ValueError):
        MatrixFiniteGPV(basis, 2**18, max_dimension=1537)
    with pytest.raises(ValueError):
        MatrixFiniteGPV(basis, 2**18, max_arithmetic_content_bytes=True)
    sampler = MatrixFiniteGPV(basis, 2**18)
    with pytest.raises(ValueError):
        sampler.sample((17,), rng=NoEntropy())


def test_gpv_same_algorithm_and_random_tape_in_overlap():
    basis = complete_kernel_basis(ModMatrixReference(((1, 2),), 17))
    kwargs = dict(tail_bits=64, mass_bits=128, precision_bits=192, gaussian_abort_bits=64,
                  max_uniform_trials=128, max_radius=2**48, rational_bits=8192, max_tape_bytes=2**40)
    old = FirstFiniteGPV(basis, 2**18, epsilon_bits=32, options=FirstFiniteOptions(**kwargs))
    new = MatrixFiniteGPV(basis, 2**18, epsilon_bits=32, options=MatrixFiniteOptions(**kwargs))
    a, b = DeterministicRandom(b"matrix-gpv-overlap"), DeterministicRandom(b"matrix-gpv-overlap")
    assert old.random_tape_bytes == new.random_tape_bytes
    assert [old.sample((i % 17,), rng=a) for i in range(64)] == [new.sample((i % 17,), rng=b) for i in range(64)]


def test_wide_complete_basis_above_legacy_limit_and_gs_quality():
    from experiments.research.chkp_tobasis import to_basis
    basis = complete_kernel_basis(ModMatrixReference(((1,) + (0,)*192,), 3))
    s = 2 * matrix(ZZ, basis.basis_rows)
    with pytest.raises(ValueError):
        to_basis(s, basis)
    output = matrix_to_basis(s, basis)
    assert abs(matrix(ZZ, output.basis_rows).det()) == 3
    assert matrix_canonical_basis(output).basis_rows == matrix_canonical_basis(basis).basis_rows
    assert output.public.ncols == 193


def test_triangular_completion_matches_legacy_dense_outputs():
    from experiments.research.chkp_tobasis import to_basis
    from random import Random
    basis = complete_kernel_basis(ModMatrixReference(((1, 2, 3, 4),), 17))
    b = matrix(ZZ, basis.basis_rows)
    for seed in range(8):
        source = Random(seed)
        u = identity_matrix(ZZ, 4)
        for _ in range(8):
            i, j = source.sample(range(4), 2)
            u.add_multiple_of_column(i, j, source.randint(-10, 10))
        r = matrix(ZZ, [[i + 2 if i == j else source.randint(-3, 3) if i < j else 0
                         for j in range(4)] for i in range(4)])
        s = b * u * r
        legacy = to_basis(s, basis)
        current = matrix_to_basis(s, basis)
        assert current.basis_rows == legacy.basis_rows
        assert abs(matrix(ZZ, current.basis_rows).det()) == 17


def test_completion_resource_estimate_is_an_explicit_gate():
    from ibme.lattice.matrix_sampling.basis import admit_transform_content
    with pytest.raises(ValueError, match="estimate"):
        admit_transform_content(1280, 200, limits=MatrixBasisLimits(max_transform_content_bytes=1))
    with pytest.raises(ValueError):
        MatrixBasisLimits(max_dimension=1537)
    with pytest.raises(ValueError):
        MatrixBasisLimits(max_transform_content_bytes=True)
    assert admit_transform_content(16, 100) > 0


def test_fixed_matrix_normalizer_checks_exact_quality_and_full_lattice():
    from experiments.research.chkp_basis import gram_schmidt_squared_lengths
    basis = complete_kernel_basis(ModMatrixReference(((1,2,3,4),),17))
    u = identity_matrix(ZZ,4)
    u[0,3] = 2**100
    skew = KernelBasis(basis.public,matrix(ZZ,basis.basis_rows)*u)
    before = gram_schmidt_squared_lengths(skew.basis_rows)
    normalized = matrix_checked_lll(skew,max(before))
    after = gram_schmidt_squared_lengths(normalized.basis_rows)
    assert normalized.public == skew.public and max(after) <= max(before)
    assert abs(matrix(ZZ,normalized.basis_rows).det()) == 17
    star = matrix(QQ,normalized.basis_rows).transpose().gram_schmidt()[0]
    for j in range(4):
        for i in range(j):
            mu = matrix(ZZ,normalized.basis_rows).column(j).dot_product(star.row(i))/after[i]
            assert abs(mu) <= QQ(1)/2
            if i == j-1:
                assert after[j]+mu**2*after[i] >= QQ(74)/100*after[i]
    with pytest.raises(ArithmeticError,match="GS"):
        matrix_checked_lll(skew,QQ(1)/100)


def test_modular_hint_has_exact_integer_fallback_not_modular_filter():
    from ibme.lattice.matrix_sampling.randbasis import _ExactIndependenceHint
    from sage.all import vector
    chosen = [vector(ZZ, [65521, 0])]
    # Simulate accepting the first row, whose modular image is zero.
    hint = _ExactIndependenceHint(2, 17)
    assert hint.accept(chosen[0], []) and not hint.enabled
    assert hint.accept(vector(ZZ, [0, 65521]), chosen)
    assert not hint.accept(vector(ZZ, [2*65521, 0]), chosen)
    ordinary = _ExactIndependenceHint(2, 65521)
    assert ordinary.field.order() != 65521
    assert ordinary.accept(vector(ZZ, [0, 1]), [])
    assert ordinary.accept(vector(ZZ, [1, 0]), [vector(ZZ, [0, 1])])


def test_real_wide_randbasis_preserves_complete_lattice_and_abort(monkeypatch):
    from experiments.research.gaussian_reference import SamplingAbort
    basis = complete_kernel_basis(ModMatrixReference(((1, 2),), 17))
    sampler = MatrixFiniteGPV(basis, 2**160, epsilon_bits=128)
    randomizer = MatrixFiniteRandBasis(sampler, max_vectors=66)
    result = randomizer.sample(rng=DeterministicRandom(b"matrix-wide-RandBasis"))
    assert result.basis.public == basis.public and result.independent_vectors == 2
    assert abs(matrix(ZZ, result.basis.basis_rows).det()) == 17
    cert = randomizer.certificate()
    assert cert["profile"] == "MATRIX-FINITE-RANDBASIS/1"
    assert cert["full_failure_upper_including_workspace"] is None
    assert cert["integer_rank_hint_rejection"] is False
    calls = []
    def outside(target, *, rng=None):
        calls.append(1)
        return (17*2**200, 0)
    monkeypatch.setattr(sampler, "sample", outside)
    with pytest.raises(SamplingAbort, match="norm"):
        randomizer.sample(rng=NoEntropy())
    assert len(calls) == 1


def test_abb_consumes_same_wide_tools_for_two_real_delegations():
    from ibme.hibe.abb_rom import MatrixSampleR, MatrixBasisDel, FiniteSampleR
    q, m = 101, 16
    root = complete_kernel_basis(ModMatrixReference((tuple((j*j+3)%q for j in range(m)),), q))
    sampler = MatrixSampleR(q, m, 16)
    first_r = sampler.sample(rng=DeterministicRandom(b"matrix-wide-H1"))
    second_r = sampler.sample(rng=DeterministicRandom(b"matrix-wide-H2"))
    first = MatrixBasisDel(root, first_r.rows, 2**100, reduce_completion=True)
    first_result = first.sample(rng=DeterministicRandom(b"matrix-wide-parent"))
    second = MatrixBasisDel(first_result.basis, second_r.rows, 2**160, reduce_completion=True)
    second_result = second.sample(rng=DeterministicRandom(b"matrix-wide-child"))
    a = matrix(GF(q), root.public.rows)
    f = a.base_ring()
    expected = a * matrix(f, first_r.rows).inverse() * matrix(f, second_r.rows).inverse()
    assert matrix(f, second_result.basis.public.rows) == expected
    assert abs(matrix(ZZ, second_result.basis.basis_rows).det()) == q
    assert first_result.basis.public.ncols == second_result.basis.public.ncols == m
    assert isinstance(first.sampler, MatrixFiniteGPV)
    assert first.sampler.scalars[0].certificate()["profile"] == "MATRIX-FINITE-DGS/1"
    assert sampler.certificate()["profile"] != FiniteSampleR(q, m, 16).certificate()["profile"]


def test_immutable_original_provider_differential():
    folder = Path(__file__).resolve().parents[1]/"test-results/matrix-original-providers"
    if not (folder/"finite_gaussian.py").is_file() or not (folder/"finite_gpv.py").is_file():
        pytest.skip("explicit f6090c9 original source snapshots required")
    def load(name):
        package = "experiments.research" if name == "tobasis" else "experiments.research.first_suite"
        qualified = package + "._matrix_original_" + name
        spec = importlib.util.spec_from_file_location(qualified, folder/(name + ".py"))
        module = importlib.util.module_from_spec(spec)
        sys.modules[qualified] = module
        spec.loader.exec_module(module)
        return module
    original_scalar = load("finite_gaussian")
    original_gpv = load("finite_gpv")
    for width, center in [(9, "1/3"), (2**80, "-17/7")]:
        before = original_scalar.FirstFiniteGaussian(width, width)
        after = FirstFiniteGaussian(width, width)
        a, b = DeterministicRandom(b"original-scalar-bytes"), DeterministicRandom(b"original-scalar-bytes")
        assert before.certificate() == after.certificate()
        assert [before.sample(width, center, rng=a) for _ in range(32)] == [after.sample(width, center, rng=b) for _ in range(32)]
    basis = complete_kernel_basis(ModMatrixReference(((1, 2),), 17))
    before = original_gpv.FirstFiniteGPV(basis, 2**18, epsilon_bits=128)
    after = FirstFiniteGPV(basis, 2**18, epsilon_bits=128)
    a, b = DeterministicRandom(b"original-gpv-bytes"), DeterministicRandom(b"original-gpv-bytes")
    assert before.certificate() == after.certificate()
    assert [before.sample((3,), rng=a) for _ in range(32)] == [after.sample((3,), rng=b) for _ in range(32)]
    if (folder/"tobasis.py").is_file() and (folder/"finite_randbasis.py").is_file():
        original_basis = load("tobasis")
        original_randomizer = load("finite_randbasis")
        from experiments.research.first_suite.finite_randbasis import FirstFiniteRandBasis
        sampler = FirstFiniteGPV(basis, 2**18, epsilon_bits=128)
        before = original_randomizer.FirstFiniteRandBasis(sampler, max_vectors=66)
        after = FirstFiniteRandBasis(sampler, max_vectors=66)
        a, b = DeterministicRandom(b"original-randbasis-bytes"), DeterministicRandom(b"original-randbasis-bytes")
        left, right = before.sample(rng=a), after.sample(rng=b)
        assert before.certificate() == after.certificate()
        assert left.basis.basis_rows == right.basis.basis_rows
        assert left.draws_used == right.draws_used
        assert original_basis.to_basis(matrix(ZZ, basis.basis_rows)*2, basis).basis_rows == matrix_to_basis(matrix(ZZ, basis.basis_rows)*2, basis).basis_rows
