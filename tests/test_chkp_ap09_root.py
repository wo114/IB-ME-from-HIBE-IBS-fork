"""Real AP09 GenBasis roots, exact algebra, finite abort, and public bounds."""

from dataclasses import replace

import pytest

pytest.importorskip("sage.all", reason="Run in WSL ~/miniconda3/envs/sage")
from sage.all import GF, QQ, ZZ, matrix

from ibme.core.errors import InvalidParameterError, RandomnessError
from ibme.core.randomness import DeterministicRandom
from ibme.lattice.chkp.ap09_root import AP09RootGenerator, AP09RootParams
from ibme.lattice.chkp.basis import gram_schmidt_squared_lengths
from ibme.lattice.chkp.gaussian import SamplingAbort


def small_params():
    return AP09RootParams(n=1, q=5, random_rows=6, m1=6, m2=24,
                          hadamard_scale=8)


def assert_real_root(result):
    p = result.params
    a = matrix(GF(p.q), result.basis.public.rows)
    s = matrix(ZZ, result.basis.basis_rows)
    assert (a.nrows(), a.ncols()) == (p.n, p.dimension)
    assert a.rank() == p.n
    assert a * matrix(GF(p.q), s) == 0
    assert abs(s.det()) == p.q**p.n
    assert max(gram_schmidt_squared_lengths(s)) <= result.public_gs_squared_bound
    assert 0 < result.entropy_bytes <= p.random_tape_bytes
    assert result.public_generation_certificate["complete_kernel_checked"]
    assert result.security_claim == "none" and not result.backend_admitted


def test_real_root_replay_and_system_entropy():
    p = small_params()
    generator = AP09RootGenerator(p)
    first = generator.generate(rng=DeterministicRandom(b"chkp-ap09-root"))
    replay = generator.generate(rng=DeterministicRandom(b"chkp-ap09-root"))
    system = generator.generate()
    assert_real_root(first)
    assert_real_root(system)
    assert first.basis == replay.basis
    assert first.public_generation_certificate["entropy_source"] == "deterministic-test"
    assert system.public_generation_certificate["entropy_source"] == "system"
    assert first.basis.public != system.basis.public
    assert "basis_rows" not in repr(first)


def test_two_row_nontrivial_complete_kernel_and_gs():
    class FullRankPrefix:
        prefix = iter([1, 1, 0, 2, 1, 0, 1, 1, 0, 2])
        tail = DeterministicRandom(b"chkp-ap09-two-row-tail")

        def read(self, size):
            value = next(self.prefix, None)
            if value is not None:
                assert size == 1
                return bytes([value])
            return self.tail.read(size)

    p = AP09RootParams(n=2, q=3, random_rows=5, m1=5, m2=18,
                       hadamard_scale=8)
    result = AP09RootGenerator(p).generate(rng=FullRankPrefix())
    assert_real_root(result)


def test_nonvacuous_statistical_profile_generates_real_root():
    p = AP09RootParams(n=1, q=257, random_rows=24, m1=24, m2=80,
                       hadamard_scale=16)
    assert p.certificate()["near_uniform_bound_nonvacuous"]
    result = AP09RootGenerator(p).generate(rng=DeterministicRandom(b"ap09-q257-root"))
    assert_real_root(result)


def test_near_uniform_certificate_is_upward_rounded_and_bounded():
    p = AP09RootParams(n=1, q=65537, random_rows=48, m1=48, m2=160,
                       hadamard_scale=24)
    certificate = p.certificate()
    tv = QQ(certificate["paper_matrix_tv_upper_before_rank_abort"])
    target = QQ(p.m2**2 * p.q**p.n) / 2**p.random_rows
    assert 0 < tv < 1 and tv**2 >= target
    assert (tv - QQ(p.m2) / 2**256)**2 < target
    assert QQ(certificate["output_vs_uniform_tv_upper_including_abort"]) < 1
    assert certificate["near_uniform_bound_nonvacuous"]
    assert certificate["security_claim"] == "none"
    assert not certificate["backend_admitted"]
    assert not certificate["CHKP_HIBE_verified"]


def test_rank_abort_is_one_attempt_without_fallback():
    class Zero:
        calls = 0

        def read(self, size):
            self.calls += 1
            return bytes(size)

    source = Zero()
    with pytest.raises(SamplingAbort, match="rank failure"):
        AP09RootGenerator(small_params()).generate(rng=source)
    assert source.calls == small_params().n * small_params().m1


def test_uniform_rejection_and_rng_type_rejected():
    class Ones:
        def read(self, size):
            return b"\xff" * size

    with pytest.raises(SamplingAbort, match="Uniform"):
        AP09RootGenerator(replace(small_params(), uniform_trials=1)).generate(rng=Ones())

    class WrongType:
        def read(self, size):
            return bytearray(size)

    with pytest.raises(RandomnessError):
        AP09RootGenerator(small_params()).generate(rng=WrongType())


@pytest.mark.parametrize("change", [
    {"q": 2}, {"q": 9}, {"n": True}, {"n": 1.0}, {"random_rows": 2},
    {"m1": 5}, {"m2": 15}, {"hadamard_scale": 1},
    {"max_entropy_bytes": 1}, {"m2": 1536},
])
def test_invalid_params_rejected_before_entropy(change):
    with pytest.raises(InvalidParameterError):
        replace(small_params(), **change)
