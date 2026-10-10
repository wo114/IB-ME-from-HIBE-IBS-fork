"""Finite K and norm ABORT behavior, exact full-lattice postconditions."""

import pytest

pytest.importorskip("sage.all", reason="Use prescribed WSL Sage")
from sage.all import QQ, ZZ, matrix

from ibme.core.randomness import DeterministicRandom
from experiments.research.chkp_basis import (
    ModMatrixReference, complete_kernel_basis, gram_schmidt_squared_lengths,
)
from experiments.research.chkp_gpv import CHKPGPVSampler
from experiments.research.chkp_randbasis import CHKPRandBasis
from experiments.research.gaussian_reference import SamplingAbort


def make():
    basis = complete_kernel_basis(ModMatrixReference([[1, 2]], 5))
    return CHKPGPVSampler(basis, 4096, epsilon_bits=16)


def test_actual_randomization_and_reproducibility():
    generator = CHKPRandBasis(make(), max_vectors=20)
    first = generator.sample(rng=DeterministicRandom(b"chkp-randbasis"))
    again = generator.sample(rng=DeterministicRandom(b"chkp-randbasis"))
    assert first.basis.basis_rows == again.basis.basis_rows
    assert first.draws_used == again.draws_used
    t = matrix(ZZ, first.basis.basis_rows)
    assert abs(t.det()) == 5
    assert all(v % 5 == 0 for v in (matrix(ZZ, [[1, 2]])*t).list())
    assert max(gram_schmidt_squared_lengths(t)) <= 2*4096
    assert first.security_claim == "none" and not first.backend_admitted
    assert "basis_rows" not in repr(first)


def test_dependent_candidates_count_towards_K(monkeypatch):
    sampler = make()
    seen = []
    def dependent(*args, **kwargs):
        seen.append(1)
        return (0, 0)
    monkeypatch.setattr(sampler, "sample", dependent)
    generator = CHKPRandBasis(sampler, max_vectors=3)
    with pytest.raises(SamplingAbort, match="rank budget"):
        generator.sample()
    assert len(seen) == 3


def test_norm_outlier_aborts_whole_call_without_resampling(monkeypatch):
    sampler = make()
    calls = []
    def outlier(*args, **kwargs):
        calls.append(1)
        return (500, 0)
    monkeypatch.setattr(sampler, "sample", outlier)
    with pytest.raises(SamplingAbort, match="norm budget"):
        CHKPRandBasis(sampler, max_vectors=3).sample()
    assert len(calls) == 1


def test_success_after_dependent_vector_completes_strict_sublattice(monkeypatch):
    sampler = make()
    values = iter([(0, 0), (10, 0), (-4, 2)])
    monkeypatch.setattr(sampler, "sample", lambda *a, **kw: next(values))
    result = CHKPRandBasis(sampler, max_vectors=3).sample()
    assert result.draws_used == 3 and abs(matrix(ZZ, result.basis.basis_rows).det()) == 5


def test_underlying_abort_propagates_no_fallback(monkeypatch):
    sampler = make()
    def abort(*a, **kw):
        raise SamplingAbort("injected scalar failure")
    monkeypatch.setattr(sampler, "sample", abort)
    with pytest.raises(SamplingAbort, match="scalar failure"):
        CHKPRandBasis(sampler, max_vectors=3).sample()


@pytest.mark.parametrize("count", [True, 1, 3.5, 4097, "3"])
def test_invalid_attempt_budget(count):
    with pytest.raises(ValueError):
        CHKPRandBasis(make(), max_vectors=count)


def test_certificate_counts_vector_tv_once_and_keeps_aborts():
    sampler = make()
    generator = CHKPRandBasis(sampler, max_vectors=8)
    cert = generator.certificate()
    assert QQ(cert["actual_vs_bounded_ideal_output_tv_upper"]) == min(1, 8*sampler.tv_upper)
    assert QQ(cert["rank_or_norm_or_sampling_failure_upper"]) == min(
        1, generator.rank_upper + 8*generator.tail_upper + 8*sampler.tv_upper)
    assert cert["canonical_complete_lattice_basis"]
    assert not cert["spectral_norm_preservation"]
    assert not cert["backend_admitted"]


def test_wrong_random_tape_length_rejected():
    with pytest.raises(ValueError, match="fixed length"):
        CHKPRandBasis(make(), max_vectors=3).sample_from_tape(b"short")


def test_whole_random_tape_cap_checked_before_sampling(monkeypatch):
    sampler = make()
    monkeypatch.setattr(sampler, "sample", lambda *a, **kw: pytest.fail("unexpected sampling"))
    with pytest.raises(ValueError, match="Whole RandBasis tape"):
        CHKPRandBasis(sampler, max_vectors=4096)
    with pytest.raises(ValueError, match="Whole RandBasis tape"):
        CHKPRandBasis(sampler, max_vectors=2, max_tape_bytes=sampler.random_tape_bytes)


@pytest.mark.parametrize("cap", [True, 0, 1.0, 256*1024*1024+1])
def test_invalid_whole_tape_cap(cap):
    with pytest.raises(ValueError):
        CHKPRandBasis(make(), max_vectors=2, max_tape_bytes=cap)


def test_tape_type_and_length_checked_before_copy(monkeypatch):
    from experiments.research import chkp_randbasis as module
    generator = CHKPRandBasis(make(), max_vectors=3)
    monkeypatch.setattr(module, "FiniteByteTape", lambda *a: pytest.fail("premature tape copy"))
    for bad in ("not bytes", None, [], b"short"):
        with pytest.raises(ValueError, match="fixed length"):
            generator.sample_from_tape(bad)


def test_multibyte_view_checked_by_actual_byte_count(monkeypatch):
    from experiments.research import chkp_randbasis as module
    generator = CHKPRandBasis(make(), max_vectors=3)
    bad = memoryview(bytearray(generator.random_tape_bytes*4)).cast("I")
    assert len(bad) == generator.random_tape_bytes
    monkeypatch.setattr(module, "FiniteByteTape", lambda *a: pytest.fail("oversized copy"))
    with pytest.raises(ValueError, match="fixed length"):
        generator.sample_from_tape(bad)
