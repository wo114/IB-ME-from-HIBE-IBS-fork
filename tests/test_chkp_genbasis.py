"""AP09 block identities, exact full lattice, finite quality and ABORT gates."""

import pytest

pytest.importorskip("sage.all", reason="Use prescribed WSL Sage")
from sage.all import QQ, ZZ, identity_matrix, matrix

from ibme.core.randomness import DeterministicRandom
from experiments.research.chkp_basis import (
    ModMatrixReference, complete_kernel_basis, gram_schmidt_squared_lengths,
)
from experiments.research.chkp_tobasis import canonical_basis
from experiments.research.chkp_genbasis import (
    AP09Parameters, _components, gen_basis, genbasis_certificate,
)
from experiments.research.gaussian_reference import SamplingAbort


def params():
    return AP09Parameters(n=1, q=2, random_rows=2, m1=2, m2=8, hadamard_scale=4)


@pytest.mark.parametrize("seed", range(8))
def test_real_blocks_full_kernel_and_gs_bound(seed):
    cfg = params()
    try:
        generated = gen_basis(cfg, rng=DeterministicRandom(f"ap09-{seed}".encode()))
    except SamplingAbort as exc:
        # Rank ABORT is a legitimate output, not counted as successful generation.
        assert "rank failure" in str(exc)
        return
    basis = generated.basis
    a, s = matrix(ZZ, basis.public.rows), matrix(ZZ, basis.basis_rows)
    assert (a.nrows(), a.ncols()) == (1, 10)
    assert all(x % cfg.q == 0 for x in (a*s).list())
    assert abs(s.det()) == cfg.q**cfg.n
    independent = complete_kernel_basis(basis.public)
    assert canonical_basis(basis).basis_rows == canonical_basis(independent).basis_rows
    assert max(gram_schmidt_squared_lengths(s)) <= cfg.gs_squared_bound
    assert generated.security_claim == "none" and not generated.backend_admitted


def test_components_without_gaussian_or_lll_substitution():
    cfg = AP09Parameters(n=1, q=5, random_rows=6, m1=6, m2=24)
    basis = complete_kernel_basis(ModMatrixReference([[1, 2, 3, 4, 0, 1]], 5))
    h = matrix(ZZ, canonical_basis(basis).basis_rows)
    g, p, u = _components(cfg, h)
    assert g*p + identity_matrix(ZZ, 6) == h
    assert u.det() == 1
    assert max(col.dot_product(col) for col in u.columns()) <= 5
    assert set(p.list()) <= {0, 1}
    assert max(col.dot_product(col) for col in (g*u).columns()) <= cfg.hadamard_scale**2*cfg.random_rows


def test_required_success_odd_prime_two_rows_nontrivial_hnf():
    # This MUST succeed: the seed sweep's legitimate ABORT branches may not
    # allow an always-aborting implementation to pass the full suite.
    class FullRankPrefix:
        prefix = iter([1, 1, 0, 2, 1, 0, 1, 1, 0, 2])
        tail = DeterministicRandom(b"ap09-required-success")
        def read(self, size):
            value = next(self.prefix, None)
            if value is not None:
                assert size == 1
                return bytes([value])
            return self.tail.read(size)
    cfg = AP09Parameters(n=2, q=3, random_rows=5, m1=5, m2=18)
    result = gen_basis(cfg, rng=FullRankPrefix())
    a, s = matrix(ZZ, result.basis.public.rows), matrix(ZZ, result.basis.basis_rows)
    assert (a.nrows(), a.ncols()) == (2, 23)
    assert all(x % 3 == 0 for x in (a*s).list())
    assert abs(s.det()) == 9
    assert max(gram_schmidt_squared_lengths(s)) <= cfg.gs_squared_bound
    assert canonical_basis(result.basis).basis_rows == canonical_basis(
        complete_kernel_basis(result.basis.public)).basis_rows


def test_nonvacuous_matrix_tv_is_an_upward_square_root_bound():
    cfg = AP09Parameters(n=1, q=3, random_rows=16, m1=16, m2=36,
                         hadamard_scale=16)
    cert = genbasis_certificate(cfg)
    bound = QQ(cert["unconditioned_paper_matrix_tv_upper"])
    squared_target = QQ(cfg.m2**2 * cfg.q**cfg.n)/2**cfg.random_rows
    assert 0 < bound < 1 and bound**2 >= squared_target
    assert (bound - QQ(cfg.m2)/2**80)**2 < squared_target
    assert cert["near_uniform_bound_nonvacuous"]


def test_A1_rank_failure_no_hidden_retry():
    class Zero:
        calls = 0
        def read(self, size):
            self.calls += 1
            return bytes(size)
    source = Zero()
    with pytest.raises(SamplingAbort, match="rank failure"):
        gen_basis(params(), rng=source)
    assert source.calls == 2


def test_uniform_rejection_exhaustion_no_fallback():
    class Ones:
        def read(self, size):
            return b"\xff"*size
    cfg = AP09Parameters(n=1, q=5, random_rows=6, m1=6, m2=24, max_uniform_trials=1)
    with pytest.raises(SamplingAbort, match="Uniform"):
        gen_basis(cfg, rng=Ones())


def test_certificate_separates_vacuous_bound_from_actual_equations():
    cert = genbasis_certificate(params())
    assert cert["quality_bad_probability_inside_admitted_domain"] == "0"
    assert QQ(cert["ideal_A1_rank_abort_upper"]) == QQ(1)/4
    assert not cert["near_uniform_bound_nonvacuous"]
    assert not cert["backend_admitted"]
    assert cert["security_claim"] == "none"


@pytest.mark.parametrize("patch", [
    {"q": 4}, {"n": True}, {"m1": 1}, {"m2": 5},
    {"hadamard_scale": 1}, {"random_rows": 1}, {"q": 2.0}, {"m2": 193},
])
def test_invalid_finite_domain_rejected(patch):
    values = dict(n=1, q=2, random_rows=2, m1=2, m2=8, hadamard_scale=4)
    values.update(patch)
    with pytest.raises(ValueError):
        AP09Parameters(**values)
