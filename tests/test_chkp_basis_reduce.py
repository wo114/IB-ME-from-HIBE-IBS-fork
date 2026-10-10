"""Independent lattice/GS checks for the optional deterministic postprocessor."""

import pytest
pytest.importorskip("sage.all", reason="Run in prescribed WSL Sage; skip is not pass")
from sage.all import QQ, ZZ, identity_matrix, matrix

from experiments.research.chkp_basis import KernelBasis, ModMatrixReference, complete_kernel_basis
from experiments.research.chkp_basis_reduce import reduce_basis, GAMMA, DELTA
from experiments.research.gaussian_reference import SamplingAbort


def skew_basis(d=4, seed=0):
    from random import Random
    rng = Random(seed)
    base = complete_kernel_basis(ModMatrixReference([[1]+[2]*(d-1)], 5))
    b = matrix(ZZ, base.basis_rows)
    for _ in range(4*d):
        if d == 1:
            break
        i, j = rng.sample(range(d), 2)
        b.add_multiple_of_column(i, j, rng.randint(-37, 37))
    return KernelBasis(base.public, b)


@pytest.mark.parametrize("d", [1, 2, 4, 8])
@pytest.mark.parametrize("seed", range(6))
def test_exact_same_lattice_gs_and_lll_conditions(d, seed):
    base = skew_basis(d, seed)
    reduced = reduce_basis(base)
    old, new = matrix(ZZ, base.basis_rows), matrix(ZZ, reduced.basis.basis_rows)
    u = matrix(ZZ, reduced.transform_rows)
    assert old*u == new and abs(u.det()) == 1
    assert old.transpose().hermite_form() == new.transpose().hermite_form()
    old_star, _ = old.transpose().change_ring(QQ).gram_schmidt()
    star, mu = new.transpose().change_ring(QQ).gram_schmidt()
    g = [v.dot_product(v) for v in star.rows()]
    assert max(g) <= max(v.dot_product(v) for v in old_star.rows())
    assert min(g) >= GAMMA**(d-1)
    for i in range(d):
        for j in range(i):
            assert abs(mu[i, j]) <= QQ(1)/2
        if i:
            assert g[i]+mu[i, i-1]**2*g[i-1] >= DELTA*g[i-1]
    assert reduce_basis(base).basis.basis_rows == reduced.basis.basis_rows
    assert reduced.security_claim == "none" and not reduced.backend_admitted


def test_exhaustion_does_not_return_unreduced_basis():
    with pytest.raises(SamplingAbort, match="step budget"):
        reduce_basis(skew_basis(), max_steps=1)


@pytest.mark.parametrize("budget", [0, True, 1.0, 100001])
def test_invalid_budget(budget):
    with pytest.raises(ValueError):
        reduce_basis(skew_basis(), max_steps=budget)


def test_input_limit_and_type():
    with pytest.raises(ValueError):
        reduce_basis(object())
    base = skew_basis(2)
    b = matrix(ZZ, base.basis_rows)
    b.add_multiple_of_column(0, 1, 2**1025)
    with pytest.raises(ValueError, match="bit resource"):
        reduce_basis(KernelBasis(base.public, b))
    large = complete_kernel_basis(ModMatrixReference([[1]+[0]*64], 2))
    with pytest.raises(ValueError, match="dimension resource"):
        reduce_basis(large)


def test_fixed_toy_schedule_has_a_uniform_scalar_width_certificate():
    # Applies to ANY successfully reduced integer level-1 basis of dimension 20
    # satisfying the existing RandBasis upper bound, not just observed samples.
    lower = GAMMA**19
    assert 15952640/lower < 10**12
    assert 15952640 == 4*22*181280
    # A raw squared width of 15952640 is not its statistical variance.
