"""External reduction proposals must retain the complete lattice and gates."""
from dataclasses import replace
import pytest

pytest.importorskip("sage.all", reason="prescribed WSL Sage required")
from sage.all import QQ, ZZ, matrix, identity_matrix
from experiments.research.chkp_basis import ModMatrixReference, KernelBasis, complete_kernel_basis
from ibme.lattice.matrix_sampling import basis as module
from ibme.hibe.abb_rom.params import ABBROMParams


def fixture():
    basis = complete_kernel_basis(ModMatrixReference(((1, 2, 3, 4),), 17))
    change = identity_matrix(ZZ, 4)
    change[0, 3] = 2**2000
    return KernelBasis(basis.public, matrix(ZZ, basis.basis_rows)*change)


def test_real_external_preconditioner_then_exact_quality():
    from sage.features.flatter import flatter
    if not flatter().is_present():
        pytest.skip("explicit local Flatter installation required")
    original = fixture()
    result = module.matrix_checked_lll(original, 2**4100, preconditioner="flatter")
    assert result.public == original.public
    assert abs(matrix(ZZ, result.basis_rows).det()) == 17
    gso = matrix(QQ, result.basis_rows).transpose().gram_schmidt()[0]
    lengths = [v.dot_product(v) for v in gso.rows()]
    for j in range(4):
        for i in range(j):
            mu = matrix(ZZ, result.basis_rows).column(j).dot_product(gso.row(i))/lengths[i]
            assert abs(mu) <= QQ(1)/2
            if i == j-1:
                assert lengths[j]+mu**2*lengths[i] >= QQ(74)/100*lengths[i]


@pytest.mark.parametrize("kind", ["zero", "foreign", "sublattice"])
def test_bad_external_output_cannot_enter_sampler(monkeypatch, kind):
    original = fixture()
    if kind == "zero": bad = matrix(ZZ, 4, 4)
    elif kind == "foreign": bad = identity_matrix(ZZ, 4)
    else: bad = 2*matrix(ZZ, original.basis_rows).transpose()
    monkeypatch.setattr(module, "_flatter_rows", lambda rows: bad)
    with pytest.raises(ValueError):
        module.matrix_checked_lll(original, 2**4100, preconditioner="flatter")


def test_parameter_snapshot_names_the_predeclared_strategy():
    old = ABBROMParams()
    new = replace(old, normalization="matrix-flatter-lll-075-0501-exact074-v2")
    assert ABBROMParams.from_bytes(old.to_bytes()) == old
    assert ABBROMParams.from_bytes(new.to_bytes()) == new
    assert new.to_bytes() != old.to_bytes()
    with pytest.raises(ValueError):
        module.matrix_checked_lll(fixture(), 2**4100, preconditioner="auto")
