"""Native modular results checked against exact field and integer references."""

import pytest
pytest.importorskip("sage.all",reason="prescribed WSL Sage required")
from sage.all import ZZ, GF, matrix, identity_matrix
from ibme.lattice.matrix_sampling.modular import modular_inverse, modular_determinant


@pytest.mark.parametrize("q",[101,2**61-1,int(ZZ(2**159).next_prime())])
def test_native_exact_inverse_and_determinant_match_field(q):
    r=matrix(ZZ,[[1,3,-2],[0,1,8],[0,0,1]])
    expected=matrix(GF(q),r).inverse()
    actual=modular_inverse(r,q)
    assert matrix(GF(q),actual)==expected
    assert modular_determinant(r,q)==1
    assert all(x%q==0 for x in (r*actual-identity_matrix(ZZ,3)).list())


def test_singular_is_not_identity_or_approximate_fallback():
    r=((1,2),(2,4))
    assert modular_determinant(r,101)==0
    with pytest.raises(Exception):modular_inverse(r,101)


@pytest.mark.parametrize("rows,q",[(((True,),),101),(((1.0,),),101),(((1,2),),101),(((1,),),9),(((1,),),True)])
def test_native_input_gates(rows,q):
    with pytest.raises(ValueError):modular_inverse(rows,q)


def test_native_whole_matrix_sampling_preserves_legacy_tape_and_outputs():
    from ibme.core.randomness import DeterministicRandom
    from ibme.hibe.abb_rom import MatrixSampleR, FiniteSampleR
    for seed in (b"native-whole-matrix-A", b"native-whole-matrix-B"):
        native, legacy = MatrixSampleR(101,8,16), FiniteSampleR(101,8,16)
        left = native.sample(rng=DeterministicRandom(seed))
        right = legacy.sample(rng=DeterministicRandom(seed))
        assert left.rows == right.rows and left.matrices_sampled == right.matrices_sampled
        assert native.last_entropy_bytes == legacy.last_entropy_bytes
    certificate = native.certificate()
    assert certificate["total_failure_upper"] is None
    assert certificate["conditional_success_vs_ideal_invertible_matrix_tv_upper"] is None


def test_native_whole_matrix_singularity_discards_all_columns(monkeypatch):
    from ibme.hibe.abb_rom import MatrixSampleR
    sampler=MatrixSampleR(101,2,16,max_matrices=2)
    values=iter([0,0,0,0,1,0,0,1])
    monkeypatch.setattr(sampler.scalar,"sample",lambda *args,**kwargs:next(values))
    result=sampler.sample()
    assert result.rows==((1,0),(0,1)) and result.matrices_sampled==2


def test_proved_padic_completion_matches_legacy_full_lattice_output():
    from ibme.core.randomness import DeterministicRandom
    from ibme.hibe.abb_rom import FiniteSampleR, prepare_basis_del, prepare_matrix_basis_del
    from ibme.lattice.research import ModMatrixReference
    from experiments.research.chkp_basis import complete_kernel_basis
    public=ModMatrixReference(((1,2,3,4),(0,1,7,9)),101)
    parent=complete_kernel_basis(public)
    transform=FiniteSampleR(101,4,16).sample(rng=DeterministicRandom(b"p-adic-canonical-HNF")).rows
    legacy=prepare_basis_del(parent,transform)
    native=prepare_matrix_basis_del(parent,transform)
    assert native.target_public==legacy.target_public
    assert native.completed_basis.basis_rows==legacy.completed_basis.basis_rows
    assert native.transformed_sublattice_index==legacy.transformed_sublattice_index
