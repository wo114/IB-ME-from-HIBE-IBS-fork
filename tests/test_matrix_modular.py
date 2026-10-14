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


@pytest.mark.parametrize("rows,q", [(((1,2,3,4),),101),(((0,1,0,2),(0,0,1,3)),101),
    (((1,0,0),(0,1,0)),7),(((0,0,1),),7),(((0,1,1),(1,0,1)),2)])
def test_direct_public_canonical_kernel_matches_unique_column_hnf(rows,q):
    from ibme.lattice.research import ModMatrixReference,KernelBasis
    from experiments.research.chkp_basis import complete_kernel_basis
    from ibme.lattice.matrix_sampling import matrix_canonical_basis
    public=ModMatrixReference(rows,q)
    anchor=complete_kernel_basis(public)
    expected=matrix(ZZ,anchor.basis_rows).transpose().hermite_form().transpose()
    direct=matrix_canonical_basis(anchor)
    assert matrix(ZZ,direct.basis_rows)==expected
    # Different complete private representation must give the same anchor.
    transformation=identity_matrix(ZZ,public.ncols)
    transformation[0,1]=-17
    other=KernelBasis(public,matrix(ZZ,anchor.basis_rows)*transformation)
    assert matrix_canonical_basis(other).basis_rows==direct.basis_rows


def test_integral_triangular_factors_match_rational_solutions_and_reject_fractions():
    from sage.all import QQ
    from ibme.lattice.matrix_sampling.basis import _integral_lower_solve,_integral_right_upper_solve
    lower=matrix(ZZ,[[2,0,0],[3,5,0],[4,-7,11]])
    z=matrix(ZZ,[[3,-2,1],[-8,7,4],[0,12,-5]])
    rhs=lower*z
    assert _integral_lower_solve(lower,rhs)==matrix(QQ,lower).solve_right(matrix(QQ,rhs))
    invalid=matrix(ZZ,rhs.rows());invalid[0,0]+=1
    with pytest.raises(ValueError,match="not in"):_integral_lower_solve(lower,invalid)
    upper=matrix(ZZ,[[2,5,1],[0,3,4],[0,0,7]])
    product=z*upper
    assert _integral_right_upper_solve(product,upper)==z
    assert matrix(QQ,z)==matrix(QQ,upper).transpose().solve_right(matrix(QQ,product).transpose()).transpose()
    invalid=matrix(ZZ,product.rows());invalid[0,0]+=1
    with pytest.raises(ArithmeticError,match="not integral"):_integral_right_upper_solve(invalid,upper)
