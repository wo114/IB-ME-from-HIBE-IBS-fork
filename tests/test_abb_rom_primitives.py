"""ABB mathematical/finite primitive scope, not a completed HIBE theorem."""

from fractions import Fraction
from itertools import chain
from pathlib import Path
import json
import pytest
pytest.importorskip("sage.all",reason="prescribed WSL Sage required; skip is not pass")
from sage.all import GF,QQ,ZZ,identity_matrix,matrix

from ibme.core.errors import InvalidParameterError,RandomnessError
from ibme.core.randomness import DeterministicRandom
from ibme.hibe.abb_rom import FiniteSampleR,FiniteBasisDel,prepare_basis_del,prefix_matrices
from ibme.lattice.research import KernelBasis,ModMatrixReference,SamplingAbort
from experiments.research.chkp_basis import complete_kernel_basis,gram_schmidt_squared_lengths
from experiments.research.ibme_joint_parameters import smoothing_factor


class NoEntropy:
    def read(self,n):raise AssertionError("preflight consumed entropy")


def fixture_basis(m=16,q=101):
    a=ModMatrixReference(tuple(tuple(int(i==j) if j<2 else (3*(i+1)+j*j)%q
        for j in range(m)) for i in range(2)),q)
    return complete_kernel_basis(a)


def test_subgrid_index_two_is_completed_not_renamed():
    parent=KernelBasis(ModMatrixReference(((1,0),),7),((7,0),(0,1)))
    p=prepare_basis_del(parent,((2,0),(0,1)))
    assert p.target_public.rows==((4,0),)
    assert abs(matrix(ZZ,p.transformed_rows).det())==14
    assert p.transformed_sublattice_index==2
    assert abs(matrix(ZZ,p.completed_basis.basis_rows).det())==7
    assert p.ordered_gs_not_increased
    assert p.completed_basis.public==p.target_public


def test_explicit_reduction_retains_full_lattice_and_quality():
    parent=fixture_basis()
    r=FiniteSampleR(101,16,16).sample(rng=DeterministicRandom(b"ABB-completion-reduction"))
    ordinary=prepare_basis_del(parent,r.rows)
    reduced=prepare_basis_del(parent,r.rows,reduce_completion=True)
    assert reduced.completion_reduced and not ordinary.completion_reduced
    assert reduced.target_public==ordinary.target_public
    assert abs(matrix(ZZ,reduced.completed_basis.basis_rows).det())==101**2
    old=gram_schmidt_squared_lengths(reduced.transformed_rows)
    new=gram_schmidt_squared_lengths(reduced.completed_basis.basis_rows)
    assert max(new)<=max(old)
    assert reduced.ordered_gs_not_increased==all(b<=a for a,b in zip(old,new))
    assert reduced.max_gs_not_increased
    with pytest.raises(InvalidParameterError):prepare_basis_del(parent,r.rows,reduce_completion=1)


def test_noncommuting_prefix_order_and_fixed_dimension():
    parent=fixture_basis(4)
    h1=identity_matrix(ZZ,4);h2=identity_matrix(ZZ,4)
    h1[0,1]=1;h2[1,0]=1
    f1,f2=prefix_matrices(parent.public,h1,h2)
    a=matrix(GF(101),parent.public.rows)
    assert matrix(GF(101),f2.rows)==a*matrix(GF(101),h2*h1).inverse()
    assert matrix(GF(101),f2.rows)!=a*matrix(GF(101),h1*h2).inverse()
    assert (f1.nrows,f1.ncols)==(f2.nrows,f2.ncols)==(2,4)


@pytest.mark.parametrize("value",[True,0,193,1.5])
def test_dimension_rejects_without_fallback(value):
    with pytest.raises(InvalidParameterError):FiniteSampleR(101,value,16)


@pytest.mark.parametrize("q",[2,15,True])
def test_odd_prime_contract(q):
    with pytest.raises(InvalidParameterError):FiniteSampleR(q,4,16)


def test_whole_matrix_rejection_discards_all_columns(monkeypatch):
    sampler=FiniteSampleR(101,2,16,max_matrices=2)
    values=iter([0,0,0,0,1,0,0,1])
    monkeypatch.setattr(sampler.scalar,"sample",lambda *a,**k:next(values))
    result=sampler.sample(rng=NoEntropy())
    assert result.matrices_sampled==2 and result.rows==((1,0),(0,1))
    assert sampler.last_entropy_bytes==0


def test_whole_matrix_exhaustion_is_abort_not_identity_fallback(monkeypatch):
    sampler=FiniteSampleR(101,2,16,max_matrices=2)
    calls=[]
    def zero(*args,**kwargs):calls.append(1);return 0
    monkeypatch.setattr(sampler.scalar,"sample",zero)
    with pytest.raises(SamplingAbort,match="exhausted"):sampler.sample(rng=NoEntropy())
    assert len(calls)==8


def test_actual_finite_gaussian_matrix_reproducibility_and_condition():
    sampler=FiniteSampleR(101,16,16)
    a=sampler.sample(rng=DeterministicRandom(b"ABB-SampleR-explicit-test"))
    b=sampler.sample(rng=DeterministicRandom(b"ABB-SampleR-explicit-test"))
    assert a.rows==b.rows and a.matrices_sampled==b.matrices_sampled
    assert matrix(GF(101),a.rows).is_invertible()
    c=sampler.certificate()
    assert QQ(c["ideal_nonsingular_probability_lower"])>QQ(1)/2
    assert 0<=QQ(c["conditional_success_vs_ideal_invertible_matrix_tv_upper"])<1
    assert not c["per_column_filtering"] and c["backend_admitted"] is False
    actual=sampler.sample()
    assert actual.rows!=a.rows


def test_finite_matrix_entropy_errors_propagate():
    class Bad:
        def read(self,n):return b""
    sampler=FiniteSampleR(101,4,16)
    with pytest.raises(RandomnessError):sampler.sample(rng=Bad())
    with pytest.raises(InvalidParameterError,match="tape"):
        FiniteSampleR(101,4,16,max_tape_bytes=1)


@pytest.mark.parametrize("bad",[
    ((0,0),(0,0)),((1,0),),((True,0),(0,1)),((1.0,0),(0,1)),
])
def test_bad_transformation_is_not_silently_lifted(bad):
    parent=KernelBasis(ModMatrixReference(((1,0),),7),((7,0),(0,1)))
    with pytest.raises(InvalidParameterError):prepare_basis_del(parent,bad)


def test_foreign_field_transformation_must_be_explicitly_integer():
    parent=fixture_basis(4)
    with pytest.raises(InvalidParameterError):prepare_basis_del(parent,identity_matrix(GF(101),4))


def test_real_randomization_outputs_full_target_kernel():
    parent=fixture_basis()
    r=FiniteSampleR(101,16,16).sample(rng=DeterministicRandom(b"ABB-transform-sample"))
    prepared=prepare_basis_del(parent,r.rows)
    max_gs=max(gram_schmidt_squared_lengths(prepared.completed_basis.basis_rows))
    sigma2=4*max_gs*smoothing_factor(16,64)
    delegate=FiniteBasisDel(parent,r.rows,sigma2,epsilon_bits=64)
    result=delegate.sample(rng=DeterministicRandom(b"ABB-delegation-finite-test"))
    assert result.basis.public==prepared.target_public
    assert abs(matrix(ZZ,result.basis.basis_rows).det())==101**2
    assert matrix(GF(101),prepared.target_public.rows)*matrix(GF(101),result.basis.basis_rows)==0
    assert max(gram_schmidt_squared_lengths(result.basis.basis_rows))<=sigma2*16
    assert result.independent_vectors==16
    c=delegate.public_test_certificate()
    assert c["not_full_HIBE"] and not c["theorem3_finite_constants_or_ROM_mapping_verified"]


def test_width_failure_is_pre_entropy():
    parent=fixture_basis()
    with pytest.raises(ValueError,match="Width"):
        FiniteBasisDel(parent,identity_matrix(ZZ,16),1,epsilon_bits=64)


def test_paper_dimension_gate_does_not_promote_primitive_fixture_to_HIBE():
    from ibme.hibe.abb_rom.parameter_gate import setup_dimension_report
    small=setup_dimension_report(2,84,549755813911)
    assert not small["paper_dimension_sufficient_checked"]
    assert small["conservative_strict_dimension_minimum"]==481
    larger=setup_dimension_report(2,733,2**61-1)
    assert larger["paper_dimension_sufficient_checked"]
    assert not larger["fixed_primitive_domain"]
    assert not larger["actual_ABB_TrapGen_verified"] and not larger["backend_admitted"]


def test_two_real_delegations_and_direct_product_keep_same_fixed_target():
    parent=fixture_basis()
    sampler=FiniteSampleR(101,16,16)
    h1=sampler.sample(rng=DeterministicRandom(b"ABB-two-level-H1")).rows
    h2=sampler.sample(rng=DeterministicRandom(b"ABB-two-level-H2")).rows
    norm1=sum(x*x for r in h1 for x in r);norm2=sum(x*x for r in h2 for x in r)
    factor=smoothing_factor(16,64)
    sigma1=4*101**2*norm1*factor
    first=FiniteBasisDel(parent,h1,sigma1,epsilon_bits=64,reduce_completion=True).sample(
        rng=DeterministicRandom(b"ABB-two-level-first"))
    sigma2=4*(sigma1*16)*norm2*factor
    via=FiniteBasisDel(first.basis,h2,sigma2,epsilon_bits=64,reduce_completion=True).sample(
        rng=DeterministicRandom(b"ABB-two-level-via"))
    product=matrix(ZZ,h2)*matrix(ZZ,h1)
    direct=FiniteBasisDel(parent,product,sigma2,epsilon_bits=64,reduce_completion=True).sample(
        rng=DeterministicRandom(b"ABB-two-level-direct"))
    _,expected=prefix_matrices(parent.public,h1,h2)
    assert via.basis.public==direct.basis.public==expected
    assert via.basis.public.ncols==direct.basis.public.ncols==16
    assert abs(matrix(ZZ,via.basis.basis_rows).det())==abs(matrix(ZZ,direct.basis.basis_rows).det())==101**2
    # Equality of sampled matrices is not a distribution test. Both are real
    # valid calls at a common width; formal indistinguishability is separate.


def test_saved_private_84_dimensional_output_is_a_full_correct_target():
    folder=Path(__file__).resolve().parents[1]/"test-results/abb-basis-reduced/private"
    if not (folder/"delegated-basis.json").is_file():pytest.skip("explicit completed private witness required")
    q=549755813911
    parent=matrix(ZZ,json.loads((folder/"parent-basis.json").read_text())["rows"])
    a=matrix(GF(q),parent).left_kernel().basis_matrix()
    a=a.matrix_from_columns([0,1]).inverse()*a
    r=matrix(ZZ,json.loads((folder/"public-transformation.json").read_text())["rows"])
    target=a*matrix(GF(q),r).inverse()
    output=matrix(ZZ,json.loads((folder/"delegated-basis.json").read_text())["rows"])
    assert output.dimensions()==(84,84)
    assert target*matrix(GF(q),output)==0
    assert abs(output.det())==q**2
    receipt=json.loads((folder.parent/"result.json").read_text())
    assert receipt["new_root_or_R_generations"]==0 and receipt["checked_completion_reduction"]
    assert not receipt["full_HIBE_implemented"] and not receipt["paper_parameter_conditions_admitted"]
