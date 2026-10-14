"""Exact differential geometry, actual GPV tape and native failure controls."""
import os
from pathlib import Path

import pytest
pytest.importorskip('sage.all',reason='prescribed WSL Sage required')
from sage.all import QQ, ZZ, matrix, identity_matrix
from ibme.core.randomness import DeterministicRandom
from ibme.lattice.matrix_sampling.exact_gram import gram_geometry,require_provider,size_reduce_and_check
from ibme.lattice.matrix_sampling.gpv import MatrixFiniteGPV,_gs_geometry
from experiments.research.chkp_basis import ModMatrixReference,complete_kernel_basis,KernelBasis


@pytest.fixture
def native():
    if not os.environ.get('IBME_EXACT_GRAM_EXECUTABLE'):
        pytest.skip('explicit built native Gram dependency required')
    return require_provider()


@pytest.mark.parametrize('dimension',[1,2,4,8,16,32])
def test_norms_mu_and_all_projection_weights_match_exact_reference(native,dimension):
    b=matrix(ZZ,dimension,dimension,lambda i,j:(i+2)*(j+3)%11-5 if i!=j else dimension*7)
    lengths,mu,weights=gram_geometry(b,projection_weights=True)
    _,reference,reference_weights=_gs_geometry(tuple(tuple(row) for row in b.rows()),65536)
    assert lengths==reference and weights==reference_weights
    assert gram_geometry(b,norms_only=True)==reference
    for i in range(dimension):
        for j in range(i+1,dimension):
            assert mu[i,j]==sum(x*w for x,w in zip(b.column(j),reference_weights[i]))


def test_fixed_entropy_gpv_samples_are_identical_with_both_engines(native):
    basis=complete_kernel_basis(ModMatrixReference(((1,2,3,4),),17))
    python=MatrixFiniteGPV(basis,2**16,epsilon_bits=8)
    flint=MatrixFiniteGPV(basis,2**16,epsilon_bits=8,geometry_engine='flint')
    assert python._weights==flint._weights and python._widths==flint._widths
    assert python._path_resources==flint._path_resources
    assert python.random_tape_bytes==flint.random_tape_bytes
    for target in (0,1,16):
        seed=b'exact-Gram-GPV-differential/'+bytes([target])
        left=python.sample((target,),rng=DeterministicRandom(seed))
        right=flint.sample((target,),rng=DeterministicRandom(seed))
        assert left==right and sum(a*b for a,b in zip(basis.public.rows[0],right))%17==target


def test_reduction_and_quality_are_exact_and_keep_full_lattice(native):
    from ibme.lattice.matrix_sampling.basis import matrix_checked_lll
    basis=complete_kernel_basis(ModMatrixReference(((1,2,3,4),),17))
    change=identity_matrix(ZZ,4);change[0,3]=2**100
    skew=KernelBasis(basis.public,matrix(ZZ,basis.basis_rows)*change)
    result=matrix_checked_lll(skew,2**300,geometry_engine='flint')
    b=matrix(ZZ,result.basis_rows)
    lengths,mu=gram_geometry(b)
    assert abs(b.det())==17 and max(lengths)<=2**300
    for j in range(4):
        for i in range(j):assert abs(mu[i,j])<=QQ(1)/2
        if j:assert lengths[j]+mu[j-1,j]**2*lengths[j-1]>=QQ(74)/100*lengths[j-1]
    with pytest.raises(ArithmeticError,match='GS bound'):
        size_reduce_and_check(b,QQ(1)/100)


def test_missing_native_dependency_fails_before_setup_entropy(monkeypatch):
    from ibme.hibe.abb_rom.backend import ABBROMHIBE
    from ibme.hibe.abb_rom.profiles import q80_normalized_root_research_params
    monkeypatch.delenv('IBME_EXACT_GRAM_EXECUTABLE',raising=False)
    class Forbidden:
        def read(self,count):raise AssertionError('missing dependency consumed private entropy')
    with pytest.raises(ValueError,match='exact Gram executable'):
        ABBROMHIBE().setup(q80_normalized_root_research_params(),rng=Forbidden())


@pytest.mark.parametrize('body',['0\nMU\n','1\nMU\nextra\n','1e999999999\nMU\n','1/0\nMU\n'])
def test_native_malformed_geometry_is_rejected(tmp_path,body):
    executable=tmp_path/'fake-native'
    executable.write_text('#!/usr/bin/env python3\nimport sys\nif "--version" in sys.argv: print("IBME-EXACT-GRAM/1 test")\nelse: sys.stdout.write('+repr(body)+')\n')
    executable.chmod(0o700)
    with pytest.raises((ArithmeticError,ValueError)):
        gram_geometry(matrix(ZZ,[[1]]),executable=executable)


def test_native_singular_input_and_wrong_engine_fail(native):
    with pytest.raises(ArithmeticError):gram_geometry(matrix(ZZ,2,2))
    basis=complete_kernel_basis(ModMatrixReference(((1,2),),17))
    with pytest.raises(ValueError,match='unknown'):
        MatrixFiniteGPV(basis,2**16,geometry_engine='auto')


def test_process_tree_budget_includes_grandchildren(tmp_path):
    from experiments.research.abb_rom.hibe_probe import process_tree_rss
    for pid,parent,rss in ((10,1,100),(20,10,200),(30,20,300),(40,1,9999)):
        folder=tmp_path/str(pid);folder.mkdir()
        (folder/'status').write_text(f'PPid:\t{parent}\nVmRSS:\t{rss} kB\n')
    assert process_tree_rss(10,tmp_path)==(600,{10,20,30})
