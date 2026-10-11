"""Exact invariants of the mainline public-test diagnostic, not HIBE tests."""

import pytest

pytest.importorskip("sage.all",reason="use prescribed WSL Sage for root diagnostic")
from sage.all import QQ

from experiments.research.chkp_genbasis import AP09Parameters
from experiments.research.chkp_basis import ModMatrixReference,complete_kernel_basis
from experiments.research.ibme_root_sampler_audit import audit_root,checked_sage_lll,geometry


def test_sage_diagnostic_verifies_exact_lattice_and_public_width_bound():
    source=complete_kernel_basis(ModMatrixReference([[1,2,3,1]],7))
    before,_=geometry(source)
    reduced=checked_sage_lll(source,max(before))
    after,mu=geometry(reduced)
    assert source.public == reduced.public
    assert max(after)<=max(before)
    assert all(abs(mu[i,j])<=QQ(1)/2 for i in range(4) for j in range(i))


def test_tiny_end_to_end_root_diagnostic_exports_no_basis_or_vectors():
    params=AP09Parameters(n=1,q=2,random_rows=2,m1=2,m2=8,hadamard_scale=4)
    result=audit_root(params,b"joint-test-root")
    assert result["root_generated"] and result["attempts"] == 1
    final=result["diagnostic_lll"]
    assert final["sampler"]["status"] == "root_preimages_sampled"
    assert final["sampler"]["samples"][0]["equation"]
    assert not final["production_or_uniform_resource_admission"]
    assert not final["bounded_chkp_reducer_used"]
    assert not result["backend_admitted"] and result["security_claim"] == "none"
    assert "basis" not in result and "preimages" not in result


def test_a_diagnostic_cannot_silently_relax_the_declared_gs_bound():
    basis=complete_kernel_basis(ModMatrixReference([[1,0]],7))
    with pytest.raises(ArithmeticError,match="exact LLL"):
        checked_sage_lll(basis,0)
