"""Mandatory real root quality gate and complete same-group recipe checks."""
from dataclasses import replace
import pytest

pytest.importorskip('sage.all',reason='prescribed WSL Sage required')
from ibme.hibe.abb_rom.backend import check_setup_profile
from ibme.hibe.abb_rom.profiles import q76_normalized_root_research_params
from ibme.hibe.abb_rom.params import ABBROMParams
from ibme.hibe.abb_rom.key_validation import validate_basis
from ibme.hibe.abb_rom.objects import ABBPublicKey
from ibme.core.errors import InvalidParameterError
from experiments.research.chkp_basis import ModMatrixReference,complete_kernel_basis


def test_full_same_group_profile_and_portable_roundtrip():
    from sage.features.flatter import flatter
    if not flatter().is_present(): pytest.skip('local fixed Flatter installation required')
    p=q76_normalized_root_research_params()
    root,sampler,report=check_setup_profile(p)
    assert report['normalized_root_quality_must_be_checked'] is True
    assert report['normalized_root_gs_squared_bound']==16
    assert report['conditional_noise_sufficient'] is True
    assert report['blockers']==[]
    assert p.identity_max_bytes==86 and p.payload_max_bytes==32
    assert p.max_parents==p.max_children_per_parent==2
    assert ABBROMParams.from_bytes(p.to_bytes())==p


def test_root_quality_gate_is_not_only_metadata():
    p=q76_normalized_root_research_params()
    rows=((1,)+(0,)*(p.dimension-1),)
    pk=ABBPublicKey(p,rows,(1,))
    bad=complete_kernel_basis(ModMatrixReference(rows,p.q))
    # A complete kernel with GS q cannot pass the new root quality premise.
    with pytest.raises(ValueError,match='GS'):
        validate_basis(pk,(),bad.basis_rows)


def test_changing_one_width_does_not_pass_the_complete_recipe():
    from sage.features.flatter import flatter
    if not flatter().is_present(): pytest.skip('local fixed Flatter installation required')
    p=q76_normalized_root_research_params()
    with pytest.raises(InvalidParameterError,match='same-group'):
        check_setup_profile(replace(p,sigma2_squared=p.sigma2_squared-1))
