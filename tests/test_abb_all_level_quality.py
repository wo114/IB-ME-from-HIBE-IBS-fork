"""The tighter next-level width requires actual quality at every key level."""
from dataclasses import replace
import os
import pytest
pytest.importorskip('sage.all',reason='prescribed WSL Sage required')
from ibme.core.errors import InvalidParameterError
from ibme.hibe.abb_rom.profiles import (q22_all_level_research_params,q80_normalized_root_research_params,
                                     q26_level_quality_research_params)
from ibme.hibe.abb_rom.backend import check_setup_profile
from ibme.hibe.abb_rom.params import ABBROMParams
from ibme.hibe.abb_rom.key_validation import validate_basis,expected_matrix
from ibme.hibe.abb_rom.objects import ABBPublicKey
from experiments.research.chkp_basis import complete_kernel_basis


@pytest.fixture(params=[q22_all_level_research_params,q26_level_quality_research_params])
def profile(request):
    if not os.environ.get('IBME_EXACT_GRAM_EXECUTABLE'):
        pytest.skip('explicit built native dependency required')
    return request.param()


def test_exact_whole_profile_keeps_full_lengths_and_gates(profile):
    _,_,report=check_setup_profile(profile)
    assert profile.dimension in (176,208) and profile.n==1
    assert report['normalized_root_gs_squared_bound']==256
    assert report['normalized_parent_gs_squared_bound']==profile.normalized_level_gs_squared_bound
    assert report['normalized_leaf_gs_squared_bound']==profile.normalized_level_gs_squared_bound
    assert report['normalized_level_quality_must_be_checked'] is True
    assert report['conditional_noise_sufficient'] is True and report['blockers']==[]
    assert profile.sigma2_squared==profile.sigma1_squared*(profile.normalized_level_gs_squared_bound//256)
    assert profile.identity_max_bytes==86 and profile.payload_max_bytes==32
    assert ABBROMParams.from_bytes(profile.to_bytes())==profile
    assert profile.security_claim=='none' and profile.backend_admitted is False


@pytest.mark.parametrize('path',[(),(b'Bob',),(b'Bob',b'Alice')])
def test_every_key_level_rejects_a_complete_but_wide_basis(profile,path):
    public=ABBPublicKey(profile,((1,)+(0,)*(profile.dimension-1),),(1,))
    basis=complete_kernel_basis(expected_matrix(public,path))
    # Completeness alone does not establish the selected 256 GS condition.
    with pytest.raises(ValueError,match='GS'):
        validate_basis(public,path,basis.basis_rows)


def test_tighter_width_cannot_be_used_without_level_quality(profile):
    with pytest.raises(InvalidParameterError,match='same-group'):
        check_setup_profile(replace(profile,normalization='matrix-flatter-rootgs256-nativegram-exact074-v4'))
    assert q80_normalized_root_research_params().normalized_level_gs_squared_bound is None
