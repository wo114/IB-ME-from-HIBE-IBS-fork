"""Independent hand-counts of reserve objects; no primitive/backend tests."""

import pytest
from experiments.research.abb_rom.reserve_costs import abb_standard_counts,chkp_standard_counts,gkr_compiler_counts,report


def test_two_level_standard_abb_objects_and_correlated_noise_work():
    result=abb_standard_counts(2,5,9)
    assert result["full_basis_dimensions"]==[5,10,15]
    assert result["public_residue_count"]==42
    assert result["independent_bit_seed_residue_bytes"]==8192
    assert result["independent_bit_seed_rademacher_symbols"]==12800
    assert result["measured"] is False


def test_admissible_hash_blocks_expand_two_layers_separately():
    result=chkp_standard_counts(2,5,9,3)
    assert result["matrix_blocks_in_master_public"]==13
    assert result["full_basis_dimensions"]==[5,20,35]
    assert result["public_matrix_residue_bytes"]==260
    assert result["shared_leading_seed_residue_bytes"]==582


def test_gkr_counts_include_root_and_final_pke_circuit():
    result=gkr_compiler_counts(1,4)
    assert result["proposed_framed_binary_path_bits"]==96
    assert result["key_node_count_including_root"]==97
    assert result["Q_garbled_circuit_count"]+result["T_garbled_circuit_count"]==98
    assert result["anonymizing_lockable_obfuscations_per_ciphertext"]==1
    assert result["concrete_ciphertext_bytes"] is None
    assert result["not_the_complete_anonymous_LWE_cost"] is True


@pytest.mark.parametrize("function,args",[(abb_standard_counts,(True,5,9)),
    (chkp_standard_counts,(2,5,9,0)),(gkr_compiler_counts,(87,False))])
def test_invalid_dimension_inputs_are_not_silently_rounded(function,args):
    with pytest.raises(ValueError):function(*args)


def test_scale_projection_remains_unmeasured_and_unadmitted():
    result=report()
    assert result["measured"] is False and result["security_claim"]=="none"
    assert result["parameters_are_formal"] is False
    assert result["abb_standard"]["full_basis_dimensions"][-1]>1536
