"""Public same-group ledger, with unknowns kept distinct from zero."""

from fractions import Fraction
import pytest
pytest.importorskip('sage.all',reason='prescribed WSL Sage required')
from ibme.core.randomness import SecureRandom
from ibme.hibe.abb_rom.profiles import q104_research_params
from experiments.research.abb_rom.public_budget_ledger import public_budget_ledger


def test_budget_projection_reads_no_entropy_and_has_current_full_scope(monkeypatch):
    def forbidden(*args,**kwargs):raise AssertionError('public ledger read entropy')
    monkeypatch.setattr(SecureRandom,'read',forbidden)
    p=q104_research_params();result=public_budget_ledger(p)
    assert result['params']==p.to_record()
    assert result['counts']['max_distinct_public_prefixes']==2
    assert result['counts']['max_vectors_each']==896
    assert result['counts']['max_decryption_SamplePre_calls']==2**28
    assert result['resource_counts']['full_basis_entries_each']==692224
    assert result['resource_counts']['all_declared_key_tree_basis_min_bytes']==12460032
    assert result['resource_counts']['complete_setup_worst_private_tape_bytes']==651456
    assert result['measured'] is False


def test_smoothing_noise_rank_and_root_tv_are_separate_terms():
    result=public_budget_ledger(q104_research_params());terms=result['terms']
    assert Fraction(terms['conditional_ideal_noise_lifetime'])==Fraction(1,2**100)
    rank=Fraction(terms['RandBasis_reference_rank_per_call'])
    assert Fraction(1,2**64)<rank<Fraction(1,2**63)
    geometry=Fraction(terms['GPV_geometry_TV_per_admitted_call'])
    assert geometry==Fraction(832,2**128-1665)
    assert Fraction(terms['AP09_actual_root_vs_uniform_TV_including_abort'])>Fraction(1,2**64)
    assert Fraction(terms['GPV_geometry_TV_for_lifetime_decrypt_calls'])==2**28*geometry


def test_missing_runtime_model_and_private_scalar_terms_remain_null():
    result=public_budget_ledger(q104_research_params())
    for name in ('matrix_R_native_allocation_failure','private_GPV_scalar_TV_bundle',
        'actual_ToBasis_LLL_GSO_workspace_failure','fresh_decryption_coset_bad_norm_bound',
        'concrete_SHAKE_matrix_RO_security_loss','full_scheme_TV_or_failure_upper'):
        assert result['terms'][name] is None
    assert result['not_a_probability_bound_for_whole_system'] is True
    assert result['parameters_are_formal'] is False and result['backend_admitted'] is False
