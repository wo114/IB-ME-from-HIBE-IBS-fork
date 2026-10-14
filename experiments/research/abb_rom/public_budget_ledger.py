"""One exact public ABB configuration: reference-model budgets and gaps.

No keys, secret geometry, oracle values or entropy are generated here. The
matrix RO is an ideal comparison model; SHAKE is not assumed statistically
uniform or indifferentiable. Missing resource/scalar/norm/model terms stay null.
"""

import argparse
from fractions import Fraction
import json
from math import isqrt
from pathlib import Path

from ibme.hibe.abb_rom.backend import check_setup_profile
from ibme.hibe.abb_rom.params import ABBROMParams
from ibme.hibe.abb_rom.profiles import q104_research_params
from ibme.hibe.abb_rom.registration import ciphertext_size


def rational(value):
    return str(Fraction(value))


def formal_scale_projection(params):
    """Dimension-only same-q inputs; never generate or admit a high-n profile."""
    scaled=Fraction(params.noise_width_numerator,params.noise_width_denominator)
    logq=(params.q-1).bit_length()
    width=(params.q.bit_length()+7)//8
    rows=[]
    for n in (1,2,3,4,16,128,256):
        minimum=6*n*logq+1  # implementation's conservative strict Setup relation
        rows.append(dict(n=n,q_bits=logq,scaled_noise=rational(scaled),
            Regev_Theorem2_strict_prerequisite=scaled*scaled>4*n,
            smallest_integer_scaled_noise_for_this_prerequisite=isqrt(4*n)+1,
            Setup_dimension_condition_minimum=minimum,
            current_n_parameter_cap_passes=n<=64,current_matrix_dimension_cap_passes=minimum<=1536,
            entrywise_signed_root_basis_format_min_bytes=6*minimum*minimum,
            raw_32B_residue_bytes_before_header=256*(minimum+1)*width,
            phase_noise_after_increasing_scaled_noise=None,actual_execution=False,
            not_a_secure_or_complete_parameter_profile=True))
    return rows


def public_budget_ledger(params):
    root,sample_r,screen=check_setup_profile(params)
    m=params.dimension
    prefixes=params.max_parents*(1+params.max_children_per_parent)
    rand_calls=prefixes
    vectors=m+64  # declared MatrixBasisDel default, not observed acceptance
    eps=Fraction(1,2**params.epsilon_bits)
    denominator=2**params.epsilon_bits-2*m-1
    geometry=min(Fraction(1),Fraction(m,denominator)) if denominator>0 else Fraction(1)
    rank=min(Fraction(1),Fraction(1,2**(vectors-m))+2*vectors*eps)
    norm=min(Fraction(1),(1+eps)/(1-eps)*Fraction(1,2**m))
    decrypt_calls=8*params.payload_max_bytes*params.encapsulation_budget
    certificate=sample_r.certificate()
    matrix_rank=Fraction(certificate['ideal_bounded_rank_abort_upper'])
    matrix_scalar=Fraction(certificate['output_tv_upper_including_scalar_abort'])
    u0_abort=Fraction(params.n,2**params.uniform_trials)
    root_tv=Fraction(root.certificate()['output_vs_uniform_tv_upper_including_abort'])
    u0_tape=params.n*params.uniform_trials*((params.q.bit_length()+7)//8)
    return dict(schema='ABB-PUBLIC-REFERENCE-BUDGET-LEDGER/1',measured=False,
        params=params.to_record(),counts=dict(root_setups=1,max_distinct_public_prefixes=prefixes,
            max_private_RandBasis_calls=rand_calls,max_vectors_each=vectors,
            max_decryption_SamplePre_calls=decrypt_calls),
        conditions=dict(same_group_widths_and_phase_bound=True,
            actual_basis_scalar_GS_path_admission='must be checked on each real basis before sampling',
            all_native_workspace_admitted=False,matrix_SHAKE_indifferentiability_verified=False,
            Regev_Theorem2_strict_noise_prerequisite=Fraction(params.noise_width_numerator,
                params.noise_width_denominator)**2>4*params.n,
            LWE_hardness_verified=False),
        terms=dict(
            AP09_actual_root_vs_uniform_TV_including_abort=rational(root_tv),
            uniform_u0_reference_abort=rational(u0_abort),
            actual_root_and_u0_vs_uniform_TV_including_abort=rational(min(1,root_tv+u0_abort)),
            matrix_R_reference_rank_abort_per_distinct_prefix=rational(matrix_rank),
            matrix_R_reference_scalar_coupling_per_distinct_prefix=rational(matrix_scalar),
            matrix_R_reference_rank_scalar_union=rational(min(1,prefixes*(matrix_rank+matrix_scalar))),
            matrix_R_native_allocation_failure=None,
            RandBasis_reference_rank_per_call=rational(rank),
            RandBasis_reference_zero_coset_norm_per_candidate=rational(norm),
            RandBasis_reference_rank_norm_union=rational(min(1,rand_calls*(rank+vectors*norm))),
            GPV_geometry_TV_per_admitted_call=rational(geometry),
            GPV_geometry_TV_for_RandBasis_candidates=rational(min(1,rand_calls*vectors*geometry)),
            GPV_geometry_TV_for_lifetime_decrypt_calls=rational(min(1,decrypt_calls*geometry)),
            private_GPV_scalar_TV_bundle=None,
            actual_ToBasis_LLL_GSO_workspace_failure=None,
            fresh_decryption_coset_bad_norm_bound=None,
            conditional_ideal_noise_lifetime=screen['conditional_ideal_noise_lifetime_upper'],
            concrete_SHAKE_matrix_RO_security_loss=None,
            full_scheme_TV_or_failure_upper=None),
        term_models=dict(
            root='actual finite uniform-byte AP09 root, public LHL/rank/entropy bounds',
            matrix_R='bounded ideal IID Gaussian matrix RO / independent uniform byte reference; not SHAKE security',
            RandBasis='bounded ideal zero-coset Gaussian, common C1 widths, rank/norm cutoff; allocation separate',
            GPV='only public geometry contribution, not total sampler TV; assumes actual C1/path admission',
            noise='conditional on norm/event hypotheses; not whole HIBE lifetime failure'),
        resource_counts=dict(
            R_worst_tape_bytes_each=sample_r.random_tape_bytes,
            root_worst_private_tape_bytes=root.random_tape_bytes,
            setup_u0_worst_private_tape_bytes=u0_tape,
            complete_setup_worst_private_tape_bytes=root.random_tape_bytes+u0_tape,
            full_basis_entries_each=m*m,
            entrywise_signed_basis_min_bytes=6*m*m,
            all_declared_key_tree_basis_min_bytes=6*m*m*(1+prefixes),
            raw_seed_ciphertext_bytes=ciphertext_size(params,32,86),
            Hybrid_capsule_limit_bytes=4*2**20,Hybrid_component_limit_bytes=16*2**20,
            process_RSS_bound=None),
        evidence='public formula projection; no sampler or key execution',
        formal_scale_projection=formal_scale_projection(params),
        formal_projection_source='ABB CRYPTO author PDF8 §2.6/Theorem2; strict q*alpha >2*sqrt(n)',
        not_a_probability_bound_for_whole_system=True,security_claim='none',
        backend_admitted=False,parameters_are_formal=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--params-file',type=Path)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    params=q104_research_params() if args.params_file is None else ABBROMParams.from_bytes(args.params_file.read_bytes())
    result=public_budget_ledger(params)
    raw=json.dumps(result,indent=2)+'\n'
    if args.output:args.output.write_text(raw,encoding='utf-8')
    else:print(raw)


if __name__=='__main__':main()
