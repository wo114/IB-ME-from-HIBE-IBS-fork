"""Finite object-count projections for AR reserves, never executable presets.

No matrix allocation, randomness, security estimation or hidden omega constant.
Bytes for complete integer bases explicitly assume the A entrywise 6-byte
minimum format; other representations need their own counts and codec.
"""

import argparse
import json
from pathlib import Path


def count(value,name,maximum=2**31):
    if type(value) is not int or not 1<=value<=maximum:
        raise ValueError(name+": bounded exact positive integer required")
    return value


def common(n,m,q_bits):
    n=count(n,"n",65536);m=count(m,"m");q_bits=count(q_bits,"q_bits",256)
    return n,m,(q_bits+7)//8


def abb_standard_counts(n,m,q_bits,depth=2,seed_bytes=32):
    n,m,width=common(n,m,q_bits)
    depth=count(depth,"depth",16);seed_bytes=count(seed_bytes,"seed_bytes",32)
    dimensions=[(level+1)*m for level in range(depth+1)]
    bits=8*seed_bytes
    return dict(source="ABB EUROCRYPT full PDF32-34, §8.2/§8.3/Theorem33",measured=False,
        n=n,root_block_m=m,q_bits=q_bits,depth=depth,seed_bytes=seed_bytes,
        full_basis_dimensions=dimensions,full_basis_entries=[d*d for d in dimensions],
        entrywise_signed_format_min_basis_bytes=[6*d*d for d in dimensions],
        public_residue_count=(depth+2)*n*m+n,public_residue_bytes=((depth+2)*n*m+n)*width,
        bit_ciphertext_residue_count=dimensions[-1]+1,
        independent_bit_seed_residue_bytes=bits*(dimensions[-1]+1)*width,
        rademacher_symbols_per_bit=depth*m*m,
        independent_bit_seed_rademacher_symbols=bits*depth*m*m,
        unknown=["finite sigma/alpha/omega constants","actual sampler TV/ABORT/workspace",
            "identity full-rank-difference map and codec","adaptive/anonymous composition mapping"],
        parameters_are_formal=False,backend_admitted=False,security_claim="none")


def chkp_standard_counts(n,m,q_bits,hash_output_bits,depth=2,seed_bytes=32):
    n,m,width=common(n,m,q_bits)
    h=count(hash_output_bits,"hash_output_bits",2**20)
    depth=count(depth,"depth",16);seed_bytes=count(seed_bytes,"seed_bytes",32)
    dimensions=[(1+level*h)*m for level in range(depth+1)]
    blocks=1+2*depth*h
    return dict(source="CHKP author full PDF26-29, (5.3)/Theorem5.4/Corollary5.5",measured=False,
        n=n,root_block_m=m,q_bits=q_bits,hash_output_bits=h,depth=depth,seed_bytes=seed_bytes,
        matrix_blocks_in_master_public=blocks,public_matrix_residue_count=blocks*n*m,
        public_matrix_residue_bytes=blocks*n*m*width,full_basis_dimensions=dimensions,
        full_basis_entries=[d*d for d in dimensions],
        entrywise_signed_format_min_basis_bytes=[6*d*d for d in dimensions],
        anon_padded_leading_residues_per_seed=dimensions[-1],
        shared_leading_seed_residue_bytes=(dimensions[-1]+8*seed_bytes)*width,
        reduction_denominator="Delta(identity_domain_bits,Q)^depth; depth2 and Delta=Theta(Q^-2) gives Theta(Q^-4)",
        unknown=["actual admissible hash construction, output length and finite Delta",
            "identity hash domain and two-level mapping","sigma/noise and hardness",
            "actual finite key generation and codec/GS/resource budgets"],
        parameters_are_formal=False,backend_admitted=False,security_claim="none")


def gkr_compiler_counts(identity_max_bytes=86,key_bits=128):
    identity_max_bytes=count(identity_max_bytes,"identity_max_bytes",256)
    key_bits=count(key_bits,"key_bits",4096)
    # Explicit project proposal: role-byte || LP(component), two components.
    path_bits=8*2*(1+4+identity_max_bytes)
    nodes=path_bits+1
    return dict(source="GKR PDF14-16 §3.1, PDF32-34 AppendixB",measured=False,
        proposed_framed_binary_path_bits=path_bits,convenience_verification_key_bits=key_bits,
        key_node_count_including_root=nodes,chain_message_material_bits=nodes*3*key_bits,
        Q_garbled_circuit_count=nodes,T_garbled_circuit_count=1,
        OTSE_encryption_circuits_inside_Q=nodes*2*key_bits,
        anonymizing_lockable_obfuscations_per_ciphertext=1,
        concrete_ciphertext_bytes=None,concrete_key_bytes=None,
        unknown=["concrete PKE/OTSE/garbling/delegatable PRF implementations and gate counts",
            "lockable obfuscator parameters/implementation/output and Dec circuit bounds",
            "fixed two-component byte encoding model mapping"],
        not_the_complete_anonymous_LWE_cost=True,parameters_are_formal=False,
        backend_admitted=False,security_claim="none")


def report():
    # A dimension-only scale input; n128/q61 is NOT a 128-bit security claim.
    n,q_bits=128,61
    m=6*n*q_bits+1
    return dict(schema="A-MATRIX-HIBE-RESERVE-COSTS/1",measured=False,
        scope="finite literal counts, no keys, no executable/safe parameter selection",
        format_assumption="signed entry is one sign byte + LP4 + >=one magnitude byte; no headers",
        scale_input=dict(n=n,q_bits=q_bits,root_block_m=m,strict_m_gt_6_n_logq=True),
        abb_standard=abb_standard_counts(n,m,q_bits),
        chkp_standard_grids=[chkp_standard_counts(n,m,q_bits,h) for h in (128,256,16384)],
        gkr=gkr_compiler_counts(),security_claim="none",backend_admitted=False,parameters_are_formal=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    result=report()
    raw=json.dumps(result,indent=2)+"\n"
    if args.output:args.output.write_text(raw,encoding="utf-8")
    else:print(raw)


if __name__=="__main__":main()
