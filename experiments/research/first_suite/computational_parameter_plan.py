"""Same-input projections for the new computational-root/DelTrap profile.

No high-dimensional keys or new security presets. Current reference caps are
kept. Per-role hardness/model mapping and actual distribution estimates remain
separate from arithmetic correctness and wire lower bounds.
"""

import argparse
import json
from fractions import Fraction
from pathlib import Path

from sage.all import ZZ
from experiments.research.ibme_joint_parameters import evaluate_noise,smoothing_factor


def projection(n,q):
    if type(n) is not int or not 2<=n<=4096 or type(q) is not int or not 3<q<=2**61-1:
        raise ValueError("bounded exact dimensions/modulus required")
    if not ZZ(q).is_prime(proof=True):raise ValueError("proven prime q required")
    k=(q-1).bit_length();w=n*k;mbar=2*n;m=mbar+w;p=2*m-w
    chi=2**(((4*n-1).bit_length()+1)//2)
    r_width=chi**2;quality=mbar*w*r_width;root_gs=10*(1+quality)
    source_width=4*root_gs*smoothing_factor(2*m,128)
    parent_gs=10*(1+w*p*source_width)
    leaf_width=4*parent_gs*smoothing_factor(3*m,128)
    noise=None if 3*m>65536 else evaluate_noise(q=q,dimension=3*m,width_squared=leaf_width,
        alpha=Fraction(chi,q),error_bits=128,seed_bits=256,encapsulations=2**20)
    gates=dict(private_root_engine=n<=64 and m<=1024 and mbar*w<=2**20,
        public_context=n*m<=2**20 and 3*m<=65536,
        parent_gpv_prefix=p<=256,parent_to_basis=2*m<=1024,
        leaf_finite_gpv=3*m<=256,leaf_squared_width_domain=leaf_width<=2**80,
        conditional_noise=None if noise is None else noise["conditional_noise_sufficient"])
    lower=dict(root_full_basis=6*m*m,parent_compact_intermediate=4*p*w,
        parent_stored_full_basis=6*(2*m)**2,fixed256_leaf=6*3*m*256,
        public_root_residues=n*m*((k+7)//8))
    return dict(n=n,q=q,k=k,m_bar=mbar,root_dimension=m,parent_dimension=2*m,leaf_dimension=3*m,
        parent_sampling_prefix=p,gadget_columns=w,
        root_gaussian_width_squared=r_width,root_public_quality_squared=quality,
        root_public_gs_squared_bound=root_gs,parent_width_squared=source_width,
        parent_public_gs_squared_bound=parent_gs,leaf_width_squared=leaf_width,
        ciphertext_continuous_noise_width=chi,alpha=str(Fraction(chi,q)),
        root_lwe=dict(distribution="normal-form small Gaussian secret/error; R2/R1; finite PMF coupling separate",
            samples_per_secret=n,independent_secret_columns=w,width_squared=r_width,
            attack_estimation_run=False),
        ciphertext_lwe=dict(distribution="uniform secret; rounded continuous Gaussian; known-bit comparator",
            known_plaintext_samples=3*m+256,width=chi,attack_estimation_run=False),
        noise_budget=noise,noise_check_omitted_due_to_checker_domain=3*m>65536,
        noise_check_status=("not-evaluated-dimension-cap" if noise is None else
            "pass" if noise["conditional_noise_sufficient"] else "fail"),
        existing_reference_execution_gates=gates,all_listed_arithmetic_resource_gates_pass=all(v is True for v in gates.values()),
        minimum_wire_bytes=lower,encoding_lower_bounds="signed integer >=6B; intermediate quoted JSON integer >=4B; headers omitted",
        generated_or_sampled=False,parameters_are_formal=False,security_claim="none",backend_admitted=False,
        exclusions=["both-role lattice estimates", "MP12/CHKP ROM mapping", "optimized or admitted Algorithm3",
            "all-path/tape construction on actual secret bases", "runtime and memory beyond wire lower bounds"])


def run(output):
    output=Path(output)
    if output.exists():raise ValueError("new projection output required")
    rows=[projection(2,549755813911)]
    rows.extend(projection(n,2**61-1) for n in (8,32,128,256,512,1024,2048,4096))
    report=dict(schema="A-COMPUTATIONAL-HIBE-PARAMETER-PROJECTIONS/1",rows=rows,
        projection_only=True,current_actual_profile="n2-reference; 21 real checks and public attack recorded separately",
        every_projection_is_not_a_hardness_or_admission_result=True,
        high_dimension_keys_generated=0,security_claim="none",backend_admitted=False,parameters_are_formal=False)
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open("x",encoding="utf-8") as f:f.write(json.dumps(report,indent=2)+"\n")
    for row in rows:
        print(json.dumps(dict(n=row["n"],m=row["root_dimension"],leaf=row["leaf_dimension"],
            gates=row["existing_reference_execution_gates"],parent_basis_min_bytes=row["minimum_wire_bytes"]["parent_stored_full_basis"])))
    return report


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--output",type=Path,required=True)
    run(p.parse_args(argv).output);return 0


if __name__=="__main__":raise SystemExit(main())
