"""Formal-size CHKP/MP12 resource projections and pinned LWE screening.

No roots/keys generated and no implementation cap overridden. LWE estimates
are Gaussian standard-deviation comparators for the rounded-continuous noise,
not a proof for its literal PMF. Cost >= target alone never admits a backend.
"""

import argparse
from fractions import Fraction
import json
from pathlib import Path
import sys
import time

from sage.all import QQ,RR,log,oo,ZZ

from experiments.research.luo_parameter_screen import verify_estimator_checkout
from experiments.research.ibme_joint_parameters import smoothing_factor,evaluate_noise
from .finite_gaussian import FirstFiniteGaussian


def minimum_entropy_columns(n,q,k,*,bits=128,mass=Fraction(319,10)):
    if (type(n) is not int or not 1<=n<=16384 or type(q) is not int or not 2<=q<2**128
            or type(k) is not int or not 1<=k<=128 or type(bits) is not int or not 8<=bits<=256
            or type(mass) not in (int,Fraction) or not 1<mass<=q):
        raise ValueError("positive exact public dimensions required")
    mass=Fraction(mass)
    target=(n*k)**2*q**n*2**(2*bits)
    low,high=0,1
    while mass**high<target:high*=2
    while low+1<high:
        middle=(low+high)//2
        if mass**middle>=target:high=middle
        else:low=middle
    return high


def public_projection(n,q):
    if type(n) is not int or not 1<=n<=16384 or type(q) is not int or not 343<q<2**128:
        raise ValueError("explicit bounded dimensions/injective finite R modulus required")
    if not ZZ(q).is_prime(proof=True):raise ValueError("prime modulus required")
    k=(q-1).bit_length();mbar=minimum_entropy_columns(n,q,k);w=n*k;m=mbar+w;p=2*m-w
    radius=FirstFiniteGaussian(1024,1024).radius
    root_bound=10*(1+mbar*w*radius**2)
    width=4*root_bound*smoothing_factor(2*m,128)
    original_parent_bound=width*2*m
    compact_parent_bound=10*(1+w*p*width)
    s2=4*original_parent_bound*smoothing_factor(3*m,128)
    compact_s2=4*compact_parent_bound*smoothing_factor(3*m,128)
    chi=2**(((4*n-1).bit_length()+1)//2)
    noise=None if 3*m>65536 else evaluate_noise(q=q,dimension=3*m,width_squared=s2,
        alpha=Fraction(chi,q),error_bits=64,seed_bits=256,encapsulations=2**20)
    return dict(n=n,q=q,k=k,m_bar=mbar,root_dimension=m,original_parent_dimension=2*m,leaf_dimension=3*m,
        deltrap_sampling_prefix=p,deltrap_columns=w,root_gs_squared_bound=root_bound,source_width_squared=width,
        original_parent_gs_squared_bound=original_parent_bound,compact_frobenius_parent_gs_squared_bound=compact_parent_bound,
        original_leaf_width_squared=s2,compact_frobenius_leaf_width_squared=compact_s2,
        continuous_noise_width=chi,alpha=str(Fraction(chi,q)),noise_lower_bound_2sqrt_n=chi**2>=4*n,
        original_conditional_noise=noise,noise_check_omitted_if_dimension_exceeds_existing_checker=3*m>65536,
        Gaussian_comparator_sigma=str(RR(chi)/(2*RR.pi()).sqrt()),
        sample_counts=dict(preamble=3*m,chosen_plaintext_seed=3*m+256),
        minimum_private_wire_bytes=dict(root_full_basis=6*m*m,original_parent_full_basis=6*(2*m)**2,
            compact_parent_trapdoor=4*p*w,terminal_256_vectors=6*3*m*256),
        private_encoding_lower_bounds=dict(existing_signed_length_integer_bytes=6,
            compact_JSON_integer_string_bytes=4,
            compact_JSON_formula="p*w integers, at least quoted zero plus separator; row/outer/header omitted"),
        actual_implementation_caps=dict(root_n=64,root_basis=1024,gpv_prefix=256,tobasis=192,private_bytes=16*2**20),
        execution_gates=dict(root=n<=64 and m<=1024,original_parent=2*m<=192,
            compact_source=p<=256,leaf=3*m<=256,terminal_unit_scalar=s2<=2**80,
            compact_terminal_unit_scalar=compact_s2<=2**80),
        actual_key_generation_or_sampling=False,parameters_are_formal=False,security_claim="none",backend_admitted=False)


def run(estimator_path,output):
    root,revision=verify_estimator_checkout(estimator_path);sys.path.insert(0,str(root))
    import estimator
    from estimator import LWE,ND
    from estimator.reduction import ADPS16
    if not Path(estimator.__file__).resolve().is_relative_to(root):raise ValueError("foreign estimator import")
    scalar=FirstFiniteGaussian(1024,1024)
    if scalar.acceptance_mass_lower<=QQ(319)/10:raise ValueError("actual finite R mass does not support projection floor")
    report=dict(estimator_revision=revision,model="ADPS16 Core-SVP classical/quantum, LGSA, primal-uSVP ONLY",
        noise_model="Gaussian sigma=continuous_width/sqrt(2*pi) comparator; not a literal rounded-noise PMF theorem",
        finite_root_entropy_floor="319/10",root_regularity_target_bits=128,
        source_finite_R_mass_floor_checked=True,rows=[],parameters_are_formal=False,security_claim="none",backend_admitted=False)
    output=Path(output);output.parent.mkdir(parents=True,exist_ok=True)
    if output.exists():raise ValueError("new parameter output required")
    for n in (128,256,512,1024,2048,4096):
        row=public_projection(n,2**61-1)
        prm=LWE.Parameters(n=n,q=row["q"],m=row["sample_counts"]["chosen_plaintext_seed"],
            Xs=ND.UniformMod(row["q"]),Xe=ND.DiscreteGaussian(RR(row["continuous_noise_width"])/(2*RR.pi()).sqrt()),
            tag=f"CHKP-MP12-parameter-resource-n{n}")
        normalized=prm.normalize()
        row["normalized_lwe"]=dict(n=normalized.n,m=str(normalized.m),secret=str(normalized.Xs),error=str(normalized.Xe))
        row["primal_usvp"]={}
        for mode in ("classical","quantum"):
            start=time.monotonic();c=LWE.primal_usvp(prm,red_cost_model=ADPS16(mode=mode),red_shape_model="lgsa")
            row["primal_usvp"][mode]=dict(core_svp_log2=None if c["rop"]==oo else float(log(c["rop"],2)),
                fields={k:str(v) for k,v in c.items() if k!="problem"},seconds=time.monotonic()-start,
                goal="heuristic secret search; not an executed key-recovery attack")
        report["rows"].append(row)
        output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
        print(json.dumps(dict(n=n,root=row["root_dimension"],compact_bytes=row["minimum_private_wire_bytes"]["compact_parent_trapdoor"],
            classical=row["primal_usvp"]["classical"]["core_svp_log2"],quantum=row["primal_usvp"]["quantum"]["core_svp_log2"])),flush=True)
    return report


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--estimator-path",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args(argv);run(a.estimator_path,a.output);return 0


if __name__=="__main__":raise SystemExit(main())
