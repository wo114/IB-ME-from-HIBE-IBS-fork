"""One real SampleR/BasisDel call on a privately generated complete kernel.

This is a primitive witness, not ABB TrapGen/HIBE or formal parameters. Saved
private JSON is never published. A failed attempt remains pending, no restart.
"""

import argparse
import json
from pathlib import Path
import time

from sage.all import GF,QQ,ZZ,matrix

from ibme.hibe.abb_rom import FiniteSampleR,FiniteBasisDel,prepare_basis_del
from ibme.lattice.research import ComputationalRootParams,ComputationalRootGenerator,KernelBasis,ModMatrixReference
from experiments.research.ibme_joint_parameters import smoothing_factor


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--engine",type=Path)
    p.add_argument("--saved-input-directory",type=Path)
    p.add_argument("--reduce-completion",action="store_true")
    p.add_argument("--private-directory",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();root=Path(__file__).resolve().parents[2]
    allowed=(root/"test-results").resolve();private=a.private_directory.resolve();output=a.output.resolve()
    if not private.is_relative_to(allowed) or output.is_relative_to(private) or output.exists():
        raise ValueError("new ignored private directory and separate public output required")
    private.mkdir(parents=True,exist_ok=False)
    pending=private/"generation.pending";pending.write_bytes(b"one ABB primitive experiment; do not restart\n")
    start=time.monotonic();events=[]
    def event(name):
        events.append(dict(stage=name,elapsed_seconds=time.monotonic()-start))
        (private/"progress.json").write_text(json.dumps(events,indent=2)+"\n",encoding="utf-8")
        print(json.dumps(events[-1]),flush=True)
    params=ComputationalRootParams(2,549755813911,16)
    m=params.dimension
    if a.saved_input_directory:
        event("restore_exact_parent_and_public_R_no_generation")
        data=a.saved_input_directory
        rows=json.loads((data/"parent-basis.json").read_text())["rows"]
        public=matrix(GF(params.q),rows).left_kernel().basis_matrix()
        # The computational input's first n columns are I. This uniquely
        # normalizes the public row space recovered from its full kernel.
        public=public.matrix_from_columns(range(params.n)).inverse()*public
        basis=KernelBasis(ModMatrixReference(tuple(tuple(int(x) for x in row) for row in public.rows()),params.q),rows)
        transformation=json.loads((data/"public-transformation.json").read_text())["rows"]
    else:
        if a.engine is None:raise ValueError("new generation requires explicit engine")
        event("private_full_kernel_root")
        generated=ComputationalRootGenerator(params,a.engine).generate()
        basis=generated.basis
    (private/"parent-basis.json").write_text(json.dumps({'rows':basis.basis_rows}),encoding="utf-8")
    r_width=4*params.public_gs_squared_bound*smoothing_factor(m,128)
    sample_r=FiniteSampleR(params.q,m,r_width)
    if a.saved_input_directory:
        r_rows=transformation;matrix_attempts=None
    else:
        event("real_whole_matrix_SampleR")
        r=sample_r.sample();r_rows=r.rows;matrix_attempts=r.matrices_sampled
    (private/"public-transformation.json").write_text(json.dumps({'rows':r_rows}),encoding="utf-8")
    public_norm=sum(x*x for row in r_rows for x in row)
    sigma2=4*params.public_gs_squared_bound*max(1,public_norm)*smoothing_factor(m,128)
    event("exact_transform_full_kernel_completion")
    prepared=prepare_basis_del(basis,r_rows,reduce_completion=a.reduce_completion)
    (private/"completed-basis.json").write_text(json.dumps({'rows':prepared.completed_basis.basis_rows}),encoding="utf-8")
    event("admit_and_execute_real_RandBasis")
    delegate=FiniteBasisDel(basis,r_rows,sigma2,reduce_completion=a.reduce_completion)
    result=delegate.sample()
    (private/"delegated-basis.json").write_text(json.dumps({'rows':result.basis.basis_rows}),encoding="utf-8")
    record=dict(schema="A-ABB-ROM-BASISDEL-PRIMITIVE/1",n=params.n,q=params.q,m=m,
        root_is_MP12_computational_input_not_ABB_TrapGen=True,
        source_root_gs_squared_bound=params.public_gs_squared_bound,
        public_R_width_squared=int(r_width),public_R_frobenius_squared=public_norm,
        sigma_squared=int(sigma2),matrix_attempts=matrix_attempts,
        saved_input_reused=bool(a.saved_input_directory),new_root_or_R_generations=0 if a.saved_input_directory else 2,
        checked_completion_reduction=a.reduce_completion,
        complete_target_kernel_verified=True,ordered_completion_gs_not_increased=prepared.ordered_gs_not_increased,
        maximum_completion_gs_not_increased=prepared.max_gs_not_increased,
        randbasis_draws=result.draws_used,independent_vectors=result.independent_vectors,
        full_kernel_determinant_matches=abs(matrix(ZZ,result.basis.basis_rows).det())==params.q**params.n,
        total_seconds=time.monotonic()-start,events=events,
        sample_R_certificate=sample_r.certificate(),private_GS_or_scalar_profiles_published=False,
        full_HIBE_implemented=False,paper_parameter_conditions_admitted=False,
        security_claim="none",backend_admitted=False,parameters_are_formal=False,
        limitations=['not ABB TrapGen','not two levels or byte HIBE','finite theorem3/model conditions pending'])
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('x',encoding='utf-8') as f:f.write(json.dumps(record,indent=2)+'\n')
    pending.unlink();event("completed")
    return 0


if __name__=="__main__":raise SystemExit(main())
