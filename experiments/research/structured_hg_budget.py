"""Read-only actual structured H/G public width/tape/finite-term certificate.

Private trapdoors are inputs solely to the existing exact precision gate.
Output contains its public certificate, no R, preimages or measured geometry.
"""

import argparse
import json
from pathlib import Path
from unittest.mock import patch

from ibme.core.randomness import SecureRandom
from ibme.core.errors import InvalidParameterError
from ibme.hibe.mp12_structured import StructuredMasterSecret, StructuredMP12HIBE, StructuredHIBEParams
from ibme.lattice.matrix_sampling.mp12_extension import StructuredLeftSampler
from ibme.lattice.matrix_sampling.mp12_structured import StructuredPreimageSampler


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--primitive-directory",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    if args.output.exists(): raise ValueError("new public budget receipt required")
    def forbidden(*a,**k): raise AssertionError("budget report requested entropy or sampling")
    with patch.object(SecureRandom,"read",forbidden),patch.object(StructuredPreimageSampler,"sample",forbidden):
        master=StructuredMasterSecret.from_bytes((args.primitive_directory/"master.bin").read_bytes())
        parent=StructuredMP12HIBE().extract(master,b"B"*86,rng=type("NoEntropy",(),{"read":forbidden})())
        params=master.params;oracle=master.public_key.oracle
        h1=oracle.h((b"B"*86,))
        first=StructuredLeftSampler(master.trapdoor,tuple(row[:-params.w] for row in h1))
        leaf=StructuredLeftSampler(parent.trapdoor,oracle.h((b"B"*86,b"A"*86)))
        assert (first.dimension,leaf.dimension)==(params.parent_sample_dimension,params.leaf_dimension)
        assert first.output_squared==params.parent_width_squared and leaf.output_squared==params.leaf_width_squared
        parent_tape=params.w*first.random_tape_bytes;leaf_tape=256*leaf.random_tape_bytes
        assert parent_tape<=2**44 and leaf_tape<=2**48
        try: StructuredHIBEParams(n=128,q=65537,root_r_squared=529)
        except InvalidParameterError as exc: blocked=str(exc)
        else: raise AssertionError("n128 root must not silently bypass full-H resource cap")
        report=dict(schema="STRUCTURED-HG-COMPLETE-GROUP-BUDGET/1",status="passed",parameters=params.record(),
            parent=first.public_certificate(),leaf=leaf.public_certificate(),noise=params.noise_budget(),
            whole_parent_tape_bytes=parent_tape,whole_leaf_tape_bytes=leaf_tape,
            tape_is_request_upper_bound_not_allocated_memory=True,entropy_reads=0,sampling_calls=0,
            n128_q65537_root_only_remains_blocked=blocked,
            stored_root_R_entries=2*params.n*params.w,stored_parent_R_entries=(2*params.m-params.w)*params.w,
            fixed_leaf_integers=256*params.leaf_dimension,full_kernel_bases_expanded=0,
            full_SampleD_TV_or_failure_upper=None,formal_security_estimation=None,
            security_claim="none",backend_admitted=False,parameters_are_formal=False)
    args.output.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(dict(status="passed",whole_parent_tape_bytes=parent_tape,whole_leaf_tape_bytes=leaf_tape)))


if __name__=="__main__":main()
