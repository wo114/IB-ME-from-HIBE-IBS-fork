"""Public-test root diagnostic; do not change the delivered CHKP backend.

Sage LLL is an independent diagnostic, not the bounded <=64-dimensional
reduction implementation, an admitted key-generation step, or a uniform
resource/failure theorem. Every fixed seed is attempted once; raw sampler
rejections and postprocessing failures stay in the report. No private key
values or sampled vectors are exported.
"""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import time

from sage.all import QQ, ZZ, matrix, vector

from ibme.core.randomness import DeterministicRandom
from .chkp_basis import KernelBasis
from .chkp_genbasis import AP09Parameters, gen_basis, genbasis_certificate
from .chkp_gpv import CHKPGPVSampler
from .ibme_joint_parameters import smoothing_factor


class CountingRandom:
    def __init__(self, seed):
        self.source = DeterministicRandom(seed)
        self.bytes_used = 0

    def read(self, count):
        value = self.source.read(count)
        self.bytes_used += len(value)
        return value


def geometry(basis):
    """Independent Sage row-GS, transposed from the declared column basis."""
    orthogonal, coefficients = matrix(QQ,basis.basis_rows).transpose().gram_schmidt()
    lengths = tuple(row.dot_product(row) for row in orthogonal.rows())
    return lengths, coefficients


def checked_sage_lll(basis, gs_upper):
    original = matrix(ZZ,basis.basis_rows)
    rows, transform = original.transpose().LLL(delta=QQ(99)/100, transformation=True)
    reduced, column_transform = rows.transpose(), transform.transpose()
    if original*column_transform != reduced or abs(column_transform.det()) != 1:
        raise ArithmeticError("Sage LLL transform did not preserve the integer lattice")
    result = KernelBasis(basis.public, reduced)
    lengths, mu = geometry(result)
    if (max(lengths)>gs_upper or
            any(abs(mu[i,j])>QQ(1)/2 for i in range(len(lengths)) for j in range(i)) or
            any(lengths[i]+mu[i,i-1]**2*lengths[i-1]<QQ(99)/100*lengths[i-1]
                for i in range(1,len(lengths)))):
        raise ArithmeticError("exact LLL size/GS/Lovasz check failed")
    return result


def sampler_attempt(basis, width_squared, seed, *, epsilon_bits=32):
    start = time.perf_counter()
    lengths, _ = geometry(basis)
    record = dict(gs_squared_min=str(min(lengths)),gs_squared_max=str(max(lengths)),
                  max_scalar_width_squared=str(max(QQ(width_squared)/x for x in lengths)),
                  min_scalar_width_squared=str(min(QQ(width_squared)/x for x in lengths)))
    try:
        sampler = CHKPGPVSampler(basis,width_squared,epsilon_bits=epsilon_bits)
        certificate = sampler.certificate()
        record.update(dimension=sampler.dimension,tv_upper=certificate["tv_upper_including_abort"],
                      public_tape_bytes=sampler.random_tape_bytes,
                      path_resources=certificate["path_resources"],samples=[])
        for syndrome in (0,17):
            if syndrome>=basis.public.q:
                continue
            entropy = CountingRandom(seed+b":preimage:"+str(syndrome).encode())
            x = sampler.sample((syndrome,),rng=entropy)
            equation = tuple(int(v)%basis.public.q for v in
                             matrix(ZZ,basis.public.rows)*vector(ZZ,x))==(syndrome,)
            if not equation:
                raise ArithmeticError("root preimage equation failed")
            record["samples"].append(dict(target=syndrome,equation=True,
                                            norm_squared=str(sum(v*v for v in x)),
                                            actual_entropy_bytes=entropy.bytes_used))
        record["status"] = "root_preimages_sampled"
    except Exception as exc:
        record.update(status="rejected",error_type=type(exc).__name__,error=str(exc))
    record["seconds"] = time.perf_counter()-start
    return record


def audit_root(params, seed, *, diagnostic_lll=True):
    started = time.perf_counter()
    certificate = genbasis_certificate(params)
    record = dict(seed=seed.decode(),parameters=certificate,attempts=1,
                  fixed_seed_test_only=True,security_claim="none",backend_admitted=False)
    try:
        source = CountingRandom(seed)
        root = gen_basis(params,rng=source).basis
        record.update(genbasis_seconds=time.perf_counter()-started,
                      genbasis_actual_entropy_bytes=source.bytes_used,
                      public_matrix_sha256=sha256(json.dumps(dict(q=root.public.q,rows=root.public.rows),
                          separators=(",",":")).encode()).hexdigest())
        dimension = root.public.ncols
        width = 4*params.gs_squared_bound*smoothing_factor(dimension,32)
        record["root_sampling_width_squared"] = width
        record["raw"] = sampler_attempt(root,width,seed+b":raw")
        print(seed.decode(),"raw",record["raw"]["status"],flush=True)
        if diagnostic_lll:
            reduction_started = time.perf_counter()
            reduced = checked_sage_lll(root,params.gs_squared_bound)
            record["diagnostic_lll"] = dict(
                algorithm="installed Sage LLL + exact transform/GS/size/Lovasz verification",
                seconds=time.perf_counter()-reduction_started,
                bounded_chkp_reducer_used=False,production_or_uniform_resource_admission=False,
                sampler=sampler_attempt(reduced,width,seed+b":lll"))
            print(seed.decode(),"diagnostic LLL",record["diagnostic_lll"]["sampler"]["status"],flush=True)
        record["root_generated"] = True
    except Exception as exc:
        record.update(error_type=type(exc).__name__,error=str(exc))
        print(seed.decode(),"audit failure",type(exc).__name__,str(exc),flush=True)
    record["total_seconds"] = time.perf_counter()-started
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",required=True)
    args = parser.parse_args(argv)
    params = AP09Parameters(n=1,q=257,random_rows=55,m1=55,m2=128,hadamard_scale=21)
    records=[]
    for seed in (b"ibme-joint-root-0",b"ibme-joint-root-1"):
        records.append(audit_root(params,seed))
        Path(args.output).write_text(json.dumps(records,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    return 0 if all(r.get("diagnostic_lll",{}).get("sampler",{}).get("status")==
                    "root_preimages_sampled" for r in records) else 2


if __name__ == "__main__":
    raise SystemExit(main())
