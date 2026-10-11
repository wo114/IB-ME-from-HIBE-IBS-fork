"""Independent qFALL -> CHKP extension -> Sage native GPV public pilot.

256 sampled positions are a NEW comparison batch, not the existing 32-bit
cache, a durable key, real H/G or a complete HIBE. Positive phase decoding
is still conditional on basis/noise/sampler obligations and toy n=1.
"""

import argparse
from dataclasses import asdict
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path
import time

from sage.all import QQ
from experiments.research.chkp_basis import ext_basis
from experiments.research.ibme_chain_audit import phase_probe, _block
from experiments.research.ibme_root_sampler_audit import CountingRandom, checked_sage_lll, geometry
from experiments.research.ibme_joint_parameters import smoothing_factor, evaluate_noise
from experiments.research.ibme_noise_budget import RoundedNoiseParams
from experiments.research.ibme_rounded_noise import build_rounded_noise
from experiments.research.chkp_gpv import CHKPGPVSampler
from .qfall_bridge import public_fixture, run_fixture, validate_root, QFALL_REV
from .sage_native_gpv import NativePublicGPV

ROOT = Path(__file__).resolve().parents[3]
EPSILON_BITS = 32
CONFIGS = ((17,8),(257,16),(1073741827,48))


def one_probe(q, m_bar, binary):
    start = time.monotonic()
    label = f"native-qfall-q{q}-bar{m_bar}".encode()
    f = public_fixture(1,q,m_bar,seed=label)
    root = validate_root(f,run_fixture(f,binary))
    m, k = root.public.ncols, (q-1).bit_length()
    # MP12 Lemma 5.3 bound + ||R||_2 <= ||R||_F, R entries bounded by 1:
    # 5*(1+sqrt(m_bar*n*k))^2 <= 10*(1+m_bar*n*k).
    root_bound = 10*(1+m_bar*k)
    root_lengths, _ = geometry(root)
    if max(root_lengths) > root_bound:
        raise ArithmeticError("MP12 public fixture GS bound failed")
    shape = type("PublicShape", (), dict(n=1,q=q))()
    parent_raw = ext_basis(root,_block(shape,m,CountingRandom(label+b"parent-block")))
    parent_width = 4*root_bound*smoothing_factor(2*m,EPSILON_BITS)
    parent_sampler = NativePublicGPV(parent_raw,parent_width,public_test_fixture=True)
    parent,count = parent_sampler.randomize_public_basis(test_seed=101,max_vectors=2*m+32)
    parent = checked_sage_lll(parent,parent_width*2*m)
    leaf = ext_basis(parent,_block(shape,m,CountingRandom(label+b"leaf-block")))
    leaf_width = 4*(parent_width*2*m)*smoothing_factor(3*m,EPSILON_BITS)
    leaf = checked_sage_lll(leaf,parent_width*2*m)
    local_probe = {}
    try:
        ref = CHKPGPVSampler(leaf,leaf_width,epsilon_bits=EPSILON_BITS)
        local_probe = dict(status="constructor_accepted",worst_tape_bytes=ref.random_tape_bytes)
    except ValueError as exc:
        local_probe = dict(status="constructor_rejected",reason=str(exc))
    native = NativePublicGPV(leaf,leaf_width,public_test_fixture=True)
    source = CountingRandom(label+b"targets")
    from experiments.research.gaussian_reference import draw_uniform_integer
    targets = tuple((draw_uniform_integer(source,q),) for _ in range(256))
    batch = native.sample_batch(targets,test_seed=202)
    norms = tuple(sum(x*x for x in row) for row in batch.preimages)
    noise_params = RoundedNoiseParams(q,Fraction(4,q),tail_bits=64,mass_bits=96,precision_bits=160)
    noise = build_rounded_noise(noise_params)
    phases = [phase_probe(batch,CountingRandom(label+f"phase{i}".encode()),noise) for i in range(2)]
    budget = evaluate_noise(q=q,dimension=3*m,width_squared=leaf_width,alpha=Fraction(4,q),
                            error_bits=32,seed_bits=256,encapsulations=2)
    return dict(q=q,n=1,m_bar=m_bar,k=k,dimensions=dict(root=m,parent=2*m,leaf=3*m),
                qfall_revision=QFALL_REV,public_seed=label.decode(),root_kernel_and_determinant_verified=True,
                root_gs_squared_max=str(max(root_lengths)),root_gs_squared_bound=root_bound,
                parent_width_squared=parent_width,leaf_width_squared=leaf_width,
                parent_native_draws=count,parent_full_basis_randomized=True,
                native_profile=native.certificate(),existing_local_leaf_probe=local_probe,
                native_batch_positions=256,fixed_leaf_cache_used=False,cache_wire_created=False,
                preimage_equations_verified=len(batch.preimages),measured_norm_good=sum(x<=leaf_width*3*m for x in norms),
                conditional_noise_budget=budget,rounded_noise_profile=noise.certificate(),phase_diagnostics=phases,
                phase_failures=sum(x["honest_rounded_noise_failed"] for x in phases),
                wall_seconds=time.monotonic()-start,security_claim="none",backend_admitted=False,
                parameters_are_formal=False,full_hibe_implemented=False,
                unresolved=["formal parameter/LWE cost", "root regularity and native sampler finite error",
                            "native rejection/resource/LLL bounds", "real H/G", "durable 256-bit keys/wire",
                            "IBS composition and attacks"])


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary",type=Path,default=ROOT/"test-results/qfall-target/release/ibme-qfall-public-fixture")
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--only-q",type=int)
    args=parser.parse_args(argv)
    out=[]
    for q,bar in CONFIGS:
        if args.only_q is not None and q!=args.only_q:continue
        try:
            row=one_probe(q,bar,args.binary)
        except Exception as exc:
            row=dict(q=q,m_bar=bar,status="failed",error=str(exc),security_claim="none",backend_admitted=False)
        out.append(row)
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(out,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        print(json.dumps({key:row.get(key) for key in ["q","status","dimensions","phase_failures","wall_seconds","error"]}),flush=True)
    return 0 if out and all("error" not in r for r in out) else 2


if __name__=="__main__":
    raise SystemExit(main())
