"""Saved CSPRNG root -> MP12 DelTrap -> fixed256 leaf -> private restore.

Distinct public profile from CHKP/RandBasis; no reuse or relabeling of old
receiver addresses. No formal parameters/model admission, or full IBME.
Source uses the explicit master-owned private-input method, not private fields.
"""

import argparse
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import time

from .compact_delegation import CompactGTrapdoor,FiniteDelTrap,split_extension,public_gpv_tv_upper
from .delegation_state import MasterTreeState
from .finite_gpv import FirstFiniteGPV
from .identity import ROHIBEContext
from .leaf_state import FixedSeedState,SeedScope
from .root_probe import scope_for,canonical_json
from .seed_kem import SeedCapsule,encapsulate_seed,decapsulate_seed

ROOT=Path(__file__).resolve().parents[3]
LEAF_PROFILE=b"MP12-DELTRAP-BINARY/1 + FIRST-SUITE-FINITE-GPV/1; epsilon128; diagnostic exact LLL"


def no_generation(plan):raise RuntimeError("restore attempted new private generation")


def restore_only(manifest_path):
    path=Path(manifest_path);m=json.loads(path.read_text(encoding="utf-8"))
    o=ROHIBEContext.from_bytes(bytes.fromhex(m["oracle_hex"]))
    r,s=bytes.fromhex(m["receiver_hex"]),bytes.fromhex(m["sender_hex"])
    from experiments.research.chkp_basis import ModMatrixReference
    parent=ModMatrixReference(o.parent_rows(r),o.q)
    private=(path.parent/"parent-trapdoor.bin").read_bytes()
    key=CompactGTrapdoor.from_bytes(private,expected_public=parent,expected_width_squared=Fraction(m["source_width"]))
    scope=SeedScope(o,r,Fraction(m["leaf_width"]),LEAF_PROFILE)
    raw=(path.parent/"fixed-leaf-state.bin").read_bytes()
    state=FixedSeedState.from_bytes(raw,expected_scope=scope)
    leaf=state.resolve(s,no_generation)
    capsule=SeedCapsule.from_bytes((path.parent/"capsule.bin").read_bytes())
    seed=decapsulate_seed(leaf,capsule)
    return dict(compact_parent_byte_equal=key.to_bytes()==private,fixed_leaf_byte_equal=state.to_bytes()==raw,
        fixed_positions=len(leaf.preimages),seed_hash_matches=sha256(seed).hexdigest()==m["seed_sha256"],
        new_root_parent_or_leaf_generations=0,private_native_conversion_used=False,
        security_claim="none",backend_admitted=False)


def one_probe(source_manifest,binary,private_directory):
    from sage.all import QQ,RR
    from ibme.core.randomness import SecureRandom
    from ibme.protocol.hybrid_hibe import HybridLimits,encoded_identity
    from experiments.research.chkp_basis import ModMatrixReference,ext_basis
    from experiments.research.ibme_root_sampler_audit import checked_sage_lll
    from experiments.research.ibme_joint_parameters import smoothing_factor,evaluate_noise
    from experiments.research.ibme_noise_budget import RoundedNoiseParams
    from experiments.research.ibme_rounded_noise import build_rounded_noise
    from .entropy import CheckedEntropy

    directory=Path(private_directory).resolve();allowed=(ROOT/"test-results").resolve()
    if not directory.is_relative_to(allowed) or directory==allowed:raise ValueError("new ignored private directory required")
    directory.mkdir(parents=True,exist_ok=False)
    pending=directory/"generation.pending";pending.write_bytes(b"reserved compact-profile lifetime; no restart here\n")
    started=time.monotonic();source_manifest=Path(source_manifest)
    original=json.loads(source_manifest.read_text(encoding="utf-8"))
    source_o=ROHIBEContext.from_bytes(bytes.fromhex(original["oracle_hex"]))
    source_scope=scope_for(source_o,original["chain_plan"])
    raw_master=(source_manifest.parent/"master-tree.bin").read_bytes()
    tree=MasterTreeState.from_bytes(raw_master,expected_scope=source_scope)
    root=tree.root_basis_for_research()
    n,m,q=source_o.n,source_o.m,source_o.q;w=n*(q-1).bit_length();p=2*m-w
    width=source_scope.parent_width_squared
    parent_bound=10*(1+w*p*width)
    leaf_width=4*parent_bound*smoothing_factor(3*m,128)
    noise_p=RoundedNoiseParams(q,Fraction(4,q),tail_bits=64,mass_bits=96,precision_bits=160)
    config=canonical_json(dict(version="FIRST-SUITE/MP12-DELTRAP-PILOT/1",n=n,m=m,q=q,
        root_gs_squared_bound=str(source_scope.root_gs_squared_bound),source_width_squared=str(width),
        delegated_full_basis_gs_squared_bound=str(parent_bound),leaf_width_squared=str(leaf_width),
        source_epsilon_bits=128,leaf_profile=LEAF_PROFILE.decode(),noise=noise_p.to_record(),
        parameters_are_formal=False,security_claim="none",backend_admitted=False))
    o=ROHIBEContext(n,m,q,root.public.rows,config)
    limits=HybridLimits(backend_id=b"chkp-first-research")
    r,s=encoded_identity(b"Bob",limits,b"P"),encoded_identity(b"Alice",limits,b"C")
    base,tail=split_extension(root,ModMatrixReference(o.h((r,)),q))
    base=checked_sage_lll(base,QQ(str(source_scope.root_gs_squared_bound)))
    sampler=FirstFiniteGPV(base,str(width),epsilon_bits=128)
    delegate=FiniteDelTrap(sampler,tail)
    print(canonical_json(dict(stage="finite_DelTrap",prefix=p,columns=w,full_parent=2*m)).decode(),flush=True)
    compact=delegate.sample()
    if compact.public.rows!=o.parent_rows(r):raise ArithmeticError("delegated matrix differs from real H")
    parent_wire=compact.to_bytes();(directory/"parent-trapdoor.bin").write_bytes(parent_wire)
    compact=CompactGTrapdoor.from_bytes(parent_wire,expected_public=compact.public,expected_width_squared=width)
    parent=compact.to_basis(binary)
    leaf_basis=ext_basis(parent,ModMatrixReference(o.h((r,s)),q))
    leaf_basis=checked_sage_lll(leaf_basis,QQ(str(parent_bound)))
    leaf_sampler=FirstFiniteGPV(leaf_basis,str(leaf_width),epsilon_bits=128)
    scope=SeedScope(o,r,Fraction(leaf_width),LEAF_PROFILE);state=FixedSeedState(scope)
    calls=[];entropy=CheckedEntropy(SecureRandom(),256*leaf_sampler.random_tape_bytes)
    def generate(plan):
        calls.append(1)
        return tuple(leaf_sampler.sample(target,rng=entropy) for target in plan.targets)
    print(canonical_json(dict(stage="finite_leaf256",dimension=3*m)).decode(),flush=True)
    leaf=state.resolve(s,generate);state.resolve(s,no_generation)
    private_leaf=state.to_bytes();(directory/"fixed-leaf-state.bin").write_bytes(private_leaf)
    noise=build_rounded_noise(noise_p);source=SecureRandom();errors=[];capsules=[];seeds=[]
    for _ in range(2):
        seed=source.read(32);capsule=encapsulate_seed(o,r,s,seed,noise,rng=source)
        recovered=decapsulate_seed(leaf,SeedCapsule.from_bytes(capsule.to_bytes()))
        errors.append(sum((a^b).bit_count() for a,b in zip(seed,recovered)));capsules.append(capsule);seeds.append(seed)
    (directory/"capsule.bin").write_bytes(capsules[0].to_bytes())
    manifest=dict(oracle_hex=o.to_bytes().hex(),receiver_hex=r.hex(),sender_hex=s.hex(),
        source_width=str(width),leaf_width=str(leaf_width),seed_sha256=sha256(seeds[0]).hexdigest())
    path=directory/"public-restore-manifest.json";path.write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8")
    result=dict(n=n,q=q,dimensions=[m,2*m,3*m],sampling_prefix_dimension=p,delegated_gaussian_columns=w,
        parent_compact_entries=p*w,parent_full_basis_entries=(2*m)**2,compact_parent_wire_bytes=len(parent_wire),
        full_parent_private_wire_lower_bound_bytes=6*(2*m)**2,fixed_leaf_wire_bytes=len(private_leaf),
        root_generations=0,parent_generations=1,leaf_generations=len(calls),fixed_positions=256,
        source_width_squared=str(width),parent_full_basis_gs_squared_bound=str(parent_bound),leaf_width_squared=str(leaf_width),
        deltrap_public_certificate=delegate.certificate(),parent_actual_entropy_bytes=delegate.last_entropy_bytes,
        leaf_actual_entropy_bytes=entropy.bytes_used,leaf_batch_public_tv_log2_upper=float(RR(min(QQ(1),256*public_gpv_tv_upper(leaf_sampler))).log(2)),
        seed_bits_tested=512,seed_bit_errors=errors,raw_capsule_bytes=len(capsules[0].to_bytes()),
        noise=noise.certificate(),conditional_noise_budget=evaluate_noise(q=q,dimension=3*m,width_squared=str(leaf_width),
            alpha=Fraction(4,q),error_bits=64,seed_bits=256,encapsulations=2**20),
        original_identity_bytes=[3,5],encoded_identity_bytes=86,seed_bytes=32,
        generation_seconds=time.monotonic()-started,parameters_are_formal=False,security_claim="none",backend_admitted=False,
        legacy_profile_relabelled=False,same_address_regenerated=False,full_hibe_or_ibme_implemented=False,
        missing=["formal hardness/resource inputs", "optimized/admitted sampler", "CHKP key-distribution/model mapping for DelTrap variant", "seven-method/CLI/protocol acceptance"])
    (directory/"public-generation-receipt.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    child=subprocess.run([sys.executable,"-m","experiments.research.first_suite.compact_delegation_probe",
        "--restore-only",str(path)],cwd=ROOT,capture_output=True,text=True,timeout=60)
    if child.returncode:raise RuntimeError("compact parent/leaf restore failed; private diagnostics withheld")
    result["fresh_process"]=json.loads(child.stdout);pending.unlink();return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-manifest",type=Path)
    parser.add_argument("--binary",type=Path,default=ROOT/"test-results/qfall-target/release/ibme-qfall-private-root")
    parser.add_argument("--private-directory",type=Path);parser.add_argument("--output",type=Path)
    parser.add_argument("--restore-only",type=Path);a=parser.parse_args(argv)
    if a.restore_only:print(canonical_json(restore_only(a.restore_only)).decode());return 0
    if a.source_manifest is None or a.private_directory is None or a.output is None:parser.error("explicit paths required")
    output=a.output.resolve();allowed=(ROOT/"test-results").resolve()
    if not output.is_relative_to(allowed) or output.exists() or output.is_relative_to(a.private_directory.resolve()):
        raise ValueError("new public output outside private directory required")
    report=one_probe(a.source_manifest,a.binary,a.private_directory)
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open("x",encoding="utf-8") as f:f.write(json.dumps(report,indent=2)+"\n")
    print(canonical_json(dict(seed_bit_errors=report["seed_bit_errors"],fresh=report["fresh_process"],seconds=report["generation_seconds"])).decode())
    return 0


if __name__=="__main__":raise SystemExit(main())
