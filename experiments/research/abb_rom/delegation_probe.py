"""One retained real AP09 root -> two true wide BasisDel operations.

Transformation matrices use system Gaussian bytes, not an identity oracle.
This is primitive evidence, never a complete HIBE/ROM/Hybrid lifecycle.
Every stage checkpoints counts/result before publication; no auto-regeneration.
Fixed checked LLL after each RandBasis is explicitly part of this probe.
"""

import argparse
from dataclasses import asdict
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path
import platform
import re
import resource
import sys
from time import perf_counter

from sage.all import ZZ, matrix

from ibme.core.randomness import SecureRandom
from ibme.hibe.abb_rom import ABBTrapGenParams, abb_parameter_screen, MatrixSampleR, MatrixBasisDel, SampleRResult
from ibme.lattice.research import KernelBasis, ModMatrixReference
from ibme.lattice.matrix_sampling import MatrixFiniteOptions, MatrixFiniteGPV, matrix_checked_lll


class CountingEntropy:
    def __init__(self):
        self.source = SecureRandom()
        self.bytes_used = 0
    def read(self, count):
        output = self.source.read(count)
        self.bytes_used += len(output)
        return output


def run(saved_private_directory, private_directory, baseline_commit, resume_input_directory=None):
    repo = Path(__file__).resolve().parents[3]
    saved, private = Path(saved_private_directory).resolve(), Path(private_directory).resolve()
    ignored = (repo/"test-results").resolve()
    if not saved.is_relative_to(ignored) or not private.is_relative_to(ignored):
        raise ValueError("private inputs and outputs must remain under ignored test-results")
    if private.exists() or not (saved/"completed").is_file() or (saved/"pending").exists():
        raise ValueError("completed retained source and new output directory required")
    if not re.fullmatch(r"[0-9a-f]{40}", baseline_commit):
        raise ValueError("host-verified baseline commit required before entropy")
    source = saved/"root-private.json"
    if not source.is_file() or source.stat().st_size > 16*2**20:
        raise ValueError("bounded retained root required")
    data = json.loads(source.read_text(encoding="utf-8"))
    root_params = ABBTrapGenParams(1, 549755813911, 56, 56, 192, hadamard_scale=32)
    if (set(data) != {"schema","params","a","u0","basis"} or
            data["schema"] != "ABB-AP09-PRIVATE-PROBE/1" or data["params"] != asdict(root_params)):
        raise ValueError("retained real AP09 profile differs")
    root = KernelBasis(ModMatrixReference(data["a"],root_params.q),data["basis"])
    u0 = tuple(data["u0"])
    del data
    options = MatrixFiniteOptions()
    screen = abb_parameter_screen(root_params)
    widths = [int(screen["sigma1_squared"]),int(screen["sigma2_squared"])]
    private.mkdir(parents=True)
    pending = private/"pending"
    receipt = {"schema":"ABB-REAL-WIDE-DELEGATION/1","status":"running",
        "baseline_commit":baseline_commit,"root_generations":0,"root_reused":True,
        "n":root_params.n,"q":str(root_params.q),"dimension":root_params.dimension,
        "input_is_real_AP09_root":True,"identity_oracle_implemented":False,
        "parameters":screen,"options":asdict(options),"stages":[],
        "normalization":"matrix-fixed-LLL-delta075-eta0501-exact-size-and-Lovasz074/1",
        "normalization_is_explicit_implementation_adaptation":True,
        "ROM_instantiation_exercised":False,"full_HIBE_backend_tested":False,
        "security_claim":"none","backend_admitted":False,"parameters_are_formal":False,
        "randomness":"system CSPRNG; no native or fixed-seed RNG",
        "python":sys.version,"platform":platform.platform()}
    files = ["experiments/research/abb_rom/delegation_probe.py","src/ibme/hibe/abb_rom/primitives.py",
        "src/ibme/lattice/matrix_sampling/scalar.py","src/ibme/lattice/matrix_sampling/gpv.py",
        "src/ibme/lattice/matrix_sampling/basis.py","src/ibme/lattice/matrix_sampling/randbasis.py"]
    receipt["source_sha256"] = {name:sha256((repo/name).read_bytes()).hexdigest() for name in files}
    def checkpoint():
        (private/"public-progress.json").write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8")
    def input_snapshot(name,basis,r,width):
        (private/(name+"-input.json")).write_text(json.dumps({"q":root_params.q,
            "a":basis.public.rows,"basis":basis.basis_rows,"r":r.rows,"width_squared":str(width)},
            separators=(",",":")),encoding="utf-8")
    started = perf_counter()
    entropy = CountingEntropy()
    current = root
    retained_input = None
    if resume_input_directory is not None:
        retained = Path(resume_input_directory).resolve()
        if not retained.is_relative_to(ignored) or not (retained/"interrupted-receipt.json").is_file():
            raise ValueError("explicit terminal zero-sampling interruption receipt required")
        history = json.loads((retained/"interrupted-receipt.json").read_text(encoding="utf-8"))
        facts = history.get("interruption",{})
        if (history.get("status")!="interrupted-before-parent-RandBasis" or
                facts.get("verified_process_absent") is not True or facts.get("parent_RandBasis_started") is not False or
                facts.get("additional_entropy_after_SampleR")!=0):
            raise ValueError("retained issuance is not eligible for zero-sampling continuation")
        retained_input = json.loads((retained/"level1-input.json").read_text(encoding="utf-8"))
        if (retained_input["q"]!=root_params.q or retained_input["width_squared"]!=str(widths[0]) or
                retained_input["a"]!=[list(row) for row in root.public.rows] or
                retained_input["basis"]!=[list(row) for row in root.basis_rows]):
            raise ValueError("retained root/input differs")
        receipt["zero_sampling_continuation"]={"old_source_sha256":history["source_sha256"],
            "old_R_and_root_reused":True,"old_root_and_R_generations_in_new_run":0,
            "changed_component":"declared deterministic normalization; distributions/widths/guards retained"}
    try:
        for level,width in enumerate(widths,1):
            pending.write_text(f"level{level} whole SampleR\n",encoding="utf-8")
            checkpoint()
            before,time0 = entropy.bytes_used,perf_counter()
            sampler = MatrixSampleR(root_params.q,root_params.dimension,int(screen["matrix_gaussian_squared_width"]),
                options=options)
            if level==1 and retained_input is not None:
                r = SampleRResult(root_params.q,tuple(tuple(x for x in row) for row in retained_input["r"]),
                    history["stages"][0]["matrices_sampled"],int(screen["matrix_gaussian_squared_width"]))
                matrix_sampled = 0
            else:
                r = sampler.sample(rng=entropy)
                matrix_sampled = r.matrices_sampled
            input_snapshot(f"level{level}",current,r,width)
            receipt["stages"].append({"name":f"level{level} whole SampleR","status":"passed",
                "seconds":perf_counter()-time0,"entropy_bytes":entropy.bytes_used-before,
                "matrices_sampled":matrix_sampled,"retained_matrix_reused":matrix_sampled==0,
                "public_distribution_certificate":sampler.certificate()})
            checkpoint()
            pending.write_text(f"level{level} BasisDel preparation\n",encoding="utf-8")
            before,time0 = entropy.bytes_used,perf_counter()
            delegator = MatrixBasisDel(current,r.rows,width,options=options,reduce_completion=True)
            receipt["stages"].append({"name":f"level{level} BasisDel preparation","status":"passed",
                "seconds":perf_counter()-time0,"entropy_bytes":entropy.bytes_used-before,
                "wide_scalar_and_all_path_resources_admitted":True})
            checkpoint()
            pending.write_text(f"level{level} RandBasis\n",encoding="utf-8")
            before,time0 = entropy.bytes_used,perf_counter()
            result = delegator.sample(rng=entropy)
            raw = result.basis
            (private/f"level{level}-raw-basis.json").write_text(json.dumps({"q":root_params.q,
                "a":raw.public.rows,"basis":raw.basis_rows},separators=(",",":")),encoding="utf-8")
            receipt["stages"].append({"name":f"level{level} RandBasis","status":"passed",
                "seconds":perf_counter()-time0,"entropy_bytes":entropy.bytes_used-before,
                "draws_used":result.draws_used,"complete_kernel_verified":True,
                "dimension":raw.public.ncols})
            checkpoint()
            pending.write_text(f"level{level} fixed checked LLL normalization\n",encoding="utf-8")
            before,time0 = entropy.bytes_used,perf_counter()
            current = matrix_checked_lll(raw,width*root_params.dimension)
            (private/f"level{level}-normalized-basis.json").write_text(json.dumps({"q":root_params.q,
                "a":current.public.rows,"basis":current.basis_rows},separators=(",",":")),encoding="utf-8")
            receipt["stages"].append({"name":f"level{level} fixed checked LLL normalization","status":"passed",
                "seconds":perf_counter()-time0,"entropy_bytes":entropy.bytes_used-before,
                "full_lattice_and_public_GS_bound_verified":True})
            checkpoint()
        pending.write_text("fresh final-leaf SamplePre\n",encoding="utf-8")
        before,time0 = entropy.bytes_used,perf_counter()
        leaf_sampler = MatrixFiniteGPV(current,int(screen["decryption_tau_squared"]),epsilon_bits=128,options=options)
        x = leaf_sampler.sample(u0,rng=entropy)
        equation = all(sum(a*b for a,b in zip(row,x))%root_params.q==target for row,target in zip(current.public.rows,u0))
        if not equation:
            raise ArithmeticError("final SamplePre equation failed")
        receipt["stages"].append({"name":"fresh final-leaf SamplePre","status":"passed",
            "seconds":perf_counter()-time0,"entropy_bytes":entropy.bytes_used-before,
            "original_u0_equation_verified":True,"dimension":len(x)})
        receipt["status"] = "passed"
        pending.rename(private/"completed")
    except (Exception,KeyboardInterrupt) as exc:
        receipt["status"] = "failed"
        receipt["failure_type"] = type(exc).__name__
        receipt["failed_stage"] = pending.read_text(encoding="utf-8").strip() if pending.exists() else "preflight"
        # Keep private inputs/pending. No diagnostics reveal secret geometry.
    receipt["seconds"] = perf_counter()-started
    receipt["entropy_bytes"] = entropy.bytes_used
    receipt["process_peak_rss_kib"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    receipt["same_group_two_level_noise_sufficient"] = screen["conditional_noise_sufficient"]
    receipt["not_covered"] = ["identity matrix RO", "five public object codecs", "fixed identity issuance/recovery",
        "HIBE bit encryption under final leaf", "Luo/Hybrid/IBME attacks", "formal parameters and hardness"]
    checkpoint()
    return receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--saved-private-directory",required=True)
    parser.add_argument("--private-directory",required=True)
    parser.add_argument("--output",required=True)
    parser.add_argument("--baseline-commit",required=True)
    parser.add_argument("--resume-input-directory")
    args = parser.parse_args()
    output = Path(args.output)
    if output.exists():
        raise FileExistsError("new public receipt required")
    receipt = run(args.saved_private_directory,args.private_directory,args.baseline_commit,args.resume_input_directory)
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open("x",encoding="utf-8") as stream:
        json.dump(receipt,stream,indent=2)
        stream.write("\n")
    print(json.dumps({"status":receipt["status"],"seconds":receipt["seconds"],"stages":len(receipt["stages"])}))
    return 0 if receipt["status"]=="passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
