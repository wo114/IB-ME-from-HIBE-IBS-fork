"""Audit ONE randomized parent -> preimage-only leaf, using public toy seeds.

Source: CHKP section 5.2 (PDF p.20), leaf-basis omission, and section 5.3
(PDF p.22), repeat-key state requirement (not implemented by this audit).
Exit 0 means ONLY this declared sampling-path gate passed; T2 remains WIP.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import time

from sage.all import QQ, ZZ, matrix, vector
from sage.env import SAGE_VERSION

from ibme.core.randomness import DeterministicRandom
from .chkp_basis import ModMatrixReference, ext_basis
from .chkp_basis_reduce import reduce_basis
from .chkp_genbasis import AP09Parameters, gen_basis, genbasis_certificate
from .chkp_gpv import CHKPGPVSampler
from .chkp_leaf_reference import sample_leaf_preimages, MAX_LEAF_TAPE_BYTES, LeafAdmissionError
from .chkp_randbasis import CHKPRandBasis
from .chkp_t2_audit import SEEDS, EPSILON_BITS, _required_width, _algebra
from .chkp_width_audit import _sampler_summary, width_interval
from .gaussian_reference import SamplingAbort, draw_uniform_integer


def run_attempt(seed, *, postprocess=True):
    if type(postprocess) is not bool:
        raise ValueError("postprocess must be bool")
    cfg = AP09Parameters(n=1, q=2, random_rows=2, m1=2, m2=8, hadamard_scale=4)
    rng = DeterministicRandom(seed.encode("ascii"))
    result = {"seed": seed, "postprocess": postprocess, "stages": [],
              "level2_randbasis_calls": 0}
    start, stage = time.perf_counter(), "GenBasis"
    try:
        basis = gen_basis(cfg, rng=rng).basis
        gs_upper = QQ(cfg.gs_squared_bound)
        for level in (1, 2):
            stage = f"level_{level}_ExtBasis"
            block = ModMatrixReference([[draw_uniform_integer(rng, cfg.q)
                                         for _ in range(cfg.m1+cfg.m2)]], cfg.q)
            expanded = ext_basis(basis, block)
            width = _required_width(expanded.public.ncols, max(gs_upper, 1))
            entry = {"level": level, "input_algebra": _algebra(expanded),
                     "width_squared": str(width),
                     "width_interval": width_interval(expanded, gs_upper)}
            result["stages"].append(entry)
            stage = f"level_{level}_SampleD_admission"
            sampler = CHKPGPVSampler(expanded, width, epsilon_bits=EPSILON_BITS)
            entry["SampleD"] = _sampler_summary(sampler)
            stage = f"level_{level}_SampleD_execution"
            if level == 2:
                # Same two targets/RNG order as the unchanged two-basis audit.
                leaf = sample_leaf_preimages(sampler, [(y,) for y in range(cfg.q)], rng=rng)
                norms = [sum(x*x for x in v) for v in leaf.preimages]
                entry.update(
                    all_syndromes_exact=[True for _ in leaf.preimages],
                    leaf_preimage_count=len(leaf.preimages),
                    leaf_integer_count=sum(len(v) for v in leaf.preimages),
                    leaf_basis_retained=False,
                    leaf_squared_norms=[str(x) for x in norms],
                    norm_reference_squared=str(width*sampler.dimension),
                    observed_norms_within_reference=all(x <= width*sampler.dimension for x in norms),
                    norm_filter_applied=False,
                    leaf_batch_tape_bytes=len(leaf.preimages)*sampler.random_tape_bytes,
                    leaf_batch_tape_cap_bytes=MAX_LEAF_TAPE_BYTES,
                    leaf_batch_tv_upper_including_abort=str(min(QQ(1), len(leaf.preimages)*sampler.tv_upper)),
                    counterfactual_randbasis_tape_bytes=(sampler.dimension+20)*sampler.random_tape_bytes)
                result["outcome"] = "leaf_preimage_path_completed"
                break
            equations = []
            for y in range(cfg.q):
                sample = vector(ZZ, sampler.sample((y,), rng=rng))
                equations.append(int((matrix(ZZ, expanded.public.rows)*sample)[0]) % cfg.q == y)
            if not all(equations):
                raise ArithmeticError("Parent preimage equation failed")
            entry["all_syndromes_exact"] = equations
            stage = "level_1_RandBasis_admission"
            rb = CHKPRandBasis(sampler, max_vectors=expanded.public.ncols+20)
            entry["RandBasis_certificate"] = rb.certificate()
            stage = "level_1_RandBasis_execution"
            drawn = rb.sample(rng=rng)
            basis = drawn.basis
            entry["raw_vectors_consumed"] = drawn.draws_used
            entry["before_postprocess"] = _algebra(basis)
            if postprocess:
                stage = "level_1_LLL"
                reduced = reduce_basis(basis)
                basis = reduced.basis
                entry["LLL"] = {"steps": reduced.steps, "swaps": reduced.swaps,
                                "after": _algebra(basis)}
            gs_upper = width*expanded.public.ncols
    except SamplingAbort as exc:
        result.update(outcome="explicit_abort", stopped_at=stage, reason=str(exc))
    except LeafAdmissionError as exc:
        result.update(outcome="admission_rejected", stopped_at="level_2_LeafBatch_admission", reason=str(exc))
    except ValueError as exc:
        outcome = "admission_rejected" if stage.endswith("_admission") else "execution_error"
        result.update(outcome=outcome, stopped_at=stage, reason=str(exc))
    result["elapsed_seconds_diagnostic_only"] = round(time.perf_counter()-start, 6)
    return result


def build_report():
    root = Path(__file__).resolve().parents[2]
    cfg = AP09Parameters(n=1, q=2, random_rows=2, m1=2, m2=8, hadamard_scale=4)
    attempts = [run_attempt(seed, postprocess=flag) for flag in (False, True) for seed in SEEDS]
    positive = [a for a in attempts if a["postprocess"]]
    negative = [a for a in attempts if not a["postprocess"]]
    names = ("chkp_basis", "chkp_genbasis", "chkp_randbasis", "chkp_tobasis", "chkp_gpv",
             "online_gaussian_reference", "chkp_basis_reduce", "chkp_t2_audit",
             "chkp_width_audit", "chkp_leaf_reference", "chkp_leaf_audit")
    paths = [f"experiments/research/{n}.py" for n in names] + ["papers/2010_bonsai_trees_cash.pdf"]
    passed = all(a["outcome"] == "leaf_preimage_path_completed" and
                 a["stages"][1]["observed_norms_within_reference"] for a in positive)
    return {
        "schema_version": 1, "created_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "fixed PUBLIC TOY sampling-path gate only, NOT HIBE correctness",
        "security_claim": "none", "backend_admitted": False, "T2_complete": False,
        "parameters_are_formal": False, "sampler_modified": False, "caps_relaxed": False,
        "seed_search_or_retry": False, "declared_seeds": list(SEEDS),
        "epsilon_bits_not_security_bits": EPSILON_BITS, "parameters": genbasis_certificate(cfg),
        "target_schedule": [[0], [1]], "targets_are_identity_hashes": False,
        "environment": {"sage": str(SAGE_VERSION), "python": platform.python_version(),
                        "platform": platform.platform(), "processor": platform.processor()},
        "attempts": attempts,
        "counts": {"without_postprocess_completed": sum(a["outcome"] == "leaf_preimage_path_completed" for a in negative),
                   "with_postprocess_completed": sum(a["outcome"] == "leaf_preimage_path_completed" for a in positive)},
        "declared_leaf_sampling_gate_passed": passed,
        "sha256": {p: hashlib.sha256((root/p).read_bytes()).hexdigest() for p in paths},
        "limitations": ["small public n=1,q=2 parameters; no security level",
                        "LLL and other initialization/resource failure budgets still open",
                        "conditional leaf TV is not the whole-chain failure probability",
                        "no H/G identity mapping, caching, serialization or byte capacity",
                        "no noisy encryption/decryption or multi-bit HIBE claim",
                        "timings include diagnostic algebra/certificates, not benchmarks",
                        "no secret basis or preimage is exported; public toy diagnostics only"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = build_report()
    encoded = json.dumps(report, indent=2, ensure_ascii=False)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    print(json.dumps({"counts": report["counts"], "T2_complete": False}), file=__import__("sys").stderr)
    return 0 if report["declared_leaf_sampling_gate_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
