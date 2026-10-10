"""Width-only scan FIRST; optional LLL postprocessing SECOND. Public toys only.

No sampler edits, no conditioning on successful seeds, no benchmark claims.
The interval is exact for scalar width/C1 only, not all GPV admission gates.
"""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import time

from sage.all import QQ, ZZ, matrix, vector
from sage.env import SAGE_VERSION

from ibme.core.randomness import DeterministicRandom
from .chkp_basis import ModMatrixReference, ext_basis, gram_schmidt_squared_lengths
from .chkp_basis_reduce import GAMMA, DELTA, reduce_basis
from .chkp_genbasis import AP09Parameters, gen_basis, genbasis_certificate
from .chkp_gpv import CHKPGPVSampler
from .chkp_randbasis import CHKPRandBasis
from .chkp_t2_audit import SEEDS, EPSILON_BITS, _required_width, _algebra
from .gaussian_reference import SamplingAbort, draw_uniform_integer
from .online_gaussian_reference import exact_integer, exact_rational


MULTIPLIERS = (1, 2, 4, 8)  # squared width, not standard deviation


def width_interval(basis, public_gs_upper=None):
    g = gram_schmidt_squared_lengths(basis.basis_rows)
    d = basis.public.ncols
    lo, hi = max(g), 10**12*min(g)
    c1 = _required_width(d, lo)
    if public_gs_upper is not None:
        public_gs_upper = exact_rational(public_gs_upper, "public_gs_upper", max_bits=1024)
        if public_gs_upper < lo:
            raise ValueError("public GS bound underestimates the actual basis")
    public_lo = None if public_gs_upper is None else _required_width(d, max(public_gs_upper, 1))
    return {"scalar_only_lower": str(lo), "upper": str(hi),
            "C1_exec_lower": str(c1),
            "public_C1_lower": None if public_lo is None else str(public_lo),
            "scalar_only_nonempty": bool(lo <= hi),
            "C1_exec_nonempty": bool(c1 <= hi),
            "public_C1_nonempty": None if public_lo is None else bool(public_lo <= hi)}


def _sampler_summary(sampler):
    cert = sampler.certificate()
    return {key: cert[key] for key in (
        "dimension", "width_squared", "epsilon_bits", "C1_exec_verified",
        "geometry_tv_upper", "scalar_tv_upper_sum", "tv_upper_including_abort",
        "random_tape_bytes", "path_resources")}


def run_attempt(seed, multiplier=1, *, postprocess=False):
    multiplier = exact_integer(multiplier, "multiplier", minimum=1, maximum=8)
    if type(postprocess) is not bool:
        raise ValueError("postprocess must be bool")
    cfg = AP09Parameters(n=1, q=2, random_rows=2, m1=2, m2=8, hadamard_scale=4)
    rng = DeterministicRandom(seed.encode("ascii"))
    result = {"seed": seed, "s1_squared_multiplier": multiplier,
              "postprocess": postprocess, "stages": []}
    start = time.perf_counter()
    stage = "GenBasis"
    try:
        basis = gen_basis(cfg, rng=rng).basis
        gs_upper = QQ(cfg.gs_squared_bound)
        for level in (1, 2):
            stage = f"level_{level}_ExtBasis"
            block = ModMatrixReference([[draw_uniform_integer(rng, cfg.q)
                                         for _ in range(cfg.m1+cfg.m2)]], cfg.q)
            expanded = ext_basis(basis, block)
            width = _required_width(expanded.public.ncols, max(gs_upper, 1))
            if level == 1:
                width *= multiplier
            entry = {"level": level, "input_algebra": _algebra(expanded),
                     "width_squared": str(width),
                     "width_interval": width_interval(expanded, gs_upper)}
            result["stages"].append(entry)
            stage = f"level_{level}_SampleD_admission"
            sampler = CHKPGPVSampler(expanded, width, epsilon_bits=EPSILON_BITS)
            entry["SampleD"] = _sampler_summary(sampler)
            stage = f"level_{level}_SampleD_execution"
            equations = []
            for y in range(cfg.q):
                sample = vector(ZZ, sampler.sample((y,), rng=rng))
                equations.append(int((matrix(ZZ, expanded.public.rows)*sample)[0]) % cfg.q == y)
            if not all(equations):
                raise ArithmeticError("syndrome relation failed")
            entry["all_syndromes_exact"] = equations
            stage = f"level_{level}_RandBasis"
            entry["RandBasis_required_tape_bytes"] = (expanded.public.ncols+20)*sampler.random_tape_bytes
            entry["RandBasis_tape_cap_bytes"] = 256*1024*1024
            rb = CHKPRandBasis(sampler, max_vectors=expanded.public.ncols+20)
            entry["RandBasis_certificate"] = rb.certificate()
            drawn = rb.sample(rng=rng)
            basis = drawn.basis
            entry["raw_vectors_consumed"] = drawn.draws_used
            entry["before_postprocess"] = _algebra(basis)
            if postprocess:
                stage = f"level_{level}_LLL"
                reduced = reduce_basis(basis)
                basis = reduced.basis
                entry["LLL"] = {"steps": reduced.steps, "swaps": reduced.swaps,
                                 "after": _algebra(basis)}
            gs_upper = width*expanded.public.ncols
        result["outcome"] = "two_randomized_delegations_completed"
    except SamplingAbort as exc:
        result.update(outcome="explicit_abort", stopped_at=stage, reason=str(exc))
    except ValueError as exc:
        result.update(outcome="admission_rejected", stopped_at=stage, reason=str(exc))
    result["elapsed_seconds_diagnostic_only"] = round(time.perf_counter()-start, 6)
    return result


def build_report():
    root = Path(__file__).resolve().parents[2]
    cfg = AP09Parameters(n=1, q=2, random_rows=2, m1=2, m2=8, hadamard_scale=4)
    attempts = [run_attempt(seed, m) for m in MULTIPLIERS for seed in SEEDS]
    attempts += [run_attempt(seed, postprocess=True) for seed in SEEDS]
    names = ("chkp_basis", "chkp_genbasis", "chkp_randbasis", "chkp_tobasis",
             "chkp_gpv", "online_gaussian_reference", "chkp_basis_reduce",
             "chkp_width_audit", "chkp_t2_audit")
    paths = [f"experiments/research/{name}.py" for name in names]
    return {
        "schema_version": 1, "scope": "public toy width/basis compatibility, NOT HIBE",
        "security_claim": "none", "backend_admitted": False, "T2_complete": False,
        "sampler_modified": False, "seed_search_or_retry": False,
        "parameters": genbasis_certificate(cfg), "epsilon_bits_not_security_bits": EPSILON_BITS,
        "declared_seeds": list(SEEDS), "declared_squared_width_multipliers": list(MULTIPLIERS),
        "smaller_public_widths": {"squared_multipliers": ["1/4", "1/2"],
            "status": "not executed: outside frozen public C1-exec schedule",
            "not_claimed": "instance-specific C1 rejection for every root"},
        "postprocess_width_certificate": {
            "delta": str(DELTA), "gamma": str(GAMMA), "dimension_before_extension": 20,
            "gs_squared_lower": str(GAMMA**19), "gs_squared_upper": "181280",
            "s2_squared_lower": "15952640", "s2_squared_upper": str(10**12*GAMMA**19),
            "maximum_scalar_squared_width_upper": str(QQ(15952640)/GAMMA**19),
            "width_gate_uniform_on_success": bool(QQ(15952640)/GAMMA**19 <= 10**12),
            "all_other_resources_uniformly_admitted": False},
        "attempts": attempts,
        "counts": {"width_only_completed": sum(a["outcome"] == "two_randomized_delegations_completed"
                       for a in attempts if not a["postprocess"]),
                   "postprocessed_completed": sum(a["outcome"] == "two_randomized_delegations_completed"
                       for a in attempts if a["postprocess"]),
                   "postprocessed_level2_sampleD_completed": sum(
                       len(a["stages"]) == 2 and a["stages"][1].get("all_syndromes_exact") == [True, True]
                       for a in attempts if a["postprocess"])},
        "environment": {"sage": str(SAGE_VERSION), "python": platform.python_version(),
                        "platform": platform.platform(), "processor": platform.processor()},
        "sha256": {p: hashlib.sha256((root/p).read_bytes()).hexdigest() for p in paths},
        "limitations": ["finite scan is not impossibility for all first-level widths",
                        "LLL/resource ABORT probability not uniformly bounded",
                        "no new Gaussian statistics experiment", "no HIBE noise/decryption",
                        "no formal security parameters/attack estimate", "not constant time",
                        "timings include algebra/certificates and are not benchmarks"],
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
    print(json.dumps(report["counts"]), file=__import__("sys").stderr)
    # Overall T2 is still WIP, even when this engineering gate is resolved.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
