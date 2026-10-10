"""Public-seed T2 chain audit, not a HIBE benchmark or security experiment.

Every predeclared attempt is reported, including ABORT and resource rejection.
No searching for successful seeds, retrying setup, or exporting real keys.
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
from .chkp_genbasis import AP09Parameters, gen_basis, genbasis_certificate
from .chkp_gpv import CHKPGPVSampler
from .chkp_randbasis import CHKPRandBasis
from .gaussian_reference import SamplingAbort, draw_uniform_integer


SEEDS = tuple(f"chkp-t2-chain-{i}" for i in range(4))
EPSILON_BITS = 16


def _required_width(dimension, gs_squared_upper):
    k = (2*dimension*(1+2**EPSILON_BITS)-1).bit_length()
    return 4*gs_squared_upper*k


def _algebra(basis):
    a, b = matrix(ZZ, basis.public.rows), matrix(ZZ, basis.basis_rows)
    norms = gram_schmidt_squared_lengths(b)
    return {
        "dimension": basis.public.ncols,
        "kernel_equation_exact": all(int(x) % basis.public.q == 0 for x in (a*b).list()),
        "absolute_determinant": str(abs(b.det())),
        "expected_index": str(basis.public.q**basis.public.nrows),
        "gs_squared_min": str(min(norms)), "gs_squared_max": str(max(norms)),
    }


def run_attempt(seed):
    cfg = AP09Parameters(n=1, q=2, random_rows=2, m1=2, m2=8, hadamard_scale=4)
    rng = DeterministicRandom(seed.encode("ascii"))
    result = {"seed": seed, "stages": [], "outcome": "not_started"}
    started = time.perf_counter()
    stage = "GenBasis"
    try:
        basis = gen_basis(cfg, rng=rng).basis
        result["stages"].append({"operation": stage, **_algebra(basis)})
        gs_upper = QQ(cfg.gs_squared_bound)
        block_width = cfg.m1+cfg.m2
        for level in (1, 2):
            stage = f"level_{level}_ExtBasis"
            block = ModMatrixReference([[draw_uniform_integer(rng, cfg.q)
                                         for _ in range(block_width)]], cfg.q)
            expanded = ext_basis(basis, block)
            dimension = expanded.public.ncols
            width_squared = _required_width(dimension, max(gs_upper, 1))
            entry = {"operation": stage, **_algebra(expanded),
                     "public_input_gs_squared_bound": str(gs_upper),
                     "public_width_squared": str(width_squared)}
            entry["maximum_required_scalar_squared_width"] = str(
                width_squared/QQ(entry["gs_squared_min"]))
            entry["scalar_squared_width_resource_cap"] = 10**12
            result["stages"].append(entry)
            stage = f"level_{level}_SampleD_admission"
            sampler = CHKPGPVSampler(expanded, width_squared, epsilon_bits=EPSILON_BITS)
            entry["sampleD_certificate"] = sampler.certificate()
            stage = f"level_{level}_SampleD_execution"
            equations = []
            for y in range(cfg.q):
                x = vector(ZZ, sampler.sample((y,), rng=rng))
                equations.append(int((matrix(ZZ, expanded.public.rows)*x)[0]) % cfg.q == y)
            if not all(equations):
                raise ArithmeticError("SampleD output equation failed")
            entry["all_syndromes_equations_exact"] = equations
            stage = f"level_{level}_RandBasis"
            randomizer = CHKPRandBasis(sampler, max_vectors=dimension+20)
            entry["randbasis_certificate"] = randomizer.certificate()
            randomized = randomizer.sample(rng=rng)
            basis = randomized.basis
            entry["randomized_basis"] = _algebra(basis)
            entry["raw_vectors_consumed"] = randomized.draws_used
            gs_upper = width_squared*dimension
        result["outcome"] = "two_randomized_delegations_completed"
    except SamplingAbort as exc:
        result.update(outcome="explicit_abort", stopped_at=stage, reason=str(exc))
    except ValueError as exc:
        # Invalid configurations are not successful runs and not samples from
        # the admitted probabilistic process. Keep this distinct from ABORT.
        result.update(outcome="admission_rejected", stopped_at=stage, reason=str(exc))
    result["elapsed_seconds_diagnostic_only"] = round(time.perf_counter()-started, 6)
    return result


def build_report():
    root = Path(__file__).resolve().parents[2]
    files = ["experiments/research/"+name for name in (
        "chkp_basis.py", "chkp_genbasis.py", "chkp_gpv.py", "chkp_randbasis.py",
        "chkp_tobasis.py", "chkp_t2_audit.py", "online_gaussian_reference.py")]
    files += ["papers/"+name for name in (
        "2009_generating_shorter_bases_alwen_peikert_full.pdf",
        "2008_gpv_trapdoors_full.pdf", "2010_bonsai_trees_cash.pdf",
        "2011_peikert_parallel_gaussian_author.pdf")]
    cfg = AP09Parameters(n=1, q=2, random_rows=2, m1=2, m2=8, hadamard_scale=4)
    attempts = [run_attempt(seed) for seed in SEEDS]
    return {
        "scope": "public toy AP09 -> ExtBasis -> SampleD -> RandBasis chain attempts",
        "schema_version": 1, "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "epsilon_bits_not_security_bits": EPSILON_BITS,
        "environment": {"python": platform.python_version(), "sage": str(SAGE_VERSION),
                        "platform": platform.platform()},
        "genbasis_certificate": genbasis_certificate(cfg),
        "declared_seeds": list(SEEDS), "seed_search_or_retry": False,
        "attempts": attempts,
        "two_randomized_delegations_completed": sum(
            x["outcome"] == "two_randomized_delegations_completed" for x in attempts),
        "all_attempts_completed": all(x["outcome"] == "two_randomized_delegations_completed" for x in attempts),
        "sha256": {name: hashlib.sha256((root/name).read_bytes()).hexdigest() for name in files},
        "not_proven": ["formal parameters or security level", "HIBE decryption/noise",
                       "ROM security reduction", "real SHAKE equals ideal random bytes",
                       "constant time or production key handling"],
        "timing_scope": "single-run diagnostics with certificate/algebra overhead; NOT a benchmark",
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
    # 2 = audit completed, chain NOT admitted. Never turn a blocked run into 0.
    return 0 if report["all_attempts_completed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
