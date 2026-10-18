"""Public master/signature perturbation fixtures; never a complete SRGG IBS."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import resource
import sys
from time import perf_counter

from sage.version import version as sage_version

from ibme.core.randomness import DeterministicRandom
from experiments.research.candidates.srgg.formal_candidates import conditional_candidate
from experiments.research.candidates.srgg.structured_geometry import signature_operator
from experiments.research.candidates.srgg.structured_samplef import StructuredSampleF, audit
# Load the CBD1 public-bound dependency before the source snapshot.
from experiments.research.candidates.srgg import spectral_bounds  # noqa: F401


def _source_hashes():
    root = Path(__file__).resolve().parents[2]
    paths = {Path(__file__).resolve()}
    for name, module in tuple(sys.modules.items()):
        if name.startswith(("ibme.", "experiments.research.")):
            filename = getattr(module, "__file__", None)
            if filename and filename.endswith(".py"):
                paths.add(Path(filename).resolve())
    return {str(path.relative_to(root)).replace("\\", "/"):
            hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(paths) if path.is_relative_to(root)}


def execute(*, mode, degree, rank, digits):
    before = _source_hashes()
    started = perf_counter()
    if mode == "master":
        result = audit(degree=degree, rank=rank, digits=digits, draws=1)
    elif mode == "signature":
        candidate = conditional_candidate(degree=degree, rank=rank, digits=digits)
        # Public non-key fixture: this vector is not an Extract result and no
        # claim is made about the key-law or this input's representativeness.
        user = tuple(tuple((11*i+7*j) % 3-1 for j in range(degree))
                     for i in range(candidate.columns))
        fixture_norm = sum(x*x for poly in user for x in poly)
        if fixture_norm > candidate.user_norm_squared_cap:
            raise ValueError("public signature fixture exceeds the candidate input cap")
        prepared = perf_counter()
        geometry = signature_operator(degree=degree, rank=rank, digits=digits,
            user_vector=user, first_squared=candidate.signature_first_squared,
            second_squared=candidate.signature_second_squared,
            r_squared=candidate.r_squared, noise_factor=2)
        plan = StructuredSampleF(geometry, bound_kind="public-norm-cap",
            witness_norm_squared_cap=candidate.user_norm_squared_cap)
        prepare_seconds = perf_counter()-prepared
        draw_started = perf_counter()
        output = plan.sample(rng=DeterministicRandom(b"SRGG-public-signature-SampleF-fixture-v1"))
        result = {
            "schema": "IBME/SRGG-STRUCTURED-SAMPLEF-SIGNATURE-FIXTURE/1",
            "fixture": "public coefficients ((11*i+7*j)%3)-1; not a sampled user key",
            "fixture_norm_squared": fixture_norm,
            "declared_public_user_norm_squared_cap": str(candidate.user_norm_squared_cap),
            "prepare_seconds": prepare_seconds,
            "certificate": plan.public_certificate(),
            "draws": [{"index": 0, "seconds": perf_counter()-draw_started,
                "coefficients": len(output),
                "output_digest": hashlib.sha256(json.dumps(output).encode()).hexdigest(),
                "squared_norm": str(sum(x*x for x in output))}],
            "production_randomness": False, "full_ibs_executed": False,
            "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False,
        }
    else:
        raise ValueError("master or signature fixture mode required")
    after = _source_hashes()
    # New lazy imports are included in the final snapshot; loaded source files
    # already in the first snapshot must remain byte-identical throughout.
    if any(after.get(path) != digest for path, digest in before.items()):
        raise RuntimeError("loaded research source changed during the run")
    cpu = next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                if line.startswith("model name")), platform.processor())
    return {"mode": mode, "degree": degree, "rank": rank, "digits": digits,
        "environment": {"platform": platform.platform(), "python": platform.python_version(),
            "sage": sage_version, "cpu_model": cpu},
        "source_sha256": after, "loaded_sources_unchanged_during_run": True,
        "total_execution_seconds": perf_counter()-started,
        "process_peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "identity_bytes": None, "message_bytes": None, "repetitions": 1,
        "random_oracle_experiment": False,
        "scope": "one public perturbation fixture only; no Extract/Sign/Verify lifecycle",
        "result": result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("master", "signature"), required=True)
    parser.add_argument("--degree", type=int, default=8)
    parser.add_argument("--rank", type=int, default=1)
    parser.add_argument("--digits", type=int, default=3)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = execute(mode=args.mode, degree=args.degree, rank=args.rank, digits=args.digits)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2)+"\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
