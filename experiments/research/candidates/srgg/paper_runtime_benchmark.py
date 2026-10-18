"""Bounded serial Python/Sage timings for original SRGG Table 4 rows.

This measures the independent research implementation, not the authors'
C/rANS implementation or its 1000-run median. No secret object is exported.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import resource
from statistics import median
from time import perf_counter, process_time

from sage.version import version as sage_version

from ibme.core.randomness import SecureRandom
from .paper_parameters import PaperParams
from .paper_schur_backend import SourceSchurBackend


ROOT = Path(__file__).resolve().parents[4]
SCHEMA = "IBME/SRGG-PAPER-SERIAL-RUNTIME/1"
IDENTITY = b"Alice"
MESSAGE = b"SRGG paper baseline: 32 bytes!!!"


def _measure(action):
    wall_start, cpu_start = perf_counter(), process_time()
    value = action()
    return value, perf_counter() - wall_start, process_time() - cpu_start


def _summary(samples):
    return {"count": len(samples), "median_seconds": median(samples),
            "min_seconds": min(samples), "max_seconds": max(samples)}


def benchmark(profile_name="PARAM-I", *, interpretation="table-standard-deviation",
              cycles=3, verify_calls=1000):
    if type(cycles) is not int or not 1 <= cycles <= 1000:
        raise ValueError("cycles must be an integer in [1, 1000]")
    if type(verify_calls) is not int or not 1 <= verify_calls <= 100000:
        raise ValueError("verify_calls must be an integer in [1, 100000]")
    params = PaperParams(profile_name, interpretation)
    source_path = ROOT / params.source.source_pdf
    if sha256(source_path.read_bytes()).hexdigest() != params.source.source_sha256:
        raise ValueError("frozen paper checksum mismatch")
    if len(MESSAGE) != 32:
        raise AssertionError("message length drift")

    samples = {name: {"wall": [], "cpu": []}
               for name in ("setup", "extract", "sign", "verify_once", "verify_fixed")}
    counts = {"setup_attempts": [], "sign_attempts": [], "extract_calls": []}
    sizes = None
    last = None
    for _ in range(cycles):
        backend = SourceSchurBackend(rng=SecureRandom())
        (public, master), wall, cpu = _measure(lambda: backend.setup(params))
        samples["setup"]["wall"].append(wall)
        samples["setup"]["cpu"].append(cpu)
        key, wall, cpu = _measure(lambda: backend.key_extract(master, IDENTITY))
        samples["extract"]["wall"].append(wall)
        samples["extract"]["cpu"].append(cpu)
        signature, wall, cpu = _measure(lambda: backend.sign(key, MESSAGE))
        samples["sign"]["wall"].append(wall)
        samples["sign"]["cpu"].append(cpu)
        verified, wall, cpu = _measure(
            lambda: backend.verify(public, IDENTITY, MESSAGE, signature))
        if not verified:
            raise AssertionError("honest signature failed verification")
        samples["verify_once"]["wall"].append(wall)
        samples["verify_once"]["cpu"].append(cpu)
        counts["setup_attempts"].append(backend.setup_attempts)
        counts["sign_attempts"].append(backend.sign_attempts)
        counts["extract_calls"].append(backend.extract_calls)
        if sizes is None:
            sizes = {"public": len(public.to_bytes()),
                     "master": len(master.to_bytes()),
                     "user_key": len(key.to_bytes()),
                     "signature": len(signature.to_bytes())}
        last = backend, public, signature

    backend, public, signature = last
    for _ in range(verify_calls):
        verified, wall, cpu = _measure(
            lambda: backend.verify(public, IDENTITY, MESSAGE, signature))
        if not verified:
            raise AssertionError("repeated honest verification failed")
        samples["verify_fixed"]["wall"].append(wall)
        samples["verify_fixed"]["cpu"].append(cpu)

    return {
        "schema": SCHEMA, "status": "functional-pass",
        "completed_utc": datetime.now(timezone.utc).isoformat(),
        "profile": params.record(), "original_table4": params.source.record(),
        "backend": "SourceSchurBackend", "implementation": "Python/Sage",
        "environment": {"python": platform.python_version(), "sage": sage_version,
                        "platform": platform.platform(), "machine": platform.machine(),
                        "cpu_affinity_count": len(os.sched_getaffinity(0))
                        if hasattr(os, "sched_getaffinity") else None,
                        "peak_process_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss},
        "workload": {"cycles": cycles, "verify_fixed_calls": verify_calls,
                     "verify_fixed_reuses_final_signature": True,
                     "identity_bytes": len(IDENTITY), "message_bytes": len(MESSAGE),
                     "serial_single_process": True, "host_cpu_isolated": False,
                     "production_random": True,
                     "rom_used": True},
        "timings": {name: {clock: _summary(values) for clock, values in data.items()}
                    for name, data in samples.items()},
        "attempts": counts, "uncompressed_object_sizes_bytes": sizes,
        "author_C_rANS_implementation_reproduced": False,
        "author_1000_run_median_reproduced": False,
        "timing_comparable_to_author_table6": False,
        "rANS_size_comparable_to_author_table7": False,
        "measurement_limits": (
            "Serial Python/Sage wall and process CPU timings. The 1000 fixed "
            "verifications reuse one honest signature; setup/extract/sign "
            "cycle count is separately stated. Peak RSS includes the whole "
            "process and cannot be attributed to one operation. Other host "
            "processes were not excluded. No C/rANS code or author hardware "
            "calibration was available."),
        "private_material_exported": False,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("PARAM-I", "PARAM-II", "PARAM-III"), required=True)
    parser.add_argument("--interpretation", choices=("table-standard-deviation", "literal-density-width"),
                        default="table-standard-deviation")
    parser.add_argument("--cycles", type=int, default=3)
    parser.add_argument("--verify-calls", type=int, default=1000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("--output already exists")
    try:
        report = benchmark(args.profile, interpretation=args.interpretation,
                           cycles=args.cycles, verify_calls=args.verify_calls)
    except Exception as error:
        report = {"schema": SCHEMA, "status": "execution-failed",
                  "profile_name": args.profile, "interpretation": args.interpretation,
                  "error_type": type(error).__name__,
                  "error": "bounded runtime measurement failed; private exception details omitted",
                  "private_material_exported": False, "security_claim": "none"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8", newline="\n")
    print(json.dumps({"status": report["status"], "output": str(args.output)}))
    if report["status"] != "functional-pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
