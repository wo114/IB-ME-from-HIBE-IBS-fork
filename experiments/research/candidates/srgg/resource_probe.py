"""Bounded measurements of actual SampleF/SampleP on public SPD fixtures.

This is a test-only engineering probe, not an IBS benchmark or a distribution
certificate. Existing sampler limits and sampling semantics are unchanged.
Every grid case runs in a fresh process with a finite timeout; the deterministic
seed is public and must never be used for production cryptographic material.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from time import perf_counter


SCHEMA = "IBME/SRGG-SAMPLER-RESOURCE-PROBE/1"
MODULE = "experiments.research.candidates.srgg.resource_probe"


@dataclass(frozen=True)
class Case:
    name: str
    algorithm: str
    fixture: str
    dimension: int
    leaf_degree: int
    width_squared: int = 4
    rational_bits: int = 8192

    def __post_init__(self):
        if not isinstance(self.name, str) or not 1 <= len(self.name) <= 128:
            raise ValueError("bounded public case name required")
        if self.algorithm not in ("f", "p") or self.fixture not in ("diagonal", "rank-one"):
            raise ValueError("explicit fixture and sampler required")
        if type(self.dimension) is not int or not 1 <= self.dimension <= 129:
            raise ValueError("probe dimension limited to 129 including rejection boundary")
        if type(self.leaf_degree) is not int or not 1 <= self.leaf_degree <= 129:
            raise ValueError("bounded positive leaf degree required")
        if self.dimension % self.leaf_degree:
            raise ValueError("leaf degree must partition probe dimension")
        if self.algorithm == "f" and self.leaf_degree != self.dimension:
            raise ValueError("SampleF leaf is the whole probe dimension")
        if type(self.width_squared) is not int or not 1 <= self.width_squared <= 10**12+1:
            raise ValueError("bounded public rounding width required")
        if type(self.rational_bits) is not int or not 128 <= self.rational_bits <= 8192:
            raise ValueError("rational bit option is limited to the current sampler profile")


def default_grid() -> list[Case]:
    cases = []
    for degree in (2, 4, 8, 16, 32, 64, 128):
        cases.append(Case(f"f-diagonal-{degree}", "f", "diagonal", degree, degree))
    for degree in (2, 8, 32, 64, 128):
        cases.append(Case(f"f-rank-one-{degree}", "f", "rank-one", degree, degree))
    for degree in (2, 4, 8, 16, 32, 64, 128):
        dimension = min(2*degree, 128)
        cases.append(Case(f"p-diagonal-{dimension}-leaf{degree}", "p", "diagonal", dimension, degree))
    for degree, dimension in ((2, 8), (8, 32), (16, 64), (32, 128), (64, 128), (128, 128)):
        cases.append(Case(f"p-rank-one-{dimension}-leaf{degree}", "p", "rank-one", dimension, degree))
    cases.extend((
        Case("f-dimension129-rejection", "f", "diagonal", 129, 129),
        Case("f-width-over-profile", "f", "diagonal", 2, 2, width_squared=10**12+1),
        Case("f-low-rational-reserve", "f", "rank-one", 8, 8, rational_bits=2048),
    ))
    return cases


def _rss() -> dict:
    try:
        import resource

        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except (ImportError, AttributeError):
        return {"ru_maxrss_raw": None, "ru_maxrss_units": "unavailable", "ru_maxrss_kib": None}
    system = platform.system()
    return {
        "ru_maxrss_raw": value,
        "ru_maxrss_units": "KiB" if system == "Linux" else "platform-dependent",
        "ru_maxrss_kib": value if system == "Linux" else None,
    }


def _fixture(case: Case):
    # Residual shape is 60 I plus optional vv^T even for the width-gate probe.
    # Normal grid cases use r^2=4, hence the familiar 64 I + optional vv^T.
    vector = tuple(1 if i % 2 == 0 else -1 for i in range(case.dimension))
    shape = tuple(tuple((case.width_squared+60)*int(i == j)+(vector[i]*vector[j] if case.fixture == "rank-one" else 0)
                        for j in range(case.dimension)) for i in range(case.dimension))
    return shape


def run_case(case: Case, *, repetitions=2, progress=None) -> dict:
    """Exercise real preparation and draws; no secret inputs or output vectors."""

    if not isinstance(case, Case):
        raise TypeError("explicit public probe Case required")
    if type(repetitions) is not int or not 1 <= repetitions <= 8:
        raise ValueError("probe repetitions must be in [1,8]")
    start = perf_counter()

    def emit(phase):
        if progress is not None:
            progress({"event": "phase", "phase": phase, "elapsed_seconds": perf_counter()-start})

    emit("import")
    from fractions import Fraction
    from sage.version import version as sage_version
    from ibme.core.randomness import DeterministicRandom
    from .full_sampling import FullSamplingOptions, prepare_f, prepare_p

    imported = perf_counter()
    after_import = _rss()
    options = FullSamplingOptions(rational_bits=case.rational_bits)
    seed = b"SRGG-PUBLIC-RESOURCE-PROBE-TEST-ONLY-v1:"+case.name.encode("utf-8")

    class CountingRandom:
        def __init__(self):
            self.source = DeterministicRandom(seed)
            self.bytes = 0
            self.calls = 0

        def read(self, size):
            value = self.source.read(size)
            self.bytes += len(value)
            self.calls += 1
            return value

    source = CountingRandom()
    fixture_started = perf_counter()
    shape = _fixture(case)
    center = tuple(Fraction(1, 3) if i % 3 == 0 else Fraction(0) for i in range(case.dimension))
    fixture_seconds = perf_counter()-fixture_started
    result = {
        "case": asdict(case),
        "options": asdict(options),
        "sage_version": sage_version,
        "fixture_spd_argument": "(rounding_width_squared+60) I plus optional vv^T; residual at least 60 I",
        "test_randomness": {"deterministic_test_only": True, "seed_hex": seed.hex()},
        "import_seconds": imported-start,
        "fixture_construction_seconds": fixture_seconds,
        "rss_after_import": after_import,
        "prepare_seconds": None,
        "draws": [],
        "public_certificate": None,
        "injected_entropy_bytes_before_draw": source.bytes,
    }
    emit("prepare")
    prepare_started = perf_counter()
    try:
        if case.algorithm == "f":
            plan = prepare_f(shape, center, case.width_squared, options=options)
        else:
            plan = prepare_p(shape, center, case.leaf_degree, case.width_squared, options=options)
    except Exception as exc:
        result.update(status="preflight_rejected" if isinstance(exc, ValueError) else "prepare_error",
                      prepare_seconds=perf_counter()-prepare_started,
                      rejection_type=type(exc).__name__, rejection_reason=str(exc))
        result["injected_entropy_bytes_before_draw"] = source.bytes
        result["rss_after_prepare"] = _rss()
        result["rss_final"] = _rss()
        result["worker_elapsed_seconds"] = perf_counter()-start
        return result
    result["prepare_seconds"] = perf_counter()-prepare_started
    result["public_certificate"] = plan.public_certificate()
    result["injected_entropy_bytes_before_draw"] = source.bytes
    result["rss_after_prepare"] = _rss()
    emit("draw")
    from experiments.research.gaussian_reference import SamplingAbort

    for index in range(repetitions):
        before_bytes, before_calls = source.bytes, source.calls
        draw_started = perf_counter()
        try:
            output = plan.sample(rng=source)
            record = {
                "index": index, "status": "success", "output_dimension": len(output),
                "output_norm_squared": sum(int(value)**2 for value in output),
                "output_sha256": hashlib.sha256(json.dumps(tuple(map(int, output))).encode()).hexdigest(),
            }
        except Exception as exc:
            record = {"index": index, "status": "sampler_abort" if isinstance(exc, SamplingAbort) else "draw_error",
                      "error_type": type(exc).__name__, "error_reason": str(exc)}
        record.update(elapsed_seconds=perf_counter()-draw_started,
                      entropy_bytes=source.bytes-before_bytes, entropy_read_calls=source.calls-before_calls)
        result["draws"].append(record)
        if record["status"] == "draw_error":
            break
    result["status"] = "success" if all(draw["status"] == "success" for draw in result["draws"]) else "draw_incomplete"
    result["rss_final"] = _rss()
    result["worker_elapsed_seconds"] = perf_counter()-start
    return result


def _progress_records(stdout) -> list[dict]:
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", errors="replace")
    records = []
    for line in (stdout or "").splitlines():
        try:
            record = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def run_isolated_case(case: Case, *, repetitions=2, timeout_seconds=20) -> dict:
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 60:
        raise ValueError("case timeout must be in [1,60] seconds")
    payload = json.dumps({"case": asdict(case), "repetitions": repetitions})
    start = perf_counter()
    try:
        child = subprocess.run([sys.executable, "-m", MODULE, "--worker-json", payload],
                               capture_output=True, text=True, timeout=timeout_seconds, check=False)
    except subprocess.TimeoutExpired as exc:
        progress = _progress_records(exc.stdout)
        return {
            "case": asdict(case), "status": "timeout", "timeout_seconds": timeout_seconds,
            "last_phase": progress[-1].get("phase") if progress else "startup",
            "worker_progress": progress, "process_wall_seconds": perf_counter()-start,
            "timing_is_censored": True,
        }
    records = _progress_records(child.stdout)
    finals = [record["result"] for record in records if record.get("event") == "result"]
    result = finals[-1] if finals else {
        "case": asdict(case), "status": "worker_error", "returncode": child.returncode,
        "stderr": child.stderr[-4096:], "worker_progress": records,
    }
    result["process_wall_seconds"] = perf_counter()-start
    result["timeout_seconds"] = timeout_seconds
    result["timing_is_censored"] = False
    return result


def _environment() -> dict:
    cpu = platform.processor()
    if platform.system() == "Linux":
        try:
            cpu = next(line.partition(":")[2].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                       if line.startswith("model name"))
        except (OSError, StopIteration):
            pass
    root = Path(__file__).resolve().parents[4]
    sources = (Path(__file__), Path(__file__).with_name("full_sampling.py"),
               root/"experiments/research/online_gaussian_reference.py")
    return {
        "python": sys.version, "executable": sys.executable, "platform": platform.platform(),
        "processor": cpu, "logical_cpu_count": os.cpu_count(),
        "source_sha256": {str(path.relative_to(root)).replace("\\", "/"):
                          hashlib.sha256(path.read_bytes()).hexdigest() for path in sources},
        "measurement_clock": "time.perf_counter",
        "rss_method": "fresh worker resource.getrusage(RUSAGE_SELF).ru_maxrss; Linux KiB",
    }


def audit(*, repetitions=2, timeout_seconds=20, cases=None) -> dict:
    if type(repetitions) is not int or not 1 <= repetitions <= 8:
        raise ValueError("probe repetitions must be in [1,8]")
    selected = default_grid() if cases is None else list(cases)
    if not selected or len(selected) > 64 or any(not isinstance(case, Case) for case in selected):
        raise ValueError("finite nonempty public case grid required")
    results = []
    for case in selected:
        result = run_isolated_case(case, repetitions=repetitions, timeout_seconds=timeout_seconds)
        results.append(result)
        print(f"{case.name}: {result['status']}", file=sys.stderr, flush=True)
    return {
        "schema": SCHEMA, "created_utc": datetime.now(timezone.utc).isoformat(),
        "environment": _environment(), "repetitions_per_prepared_case": repetitions,
        "timeout_seconds_per_case_including_import": timeout_seconds, "cases": results,
        "scope": "public SPD fixture sampler engineering measurements; no IBS/HIBE key or signature execution",
        "status_counts": {status: sum(result["status"] == status for result in results)
                          for status in sorted({result["status"] for result in results})},
        "limitations": [
            "Timing and RSS are single-run fixture observations, not a representative IBS benchmark.",
            "ru_maxrss includes interpreter/Sage import and is a high-water mark, not a matrix-only allocation.",
            "The deterministic seed is test-only and no production cryptographic material is generated.",
            "Existing scalar width, rational reserve and dense admission gates are unchanged.",
            "No full-TV, sampler-distribution, hardness or formal-security certificate follows.",
        ],
        "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--repetitions", type=int, default=2)
    parser.add_argument("--timeout-seconds", type=int, default=20)
    parser.add_argument("--worker-json", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker_json is not None:
        payload = json.loads(args.worker_json)
        result = run_case(Case(**payload["case"]), repetitions=payload["repetitions"],
                          progress=lambda record: print(json.dumps(record), flush=True))
        print(json.dumps({"event": "result", "result": result}), flush=True)
        return
    result = audit(repetitions=args.repetitions, timeout_seconds=args.timeout_seconds)
    encoded = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2)+"\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8", newline="\n")
    print(encoded, end="")


if __name__ == "__main__":
    main()
