"""Serial SecureRandom Table 4 runs with paired codecs and cold restoration.

Private objects stay under ignored build/outputs. Public output contains only
allowlisted worker metrics, source hashes and /proc RSS samples, never objects
or their hashes. Failures remain in the fixed schedule without replacement.
"""
import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import shutil
from statistics import median
import sys

from .benchmark_process import supervise
from experiments.research.runtime_metrics import environment

ROOT = Path(__file__).resolve().parents[4]


def source_hashes():
    paths = list((ROOT/"experiments/research/candidates/srgg").glob("*.py"))
    paths += [ROOT/p for p in (
        "experiments/research/runtime_metrics.py", "src/ibme/core/randomness.py",
        "src/ibme/core/hashing.py", "src/ibme/ibs/srgg_paper_service.py",
        "src/ibme/ibs/srgg_service.py", "src/ibme/lattice/chkp/gaussian.py",
        "experiments/research/online_gaussian_reference.py",
        "experiments/research/gaussian_reference.py", "papers/2025_efficient_ibs_jia.pdf")]
    return {p.relative_to(ROOT).as_posix(): sha256(p.read_bytes()).hexdigest() for p in sorted(set(paths))}


def describe(values):
    return {"count": len(values), "min": min(values), "median": median(values), "max": max(values)} if values else None


def summarize(rows):
    result = {}
    for profile in ("PARAM-I", "PARAM-II", "PARAM-III"):
        modes = {}
        for mode in ("generate", "restore-json", "restore-compact"):
            selected = [x for x in rows if x["profile_name"] == profile and x["mode"] == mode]
            passed = [x for x in selected if x["status"] == "passed"]
            groups = {}
            for row in passed:
                by_phase = {}
                for phase in row["phases"]:
                    name = re.sub(r"-\d+$", "", phase["name"])
                    by_phase.setdefault(name, []).append(phase["seconds"])
                for name, values in by_phase.items():
                    groups.setdefault(name, []).append(median(values))
            modes[mode] = {"scheduled": len(selected), "passed": len(passed),
                "process_wall_seconds": describe([x["process_wall_seconds"] for x in passed]),
                "sampled_tree_peak_rss_bytes": describe([x["sampled_tree_peak_rss_bytes"] for x in passed
                                                        if x["sampled_tree_peak_rss_bytes"] is not None]),
                "kernel_lifetime_peak_rss_bytes": describe([x["kernel_lifetime_peak_rss_bytes"] for x in passed
                                                           if "kernel_lifetime_peak_rss_bytes" in x]),
                "phase_seconds_per_run_medians": {name: describe(values) for name, values in groups.items()}}
        generated = [x for x in rows if x["profile_name"] == profile and x["mode"] == "generate" and x["status"] == "passed"]
        sizes = {}
        for name in ("public", "master", "key", "signature"):
            pairs = [x["object_sizes_bytes"][name] for x in generated]
            sizes[name] = {kind: describe([x[kind] for x in pairs]) for kind in ("json", "compact")}
            sizes[name]["paired_json_over_compact_ratio"] = describe([x["json"]/x["compact"] for x in pairs])
        result[profile] = {"modes": modes, "object_sizes_bytes": sizes}
    return result


def run(private, output, *, repetitions=3, warm_repetitions=3, codec_repetitions=5, source_commit):
    private, output = Path(private).resolve(), Path(output).resolve()
    if (not private.is_relative_to(ROOT/"build/outputs") or private.exists() or output.exists()
            or (output.parent/"evidence").exists()):
        raise ValueError("new private directory under build/outputs and new public output required")
    if not 1 <= repetitions <= 8 or not 0 <= warm_repetitions <= 16 or not 1 <= codec_repetitions <= 32:
        raise ValueError("bounded benchmark repetition counts required")
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise ValueError("explicit 40-character base/source commit required")
    os.umask(0o077)
    private.mkdir(parents=True, mode=0o700)
    public = output.parent/"evidence"
    public.mkdir(parents=True, exist_ok=False)
    before, rows = source_hashes(), []
    for profile in ("PARAM-I", "PARAM-II", "PARAM-III"):
        for index in range(repetitions):
            name = f"{profile.lower()}-{index}"
            generation = private/name/"generate"
            generation.mkdir(parents=True)
            generation_passed = False
            for mode in ("generate", *( ("restore-json", "restore-compact") if index % 2 == 0 else
                                       ("restore-compact", "restore-json") )):
                directory = private/name/mode
                if mode != "generate":
                    if not generation_passed:
                        rows.append({"profile_name": profile, "run_index": index, "mode": mode,
                                     "status": "not-run-generation-failed", "phases": []})
                        continue
                    directory.mkdir()
                    variant = mode.removeprefix("restore-")
                    for obj in ("public", "master", "key", "signature"):
                        shutil.copyfile(generation/(obj+"."+variant), directory/(obj+"."+variant))
                print(f"{name}: {mode}", flush=True)
                command = [sys.executable, "-m", "experiments.research.candidates.srgg.compact_benchmark_worker",
                           "--private-directory", str(directory), "--profile", profile, "--mode", mode,
                           "--warm-repetitions", str(warm_repetitions), "--codec-repetitions", str(codec_repetitions)]
                row = supervise(command, directory)
                if mode == "generate":
                    generation_passed = row["status"] == "passed"
                row.update(profile_name=profile, run_index=index, mode=mode)
                sample_name = name+"-"+mode+"-rss.jsonl.gz"
                shutil.copyfile(directory/"rss-samples.jsonl.gz", public/sample_name)
                row["rss_samples"] = "evidence/"+sample_name
                rows.append(row)
                (public/(name+"-"+mode+".json")).write_text(json.dumps(row, indent=2, sort_keys=True)+"\n")
    after = source_hashes()
    report = {"schema": "IBME/SRGG-COMPACT-BENCHMARK/1", "started_from_commit": source_commit,
        "ended_utc": datetime.now(timezone.utc).isoformat(), "environment": environment(),
        "controller_python": platform.python_version(), "source_sha256": before,
        "source_bytes_unchanged_during_measurement": before == after,
        "schedule": {"profiles": ["PARAM-I", "PARAM-II", "PARAM-III"], "interpretation": "table-standard-deviation",
                     "independent_secure_random_roots_per_profile": repetitions,
                     "warm_sign_verify_per_root": warm_repetitions, "paired_codec_repetitions_per_object": codec_repetitions,
                     "identity_bytes": 64, "message_bytes": 32, "external_failure_replacement": False,
                     "restore_order_alternates_by_run": True},
        "method": {"backend": "unchanged SourceSchurBackend", "algorithms_or_parameters_modified": False,
                   "cold": "fresh Python process; OS page cache retained; imports and file reads included in process wall",
                   "warm": "same backend/root/key; existing scalar component cache; Schur plans rebuilt by unchanged backend",
                   "codec": "same four objects; one unmeasured roundtrip then alternating five paired repetitions by default",
                   "codec_timing_scope": "complete existing API costs, including semantic validation performed by each codec; not isolated bit-packing speed",
                   "restore": "same persisted objects; fresh process for JSON and compact; cached extract reads no entropy; re-sign uses fresh SecureRandom",
                   "RSS": "external 10ms /proc tree samples; may miss spikes and count shared pages twice; not an upper bound",
                   "kernel_RSS": "worker lifetime ru_maxrss, not an isolated phase peak",
                   "service": "raw backend and standalone object snapshots; FixedIssuer locks/fsync unchanged and not benchmarked",
                   "machine_isolation": "single benchmark worker at a time; unrelated host work and CPU frequency not controlled",
                   "statistics": "within-run phase medians, then descriptive summaries across independent roots; failures retained"},
        "runs": rows, "summary": summarize(rows), "private_material_exported": False,
        "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False, "nist_security_category": None}
    report["status"] = "passed" if before == after and all(x["status"] == "passed" for x in rows) else "completed-with-failures"
    output.write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--warm-repetitions", type=int, default=3)
    parser.add_argument("--codec-repetitions", type=int, default=5)
    args = parser.parse_args()
    result = run(args.private_directory, args.output, repetitions=args.repetitions,
                 warm_repetitions=args.warm_repetitions, codec_repetitions=args.codec_repetitions,
                 source_commit=args.source_commit)
    print(json.dumps({"status": result["status"], "runs": len(result["runs"])}))
    raise SystemExit(0 if result["status"] == "passed" else 1)


if __name__ == "__main__":
    main()
