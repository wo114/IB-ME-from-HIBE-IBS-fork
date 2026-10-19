"""External Linux /proc sampling for an owned SRGG benchmark subprocess."""
import gzip
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from experiments.research.runtime_metrics import rss_tree

WORKER_FIELDS = frozenset(("status", "phases", "checks", "private_material_exported", "profile",
    "published_inputs", "mode", "sage", "identity_bytes", "message_bytes", "randomness",
    "numerical_options", "security_claim", "backend_admitted", "parameters_are_formal",
    "nist_security_category", "warm_repetitions", "codec_repetitions", "object_sizes_bytes",
    "dense_coefficient_matrix_materialized", "entropy_bytes_returned", "entropy_read_requests",
    "setup_attempts", "extraction_calls", "sign_attempts", "kernel_lifetime_peak_rss_bytes",
    "error_type", "private_diagnostics_exported"))


def public_worker_result(path):
    if not path.is_file():
        return {"status": "worker-incomplete", "phases": [], "private_material_exported": False}
    try:
        if path.stat().st_size > 8*1024*1024:
            raise ValueError("worker report limit")
        result = json.loads(path.read_text())
    except (OSError, ValueError, UnicodeError):
        return {"status": "worker-report-invalid", "phases": [], "private_material_exported": False}
    if (type(result) is not dict or set(result)-WORKER_FIELDS
            or result.get("private_material_exported") is not False
            or type(result.get("phases")) is not list
            or any(type(x) is not dict or not {"name", "start_ns", "end_ns", "seconds"} <= x.keys()
                   for x in result.get("phases", []))):
        return {"status": "worker-report-rejected", "phases": [], "private_material_exported": False}
    return result


def supervise(command, directory, *, timeout_seconds=900, rss_limit_bytes=2**31,
              sample_seconds=0.01):
    directory = Path(directory)
    samples, stopped = [], None
    started = time.monotonic_ns()
    with (directory/"stdout.log").open("xb") as out, (directory/"stderr.log").open("xb") as err:
        proc = subprocess.Popen(command, stdout=out, stderr=err, start_new_session=True)
        while True:
            now = time.monotonic_ns()
            own, tree = rss_tree(proc.pid)
            samples.append((now, own, tree))
            if proc.poll() is not None:
                break
            if now-started > timeout_seconds*10**9:
                stopped = "timeout"
            elif tree > rss_limit_bytes:
                stopped = "sampled-rss-budget"
            if stopped:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    proc.wait()
                break
            time.sleep(sample_seconds)
    ended = time.monotonic_ns()
    path = directory/"worker.json"
    result = public_worker_result(path)
    for phase in result["phases"]:
        start, end = phase.pop("start_ns"), phase.pop("end_ns")
        observed = [x for x in samples if start <= x[0] <= end and x[1] > 0]
        phase.update(start_offset_seconds=(start-started)/1e9,
                     sampled_self_peak_rss_bytes=max((x[1] for x in observed), default=None),
                     sampled_tree_peak_rss_bytes=max((x[2] for x in observed), default=None),
                     rss_sample_count=len(observed))
    observed = [x for x in samples if x[1] > 0]
    result.update(process_wall_seconds=(ended-started)/1e9, process_exit_code=proc.returncode,
                  external_stop_reason=stopped,
                  sampled_self_peak_rss_bytes=max((x[1] for x in observed), default=None),
                  sampled_tree_peak_rss_bytes=max((x[2] for x in observed), default=None),
                  rss_sample_count=len(observed), rss_requested_interval_seconds=sample_seconds,
                  rss_max_observed_gap_seconds=max((b[0]-a[0] for a, b in zip(samples, samples[1:])), default=0)/1e9,
                  watchdog_timeout_seconds=timeout_seconds, watchdog_sampled_rss_budget_bytes=rss_limit_bytes)
    if stopped or proc.returncode:
        result["status"] = "failed"
    with gzip.open(directory/"rss-samples.jsonl.gz", "xt", encoding="utf-8") as handle:
        for stamp, own, tree in samples:
            handle.write(json.dumps({"offset_ns": stamp-started, "self_rss_bytes": own,
                                     "tree_rss_bytes": tree}, sort_keys=True)+"\n")
    return result
