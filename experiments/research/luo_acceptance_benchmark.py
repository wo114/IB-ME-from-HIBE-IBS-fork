"""Measure missing Setup/codec boundaries for the teaching Luo combination.

Run from the repo root with PYTHONPATH=src. This does not time full IB-ME or
estimate security. It writes only aggregate metadata, lengths and timings,
never key/signature/ciphertext bytes. A fresh output directory is required.
"""

import argparse
import csv
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time

from ibme.core.randomness import DeterministicRandom
from ibme.ibs.luo_module_codec import LuoModuleCompactIBSBackend, LuoModuleCompactSignature
from ibme.protocol.luo_hybrid import (
    RESEARCH_HIBE_PARAMS, RESEARCH_IBS_PARAMS, make_research_runtime,
)

ROOT = Path(__file__).resolve().parents[2]
FIELDS = ("rep", "stage", "format", "order", "seconds", "serialized_bytes", "status", "error_type")
STAGES = {
    ("setup", "shared"), ("extract_cold", "shared"), ("extract_cached", "shared"),
    ("sign", "reference"),
    *((stage, fmt) for stage in ("encode", "decode", "verify") for fmt in ("reference", "compact")),
}


def rng(label):
    return DeterministicRandom(b"luo-acceptance-benchmark-v1:" + label.encode("ascii"))


def public_parameter_json(value):
    """JSON conversion for PUBLIC parameter dataclasses only, not key objects."""
    if isinstance(value, bytes):
        return {"encoding": "hex", "value": value.hex()}
    if isinstance(value, dict):
        return {key: public_parameter_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [public_parameter_json(item) for item in value]
    return value


def percentile(values, fraction):
    ordered = sorted(values)
    index = (len(ordered) - 1) * fraction
    lower = math.floor(index)
    upper = math.ceil(index)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower)


def validate_result(row, condition):
    # Postconditions are outside the timed interval but part of row acceptance.
    # Explicit checks must remain active under python -O.
    if not condition:
        row["status"] = "invalid"
        row["error_type"] = "EvidenceValidationError"
        raise ValueError("benchmark result failed validation")


def summarize(rows, repeats):
    """Reject incomplete/duplicate evidence, including any recorded failure."""
    expected = {(rep, stage, fmt) for rep in range(repeats) for stage, fmt in STAGES}
    keys = [(int(row["rep"]), row["stage"], row["format"]) for row in rows]
    if len(keys) != len(set(keys)) or set(keys) != expected:
        raise ValueError("missing, duplicate or unexpected benchmark cells")
    result = {}
    for row in rows:
        elapsed = float(row["seconds"])
        if row["status"] != "ok" or row["error_type"] or not math.isfinite(elapsed) or elapsed < 0:
            raise ValueError("failed or invalid timing row")
    for stage, fmt in sorted(STAGES):
        selected = [row for row in rows if row["stage"] == stage and row["format"] == fmt]
        values = [float(row["seconds"]) for row in selected]
        result[f"{stage}/{fmt}"] = {
            "n": len(values), "median_seconds": statistics.median(values),
            "min_seconds": min(values), "max_seconds": max(values),
            "q1_seconds": percentile(values, .25), "q3_seconds": percentile(values, .75),
            "serialized_bytes_observed": sorted({int(row["serialized_bytes"]) for row in selected
                                                  if row["serialized_bytes"] != ""}),
        }
    return result


def revision():
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()


def environment():
    paths = ["src/ibme/ibs/luo_module.py", "src/ibme/ibs/luo_module_codec.py",
             "src/ibme/protocol/luo_hybrid.py", "src/ibme/protocol/hybrid_hibe.py",
             "src/ibme/protocol/byteauth.py", "src/ibme/protocol/baseline.py",
             "experiments/research/luo_acceptance_benchmark.py"]
    return {
        "utc_started": datetime.now(timezone.utc).isoformat(), "source_base_commit": revision(),
        "python": sys.version, "platform": platform.platform(),
        "processor": platform.processor(), "logical_cpu_count": os.cpu_count(),
        "clock": "perf_counter_ns wall clock; serial operations; no deliberate warmup",
        "source_sha256": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths},
    }


def main(output, repeats):
    if not 1 <= repeats <= 100:
        raise ValueError("repeats must be in [1, 100]")
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    metadata = {
        "schema": "IBME/LUO-SETUP-CODEC-EVIDENCE/1", "environment": environment(),
        "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False,
        "combo": "ABB10 teaching Hybrid + Luo module + BYTEAUTH; NOT CHKP",
        "hibe_parameters": public_parameter_json(asdict(RESEARCH_HIBE_PARAMS)),
        "ibs_parameters": public_parameter_json(asdict(RESEARCH_IBS_PARAMS)),
        "rng": "deterministic test streams, disjoint per repetition and role; not production randomness",
        "repeats": repeats, "identity_bytes": 5, "ibs_message_bytes": 256,
        "boundaries": {
            "setup": "protocol.setup: actual HIBE and IBS Setup; excludes runtime creation and wire encoding",
            "extract_cold": "protocol.skgen for Alice in each fresh master state",
            "extract_cached": "protocol.skgen for the already-issued Alice; no new issuance",
            "sign": "IBS Sign on raw 256-byte message, includes internal self-verification; excludes wire encoding",
            "encode": "signature.to_bytes only; same mathematical signature in both formats",
            "decode": "backend.load_signature only, includes validation; verify excluded",
            "verify": "IBS Verify on already-decoded signature; decode excluded",
        },
        "unit": "one fresh system and one authentic mathematical signature per repetition; formats share that signature",
        "scope": "five independent systems at default repeats; codec pairs alternate order; no end-to-end speed claim",
    }
    # Fail before expensive work if any future public parameter is not encodable.
    json.dumps(metadata, ensure_ascii=False)

    def measure(rep, stage, fmt, order, fn):
        row = dict(rep=rep, stage=stage, format=fmt, order=order, seconds="",
                   serialized_bytes="", status="error", error_type="")
        start = time.perf_counter_ns()
        try:
            value = fn()
        except BaseException as exc:
            row["error_type"] = type(exc).__name__
            raise
        else:
            row["status"] = "ok"
            return value, row
        finally:
            row["seconds"] = (time.perf_counter_ns() - start) / 1e9
            rows.append(row)

    failure = None
    completed = False
    try:
        for rep in range(repeats):
            protocol, _ = make_research_runtime(ibs_rng=rng(f"{rep}:ibs"), ots_rng=rng(f"{rep}:ots"))
            # Runtime construction and entropy-object construction are outside Setup.
            setup_rng = rng(f"{rep}:setup")
            (public, master), setup_row = measure(rep, "setup", "shared", "", lambda: protocol.setup(
                RESEARCH_HIBE_PARAMS, ibs_params=RESEARCH_IBS_PARAMS, rng=setup_rng))
            setup_row["serialized_bytes"] = len(public.to_bytes())
            sender, cold_row = measure(rep, "extract_cold", "shared", "", lambda: protocol.skgen(master, b"Alice"))
            cached, cached_row = measure(rep, "extract_cached", "shared", "", lambda: protocol.skgen(master, b"Alice"))
            validate_result(cached_row, cached.to_bytes() == sender.to_bytes())
            cold_row["serialized_bytes"] = cached_row["serialized_bytes"] = len(sender.to_bytes())
            message = b"x" * 256
            signature, _ = measure(rep, "sign", "reference", "", lambda: protocol.ibs_backend.sign(sender.signing_key, message))
            compact = LuoModuleCompactSignature(signature)
            codecs = {"reference": (protocol.ibs_backend, signature),
                      "compact": (LuoModuleCompactIBSBackend(), compact)}
            order = ["reference", "compact"] if rep % 2 == 0 else ["compact", "reference"]
            for fmt in order:
                backend, value = codecs[fmt]
                encoded, enc_row = measure(rep, "encode", fmt, "/".join(order), value.to_bytes)
                loaded, dec_row = measure(rep, "decode", fmt, "/".join(order), lambda: backend.load_signature(public.ipk, encoded))
                enc_row["serialized_bytes"] = dec_row["serialized_bytes"] = len(encoded)
                mathematical = loaded.signature if fmt == "compact" else loaded
                validate_result(dec_row, (mathematical.params, mathematical.context, mathematical.z, mathematical.c, mathematical.w1, mathematical.h) == (
                    signature.params, signature.context, signature.z, signature.c, signature.w1, signature.h))
                validate_result(dec_row, loaded.to_bytes() == encoded)
                accepted, verify_row = measure(rep, "verify", fmt, "/".join(order), lambda: backend.verify(public.ipk, b"Alice", message, loaded))
                validate_result(verify_row, accepted is True)
            print(f"completed repetition {rep + 1}/{repeats}", flush=True)
        completed = True
    except BaseException as exc:
        failure = type(exc).__name__
        raise
    finally:
        metadata["completed"] = completed
        metadata["failure_type"] = failure
        metadata["utc_finished"] = datetime.now(timezone.utc).isoformat()
        with (output / "raw.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        (output / "metadata.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # Summaries are rebuilt from persisted raw data, never from hard-coded numbers.
    with (output / "raw.csv").open(newline="", encoding="utf-8") as stream:
        summary = summarize(list(csv.DictReader(stream)), repeats)
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()
    main(args.output, args.repeats)
