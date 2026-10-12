"""Bounded, public-evidence-only Luo single-primitive lifecycle benchmark.

Fresh output directory required. Private snapshots never leave memory. This
does not exercise filesystem persistence, CHKP, or full IB-ME encryption.
"""
import argparse
import csv
import ctypes
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

from ibme.core.randomness import DeterministicRandom
from ibme.ibs.luo_module import (
    LuoModuleIBSBackend, LuoModuleParams, LuoModulePublicKey,
    LuoModuleMasterSecret, LuoModuleSigningKey, LuoModuleSamplingAbort,
)
from ibme.ibs.luo_module_codec import LuoModuleCompactIBSBackend, LuoModuleCompactSignature

ROOT = Path(__file__).resolve().parents[2]
EVENT_FIELDS = ("system", "identity_len", "message_len", "repetition", "stage", "format",
                "seconds", "status", "error_type", "extract_attempts", "sign_attempts",
                "serialized_bytes", "math_fields_equal", "cache_entries")
CALL_FIELDS = ("system", "identity_len", "message_len", "repetition", "status", "failure_type",
               "sign_attempts", "sign_seconds", "reference_bytes", "compact_bytes",
               "verify_reference", "verify_compact", "math_fields_equal", "roundtrip_equal")
SIZE_FIELDS = ("system", "component", "identity_len", "cache_entries", "bytes", "includes_public_key")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(row, condition):
    if not condition:
        row.update(status="invalid", error_type="EvidenceValidationError")
        raise ValueError("lifecycle postcondition failed")


def timed(rows, unit, stage, function, fmt="", backend=None):
    row = {field: "" for field in EVENT_FIELDS}
    row.update(dict(zip(("system", "identity_len", "message_len", "repetition"), unit)),
               stage=stage, format=fmt, status="error")
    rows.append(row)  # Reserve the event before entering user code.
    start = time.perf_counter_ns()
    try:
        value = function()
    except BaseException as exc:
        row["error_type"] = type(exc).__name__
        raise
    else:
        row["status"] = "ok"
        return value, row
    finally:
        row["seconds"] = (time.perf_counter_ns() - start) / 1e9
        if backend is not None:
            if stage.startswith("extract"):
                row["extract_attempts"] = backend.last_extract_attempts
            if stage == "sign":
                row["sign_attempts"] = backend.last_sign_attempts or ""


def math_fields(signature):
    return tuple(getattr(signature, name) for name in ("params", "context", "z", "c", "w1", "h"))


def make_backend(run_id, label):
    return LuoModuleIBSBackend(rng=DeterministicRandom(
        ("luo-lifecycle-v2:" + run_id + ":" + label).encode("ascii")))


class NoEntropy:
    def read(self, count):
        raise RuntimeError("cache retrieval must not consume entropy")


def peak_memory():
    if os.name != "nt":
        return {"bytes": None, "method": "not measured on this platform"}
    class Counters(ctypes.Structure):
        _fields_ = [("cb", ctypes.c_ulong), ("faults", ctypes.c_ulong)] + [
            (name, ctypes.c_size_t) for name in ("peak", "current", "qpp", "qp", "qnp", "qn", "pf", "pfp")]
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = ctypes.c_void_p
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(Counters), ctypes.c_ulong]
        psapi.GetProcessMemoryInfo.restype = ctypes.c_int
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        if not psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
            raise OSError(ctypes.get_last_error(), "GetProcessMemoryInfo")
        return {"bytes": int(counters.peak), "method": "Windows PeakWorkingSetSize; whole worker lifetime, interpreter/imports/evidence included"}
    except (OSError, AttributeError) as exc:
        return {"bytes": None, "method": "not measured", "error_type": type(exc).__name__}


def metadata(run_id):
    import ibme.ibs.luo_module as loaded
    require(Path(loaded.__file__).resolve().is_relative_to((ROOT / "src").resolve()), "wrong source import")
    files = ["src/ibme/ibs/luo_module.py", "src/ibme/ibs/luo_module_math.py",
             "src/ibme/ibs/luo_module_codec.py", "src/ibme/core/randomness.py",
             "src/ibme/core/encoding.py", "src/ibme/core/hashing.py",
             "experiments/research/luo_lifecycle_benchmark.py"]
    return dict(
        schema="IBME/LUO-LIFECYCLE/2", run_id=run_id, started_utc=datetime.now(timezone.utc).isoformat(),
        source_base_commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        source_sha256={f: hashlib.sha256((ROOT / f).read_bytes()).hexdigest() for f in files},
        python=sys.version, platform=platform.platform(), logical_cpus=os.cpu_count(),
        parameters=asdict(LuoModuleParams()), security_claim="none", backend_admitted=False,
        parameters_are_formal=False, completed=False, interrupted=False, failure_type=None,
        rng="deterministic test streams, disjoint setup/extract and each sign call; not production",
        unit="3 systems x identity bytes 1/5/64 x message bytes 0/256/4096 x 2 repetitions = 54 Sign calls",
        timing="perf_counter_ns wall time; no affinity/load control; validation/serialization excluded except named stage",
        restore="in-memory wire decoding and equation checks; no disk I/O, crash safety or anti-rollback claim",
        sign="includes backend self-Verify, excludes wire encoding; rep0 uses original key, rep1 restored key",
        cache="timed key_extract only; equality checks outside timer; NoEntropy enforces zero resampling",
        unknown=dict(theoretical_sign_abort_bound=None, security_bits=None),
    )


def persist(output, run_id, rows, calls, sizes, meta):
    for name, values, fields in (("luo-single-call-ledger", rows, EVENT_FIELDS),
                                 ("luo-sign-calls", calls, CALL_FIELDS),
                                 ("primitive-sizes", sizes, SIZE_FIELDS)):
        with (output / f"{name}-{run_id}.csv").open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows(values)
    (output / f"run-metadata-{run_id}.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main(output, run_id="codex-final"):
    require(run_id.isascii() and run_id.replace("-", "").isalnum(), "invalid run id")
    output.mkdir(parents=True, exist_ok=False)
    meta = metadata(run_id)
    rows, calls, sizes = [], [], []
    batch_start = time.monotonic()
    def size(system, component, data, identity=0, count=0):
        sizes.append(dict(system=system, component=component, identity_len=identity,
                          cache_entries=count, bytes=len(data), includes_public_key=component != "signature"))
    def restore_master(master, system, identity, count):
        raw = master.to_bytes()
        restored, row = timed(rows, (system, identity, 0, -1), "master_state_recover",
                              lambda: LuoModuleMasterSecret.from_bytes(raw))
        row.update(cache_entries=count, serialized_bytes=len(raw))
        validate(row, restored.to_bytes() == raw and len(restored.cached_identities) == count)
        if count in (0, 1, 3): size(system, "master_state_wire", raw, count=count)
        return restored
    try:
        for system in range(3):
            p = LuoModuleParams()
            setup_backend = make_backend(run_id, f"{system}:setup")
            (public, master), setup_row = timed(rows, (system, 0, 0, -1), "setup", lambda: setup_backend.setup(p))
            public_raw = public.to_bytes()
            size(system, "public_key_wire", public_raw)
            checked_public = LuoModulePublicKey.from_bytes(public_raw)
            validate(setup_row, checked_public.to_bytes() == public_raw)
            restore_master(master, system, 0, 0)
            extractor = make_backend(run_id, f"{system}:extract")
            cache_reader = LuoModuleIBSBackend(rng=NoEntropy())
            originals, restored_keys = {}, {}
            for count, length in enumerate((1, 5, 64), 1):
                identity = b"i" * length
                sk, row = timed(rows, (system, length, 0, -1), "extract_cold",
                                lambda: extractor.key_extract(master, identity), backend=extractor)
                key_raw = sk.to_bytes()
                row["serialized_bytes"] = len(key_raw)
                size(system, "identity_signing_key_wire", key_raw, identity=length, count=count)
                cached, row = timed(rows, (system, length, 0, -1), "extract_cached",
                                    lambda: cache_reader.key_extract(master, identity), backend=cache_reader)
                validate(row, cached.to_bytes() == key_raw and cache_reader.last_extract_attempts == 0)
                recovered, row = timed(rows, (system, length, 0, -1), "signing_key_recover",
                                      lambda: LuoModuleSigningKey.from_bytes(key_raw))
                validate(row, recovered.to_bytes() == key_raw)
                restored = restore_master(master, system, length, count)
                from_master = cache_reader.key_extract(restored, identity)
                validate(row, from_master.to_bytes() == key_raw and cache_reader.last_extract_attempts == 0)
                originals[length], restored_keys[length] = sk, from_master
            master_before = master.to_bytes()
            for length in (1, 5, 64):
                for message_len in (0, 256, 4096):
                    message = bytes(i % 251 for i in range(message_len))
                    for rep in range(2):
                        require(time.monotonic() - batch_start < 1800, "cooperative batch timeout")
                        unit = system, length, message_len, rep
                        call = {f: "" for f in CALL_FIELDS}
                        call.update(dict(zip(("system", "identity_len", "message_len", "repetition"), unit)), status="error")
                        calls.append(call)  # Includes the call even when Sign aborts.
                        signer = make_backend(run_id, ":".join(map(str, unit)) + ":sign")
                        key_to_use = originals[length] if rep == 0 else restored_keys[length]
                        try:
                            signature, sign_row = timed(rows, unit, "sign", lambda: signer.sign(key_to_use, message), backend=signer)
                            call.update(sign_attempts=signer.last_sign_attempts, sign_seconds=sign_row["seconds"])
                            order = ("reference", "compact") if rep == 0 else ("compact", "reference")
                            for fmt in order:
                                verifier = LuoModuleIBSBackend(rng=NoEntropy()) if fmt == "reference" else LuoModuleCompactIBSBackend(rng=NoEntropy())
                                value = signature if fmt == "reference" else LuoModuleCompactSignature(signature)
                                wire, row = timed(rows, unit, "encode", value.to_bytes, fmt)
                                row["serialized_bytes"] = len(wire)
                                call[f"{fmt}_bytes"] = len(wire)
                                loaded, row = timed(rows, unit, "decode", lambda: verifier.load_signature(checked_public, wire), fmt)
                                mathematical = loaded if fmt == "reference" else loaded.signature
                                validate(row, math_fields(mathematical) == math_fields(signature) and loaded.to_bytes() == wire)
                                row["math_fields_equal"] = "yes"
                                accepted, row = timed(rows, unit, "verify", lambda: verifier.verify(checked_public, b"i" * length, message, loaded), fmt)
                                validate(row, accepted is True)
                                row["math_fields_equal"] = "yes"
                                call[f"verify_{fmt}"] = "True"
                            call.update(status="ok", math_fields_equal="yes", roundtrip_equal="yes")
                        except BaseException as exc:
                            call.update(failure_type=type(exc).__name__, sign_attempts=signer.last_sign_attempts or "")
                            # timed() reserved and completed the Sign event even
                            # when it raised; carry its measured duration into
                            # the call ledger instead of dropping failure cost.
                            sign_event = next(r for r in reversed(rows) if r["stage"] == "sign")
                            call["sign_seconds"] = sign_event["seconds"]
                            if isinstance(exc, LuoModuleSamplingAbort):
                                continue
                            raise
            require(master.to_bytes() == master_before, "Sign changed master snapshot")
            persist(output, run_id, rows, calls, sizes, meta)
            print(f"completed system {system + 1}/3; calls {len(calls)}/54", flush=True)
        meta["source_sha256_final"] = {f: hashlib.sha256((ROOT / f).read_bytes()).hexdigest()
                                       for f in meta["source_sha256"]}
        require(meta["source_sha256_final"] == meta["source_sha256"], "source changed during run")
        meta["completed"] = len(calls) == 54 and all(c["status"] == "ok" for c in calls)
    except BaseException as exc:
        meta.update(failure_type=type(exc).__name__, interrupted=isinstance(exc, (KeyboardInterrupt, SystemExit)))
        raise
    finally:
        meta.update(finished_utc=datetime.now(timezone.utc).isoformat(), elapsed_seconds=time.monotonic() - batch_start,
                    memory=peak_memory(), attempted_sign_calls=sum(r["stage"] == "sign" for r in rows),
                    normal_call_failures=sum(c["status"] != "ok" for c in calls))
        persist(output, run_id, rows, calls, sizes, meta)
    require(meta["completed"], "incomplete or failed lifecycle batch; raw records retained")
    from audit_luo_lifecycle import audit
    try:
        summary = audit(output, run_id)
    except BaseException as exc:
        meta.update(completed=False, failure_type=type(exc).__name__)
        persist(output, run_id, rows, calls, sizes, meta)
        raise
    (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k != "per_cell_timings"}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", default="codex-final")
    args = parser.parse_args()
    main(args.output, args.run_id)
