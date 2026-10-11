"""Bounded, local-only evidence runner. Writes exclusively to a NEW sidecar subdir.

Exit 0: checker tests and boundary probes passed, expected BLOCKED preflight
was observed, and monitored input bytes stayed unchanged. It NEVER means the
CHKP composition or security admission passed. preflight.py itself exits 2.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

import preflight as p
from public_contract_probe import PACKAGE

BASE = Path(__file__).resolve().parent


def write_json(path, value):
    path.write_bytes((json.dumps(value, ensure_ascii=True, indent=2) + "\n").encode("utf-8"))


def snapshot():
    sources = p.source_snapshot(p.DEFAULT_REPO)
    # Full tracked repository byte inventory. Package scope is ONLY the files
    # read/imported here; no repeat of the owner's 465-entry package audit.
    names = subprocess.check_output(["git", "-C", str(p.DEFAULT_REPO), "ls-files", "-z"], timeout=20).decode("utf-8").split("\0")
    tracked = {}
    for name in names:
        if name:
            path = p.DEFAULT_REPO / name
            tracked[name] = p.digest(path.read_bytes()) if path.is_file() else "MISSING"
    relevant = ["a_contract/wire_reference.py", "a_contract/T4-contract-v0.4.md",
                "f_handoff/call_collector.py", "f_handoff/integration_handoff_v2.md",
                "source_manifest.json", "MANIFEST_SHA256.txt"]
    return {"head": p.git(p.DEFAULT_REPO, "rev-parse", "HEAD"),
            "status": p.git(p.DEFAULT_REPO, "status", "--porcelain=v1"),
            "tracked_repository_files": tracked, "source_snapshot_sha256": sources["sha256"],
            "package_files_read": {name: p.digest((PACKAGE / name).read_bytes()) for name in relevant},
            "step8_present": (PACKAGE.parent / "CHKP-step8-package").exists(),
            "chkp_slot_present": (p.DEFAULT_REPO / p.SLOT).exists()}


def execute(out, name, arguments, timeout=45):
    command = [sys.executable, "-B", *arguments]
    started = datetime.now(timezone.utc).isoformat()
    tick = time.monotonic()
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")
    try:
        run = subprocess.run(command, cwd=BASE, env=env, capture_output=True, timeout=timeout)
        rc, stdout, stderr = run.returncode, run.stdout, run.stderr
        status = "exited"
    except subprocess.TimeoutExpired as exc:
        rc, stdout, stderr, status = 124, exc.stdout or b"", exc.stderr or b"", "timeout"
    except OSError as exc:
        rc, stdout, stderr, status = 125, b"", type(exc).__name__.encode(), "launch_error"
    (out / (name + ".stdout.txt")).write_bytes(stdout)
    (out / (name + ".stderr.txt")).write_bytes(stderr)
    receipt = {"command": command, "cwd": str(BASE), "start_utc": started,
               "end_utc": datetime.now(timezone.utc).isoformat(),
               "duration_seconds": time.monotonic() - tick, "timeout_seconds": timeout,
               "exit_code": rc, "process_status": status,
               "stdout_sha256": p.digest(stdout), "stderr_sha256": p.digest(stderr)}
    write_json(out / (name + ".receipt.json"), receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to(BASE) or out == BASE or out.exists():
        parser.error("--out must be a NEW directory under the private sidecar; existing outputs are never overwritten")
    out.mkdir(parents=True)
    before = snapshot()
    write_json(out / "inputs-before.json", before)
    environment = {"python": sys.version, "executable": sys.executable, "platform": platform.platform(),
                   "logical_cpus": os.cpu_count(), "processor": platform.processor(),
                   "package_check": "owner confirmation: stable step7, 465 entries pass; NOT rerun here",
                   "sidecar_source_sha256": {f.name: p.digest(f.read_bytes()) for f in sorted(BASE.glob("*.py"))}}
    write_json(out / "environment.json", environment)
    receipts = {}
    receipts["preflight"] = execute(out, "preflight", [str(BASE / "preflight.py")])
    receipts["tests"] = execute(out, "tests", ["-m", "unittest", "-v", "test_preflight"])
    receipts["public-contract"] = execute(out, "public-contract", [str(BASE / "public_contract_probe.py")])
    after = snapshot()
    write_json(out / "inputs-after.json", after)
    expected = {"preflight": 2, "tests": 0, "public-contract": 0}
    all_ok = before == after and all(receipts[name]["exit_code"] == rc for name, rc in expected.items())
    try:
        result = json.loads((out / "preflight.stdout.txt").read_text(encoding="utf-8"))
        all_ok &= (result["first_blocker"] == "CHKP_PUBLIC_BACKEND_MISSING"
                   and result["ready_for_bounded_smoke"] is False and result["backend_admitted"] is False)
    except (ValueError, KeyError):
        all_ok = False
    summary = {"sidecar_validation_passed": bool(all_ok), "expected_exit_codes": expected,
               "actual_exit_codes": {name: receipt["exit_code"] for name, receipt in receipts.items()},
               "monitored_input_bytes_unchanged": before == after,
               "functional_status": "BLOCKED", "first_blocker": "CHKP_PUBLIC_BACKEND_MISSING",
               "smoke_executed": False, "functional_integration_passed": False,
               "security_claim": "none", "backend_admitted": False,
               "package_manifest_verification": "not repeated; owner-confirmed 465 entries",
               "environment": "environment.json"}
    write_json(out / "summary.json", summary)
    files = {f.name: p.digest(f.read_bytes()) for f in sorted(out.iterdir()) if f.is_file()}
    write_json(out / "manifest.json", files)
    print(json.dumps(summary, indent=2))
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
