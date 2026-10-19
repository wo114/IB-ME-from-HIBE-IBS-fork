"""Compile and check task dependencies without running a cryptographic experiment."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

import psutil


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task-directory", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    args = parser.parse_args()
    task = args.task_directory.resolve()
    environment = task / "environment"
    environment.mkdir(parents=True, exist_ok=True)
    versions = {}
    for name in ("numpy", "scipy", "pytest", "psutil", "gmpy2", "cryptography"):
        importlib.import_module(name)
        versions[name] = importlib.metadata.version(name)
    import sage.all  # noqa: F401
    import sage.version
    versions["sage"] = sage.version.version
    from ibme.ibs.wang_pw_target import native
    library = native.build_native(output_directory=environment / "native" / "wang")
    os.environ["IBME_WANG_PW_TARGET_NATIVE"] = str(library)
    native._library()  # ABI and source/binary continuity only; no samples.
    latte_prefix = environment / "native" / "latte"
    subprocess.run([sys.executable, "-m", "ibme.hibe.latte.native.build", "--prefix", str(latte_prefix)], check=True)
    latte = latte_prefix / "bin" / "ibme-latte3"
    meta = json.loads(subprocess.run([str(latte), "meta"], input=b"", capture_output=True,
                                     check=True, timeout=15).stdout)
    from ibme.hibe.latte.native.build import source_id
    if meta["source_id"] != source_id():
        raise RuntimeError("LATTE metadata source mismatch")
    locks = {}
    for name in ("requirements.lock.txt", "sage-explicit.lock.txt"):
        locks[name] = hashlib.sha256((environment / name).read_bytes()).hexdigest()
    report = dict(
        schema="IBME/WANG-PW-TASK-ENVIRONMENT/1", status="ready",
        checked_at=datetime.now(timezone.utc).isoformat(), source_commit=args.source_commit,
        python=platform.python_version(), platform=platform.platform(),
        cpu=platform.processor(), logical_cpus=psutil.cpu_count(),
        ram_total_bytes=psutil.virtual_memory().total, packages=versions,
        compiler=subprocess.run(["g++", "--version"], capture_output=True, text=True, check=True).stdout.splitlines()[0],
        wang_native=json.loads(library.with_name(library.name + ".json").read_text()),
        latte_native=dict(source_id=meta["source_id"], binary_sha256=hashlib.sha256(latte.read_bytes()).hexdigest()),
        dependency_locks_sha256=locks, cryptographic_experiments_run=False,
        security_claim="none", backend_admitted=False, parameters_are_formal=False,
        nist_security_category=None,
    )
    output = environment / "environment-ready.json"
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    # Shell assignments are local operator configuration, not public evidence.
    (environment / "runtime.env").write_text(
        f"export IBME_WANG_PW_TARGET_NATIVE='{library}'\n"
        f"export IBME_LATTE3_EXECUTABLE='{latte}'\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
