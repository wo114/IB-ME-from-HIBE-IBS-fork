"""Explicit v2 system-entropy tree, read-only recovery and one real Luo pairing.

Uses the shared framework probe and common acceptance runner. Private state
creation is restricted to a NEW directory under this checkout's ignored
test-results tree. Failed trees are retained and never regenerated here.
No external service, key recovery or public-parameter attack is performed.
"""

import argparse
from dataclasses import asdict
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import resource
import time
from unittest.mock import patch

from ibme.assembly import BackendRegistry, default_registry
from ibme.core.randomness import SecureRandom
from ibme.hibe.mp12_structured import StructuredHIBEParams192, finite192_backend_spec
from ibme.ibs.luo_module_profiles import c64b_params
from experiments.research.structured_framework_probe import generate, restore, matrix
from experiments.research.structured_hibe_probe import save
from experiments.research.structured_service_budget import service_budget


def selected_registry():
    return BackendRegistry((finite192_backend_spec(), default_registry().get("ibs", "luo-module")))


def check_private_destination(directory):
    root = Path(__file__).resolve().parents[2]
    allowed = (root/"test-results").resolve()
    resolved = Path(directory).resolve()
    if resolved == allowed or not resolved.is_relative_to(allowed):
        raise ValueError("new finite192 private state must be under the ignored test-results directory")
    return resolved


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-directory", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--restore-only", action="store_true")
    mode.add_argument("--matrix", action="store_true")
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("new public receipt required")
    directory = (args.private_directory.resolve(strict=True) if args.restore_only or args.matrix
                 else check_private_destination(args.private_directory))
    if args.output.resolve().is_relative_to(directory):
        raise ValueError("public receipt must be outside the private-state directory")
    registry = selected_registry()
    budget = service_budget(StructuredHIBEParams192())
    if not budget["meets_target_in_stated_model"]:
        raise ValueError("finite192 recipe no longer meets its declared probability target")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write('{"status":"started"}\n')
    original_read = SecureRandom.read
    entropy = dict(reads=0, bytes=0)
    def measured_read(source, count):
        raw = original_read(source, count)
        entropy["reads"] += 1
        entropy["bytes"] += len(raw)
        return raw
    started = time.perf_counter()
    with patch.object(SecureRandom, "read", measured_read):
        if args.restore_only:
            if not (directory/"completed").is_file():
                raise ValueError("completed original tree required; failed addresses are not retried")
            result = restore(directory, registry=registry)
        elif args.matrix:
            cases = [("luo-module-c64b-compact", "luo-module", asdict(c64b_params()), "compact")]
            # The common runner reserves its own separate, new receipt.
            result = matrix(directory, args.output.with_suffix(".matrix.json"), args.source_commit,
                            registry=registry, cases=cases)
        else:
            result = generate(directory, args.source_commit, registry=registry)
    from sage.version import version as sage_version
    result.update(schema="A-STRUCTURED-FINITE192-"+
        ("RESTORE/1" if args.restore_only else "COMBINATION/1" if args.matrix else "TREE/1"),
        source_commit=args.source_commit, parameters=StructuredHIBEParams192().record(),
        public_budget=budget, default_registry_changed=False,
        finite192_probe_sha256=sha256(Path(__file__).read_bytes()).hexdigest(),
        measured_system_entropy=entropy, probe_seconds=time.perf_counter()-started,
        peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        environment=dict(python=platform.python_version(), sage=sage_version,
            platform=platform.platform(), OMP_NUM_THREADS=os.getenv("OMP_NUM_THREADS"),
            OPENBLAS_NUM_THREADS=os.getenv("OPENBLAS_NUM_THREADS")),
        private_values_exported=False,
        security_claim="none", backend_admitted=False, parameters_are_formal=False)
    save(args.output, result)
    print(json.dumps(dict(status=result["status"], mode="restore" if args.restore_only else
        "combination" if args.matrix else "system-tree", probability_exponent=131)), flush=True)


if __name__ == "__main__":
    main()
