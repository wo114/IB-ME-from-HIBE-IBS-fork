"""Run all current SRGG delivery checks without rewriting any receipt."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
DELIVERIES = ROOT / "docs/research/team-b-delivery"
SOURCE_SCHUR = "2026-10-18-srgg-source-schur"


def run(path: Path, *, optimized: bool) -> None:
    command = [sys.executable]
    if optimized:
        command.append("-O")
    command.append(str(path))
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError(
            f"{path.parent.name} optimized={optimized} exit={result.returncode}\n"
            f"stdout tail:\n{result.stdout[-2000:]}\n"
            f"stderr tail:\n{result.stderr[-2000:]}"
        )
    try:
        record = json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{path.parent.name}: missing JSON verification result") from error
    if (not isinstance(record, dict) or
            record.get("status", "verified") != "verified" or
            record.get("security_claim", "none") != "none"):
        raise RuntimeError(f"{path.parent.name}: invalid verification result")


def main() -> None:
    verifiers = sorted(DELIVERIES.glob("2026-10-18-srgg-*/verify_delivery.py"))
    verifiers.append(DELIVERIES / "2026-10-18-srgg-closure-followup/verify_followup.py")
    if len(verifiers) != 19 or sum(p.parent.name == SOURCE_SCHUR for p in verifiers) != 1:
        raise RuntimeError("expected exactly 19 source-era SRGG packages")
    for verifier in verifiers:
        if verifier.parent.name == SOURCE_SCHUR:
            continue
        for optimized in (False, True):
            run(verifier, optimized=optimized)
    for optimized in (False, True):
        run(HERE / "verify_publication.py", optimized=optimized)
    print(json.dumps({
        "schema": "IBME/SRGG-PR-INTEGRATION-VERIFY-ALL/1",
        "status": "verified",
        "packages": 19,
        "historical_current_packages": 18,
        "source_schur_overlay_packages": 1,
        "normal_and_optimized_checks": 38,
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
        "nist_security_category": None,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
