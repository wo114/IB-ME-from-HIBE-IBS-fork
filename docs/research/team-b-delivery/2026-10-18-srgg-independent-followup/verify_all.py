"""Run the nine independently frozen SRGG delivery verifiers.

Use the designated WSL Sage Python. This driver does not modify a receipt
unless --output explicitly names a new report path.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


PACKAGE_NAMES = (
    "2026-10-18-srgg-finite-chain",
    "2026-10-18-srgg-setup-acceptance",
    "2026-10-18-srgg-verification-image",
    "2026-10-18-srgg-smoothing-eta",
    "2026-10-18-srgg-source-issuance",
    "2026-10-18-srgg-setup-backend-gap",
    "2026-10-18-srgg-structural-cost",
    "2026-10-18-srgg-history-law-followup",
    "2026-10-18-srgg-strong-game",
)


def verify() -> dict:
    root = Path(__file__).resolve().parents[4]
    delivery_root = root / "docs/research/team-b-delivery"
    packages = []
    for name in PACKAGE_NAMES:
        verifier = delivery_root / name / "verify_delivery.py"
        if not verifier.is_file():
            raise FileNotFoundError(name)
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.append(str(verifier))
            result = subprocess.run(
                command, cwd=root, capture_output=True, text=True, check=False
            )
            if result.returncode:
                raise RuntimeError(
                    f"{name} optimized={optimized} exit={result.returncode}\n"
                    f"stdout tail:\n{result.stdout[-4000:]}\n"
                    f"stderr tail:\n{result.stderr[-4000:]}"
                )
            packages.append({"name": name, "optimized": optimized, "exit_code": 0})
    return {
        "schema": "srgg-independent-followup-verify-all-v1",
        "package_count": len(PACKAGE_NAMES),
        "checks": packages,
        "all_passed": True,
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
        "nist_security_category": None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    record = verify()
    encoded = json.dumps(record, indent=2, sort_keys=True) + "\n"
    if arguments.output is not None:
        arguments.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")


if __name__ == "__main__":
    main()
