"""Read-only checks on actual public A records; no cryptographic replay."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from experiments.research.verify_backend_optimization import validate_batch

FOLDER = Path(__file__).resolve().parents[1]/"docs/research/2026-10-20-multi-backend-optimization"


def inputs():
    return [json.loads((FOLDER/name).read_bytes()) for name in
            ("A.json", "installation.json", "source-manifest.json")]


def test_actual_installed_A_receipt_and_native_verification_counts():
    data, installation, manifest = inputs()
    result = validate_batch(data, installation, manifest)
    assert result["decrypt"]["median_root_speedup"] > 0


@pytest.mark.parametrize("tamper", ("failure", "provider", "count", "summary", "suite", "roots"))
def test_tampered_receipts_do_not_inherit_success(tamper):
    data, installation, manifest = deepcopy(inputs())
    first = data["records"][0]
    if tamper == "failure":
        first["status"] = "failed"
    elif tamper == "provider":
        next(iter(first["providers"].values()))["sha256"] = "0"*64
    elif tamper == "count":
        row = next(r for r in first["phases"] if r["name"] == "decrypt" and r["mode"] == "on")
        row["native_calls"]["mldsa:verify"] = 2
    elif tamper == "summary":
        data["summary"]["decrypt"]["median_root_speedup"] = 1000
    elif tamper == "suite":
        first["suite"]["hybrid_limits"]["max_payload_bytes"] += 1
    else:
        data["records"][1]["root"] = 0
    with pytest.raises(ValueError):
        validate_batch(data, installation, manifest)
