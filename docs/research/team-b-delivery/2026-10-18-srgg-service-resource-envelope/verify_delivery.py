"""Verify frozen SRGG service-resource evidence against live public formulas."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

from experiments.research.candidates.srgg.paper_service_resource_envelope import (
    SCHEMA, SOURCE_FILES, report,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PREFIX = "docs/research/team-b-delivery/2026-10-18-srgg-service-resource-envelope/"
REQUIRED = {
    "experiments/research/candidates/srgg/paper_service_resource_envelope.py",
    "tests/test_srgg_paper_service_resource_envelope.py",
    PREFIX + "README_zh-CN.md", PREFIX + "service-resource-envelope.json",
    PREFIX + "validation.json", PREFIX + "verify_delivery.py",
}


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _canonical_file(name):
    _require(type(name) is str and name and "\\" not in name, "canonical path required")
    rel = Path(name)
    _require(not rel.is_absolute() and all(part not in ("", ".", "..") for part in rel.parts),
             "unsafe package path")
    target = (ROOT / rel).resolve()
    _require(target.is_relative_to(ROOT) and target.is_file(), "package file absent")
    raw = target.read_bytes()
    _require(raw.count(b"\r") == raw.count(b"\r\n"), "noncanonical line ending")
    return raw.replace(b"\r\n", b"\n")


def main():
    manifest = json.loads((HERE / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest.get("entries")
    _require(manifest.get("schema") == "IBME/SRGG-PAPER-SERVICE-RESOURCE-MANIFEST/1"
             and type(entries) is dict and set(entries) == REQUIRED,
             "manifest scope mismatch")
    for name, entry in entries.items():
        raw = _canonical_file(name)
        _require(type(entry) is dict and set(entry) == {"bytes", "sha256"}
                 and type(entry["bytes"]) is int and entry["bytes"] == len(raw)
                 and type(entry["sha256"]) is str
                 and sha256(raw).hexdigest() == entry["sha256"],
                 "manifest byte/hash mismatch: " + name)
    validation = json.loads((HERE / "validation.json").read_text(encoding="utf-8"))
    frozen_raw = _canonical_file(PREFIX + "service-resource-envelope.json")
    frozen = json.loads(frozen_raw)
    _require(validation.get("schema") == "IBME/SRGG-PAPER-SERVICE-RESOURCE-VALIDATION/1"
             and validation.get("targeted_tests") == {"passed": 4, "failed": 0, "skipped": 0}
             and validation.get("frozen_report_sha256") == sha256(frozen_raw).hexdigest()
             and validation.get("security_claim") == "none",
             "validation claim exceeds evidence")
    _require(frozen.get("schema") == SCHEMA and len(frozen.get("rows", [])) == 6
             and frozen.get("global_service_lifetime_entropy_cap_bytes") is None
             and frozen.get("global_service_lifetime_failure_upper") is None
             and frozen.get("whole_process_randomness_upper_bytes") is None
             and frozen.get("peak_ram_upper_bytes") is None
             and frozen.get("security_claim") == "none"
             and frozen.get("backend_admitted") is False
             and frozen.get("parameters_are_formal") is False
             and frozen.get("nist_security_category") is None,
             "frozen report scope changed")
    for name in SOURCE_FILES:
        _require(frozen["source_sha256"][name] == sha256(_canonical_file(name)).hexdigest(),
                 "source hash differs from frozen report: " + name)
    _require(report() == frozen, "live Table 4 public caps differ from frozen report")
    print(json.dumps({"status": "verified", "entries": len(entries),
        "rows": 6, "global_lifetime_entropy_cap": None, "security_claim": "none"},
        sort_keys=True))


if __name__ == "__main__":
    main()
