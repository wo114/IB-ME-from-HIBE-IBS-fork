"""Verify the v2 gate-uniform scope re-freeze.

Pure Python (no Sage).  It checks:
- this package's MANIFEST entries;
- the four v1 package manifests and every v1 manifest entry byte/hash;
- the corrected scope declaration and the complete gate set;
- the recorded v1 verifier run (nine packages, 18 checks);
- the guard report's full-gate fields.

Run:
    python docs/research/team-b-delivery/2026-10-18-srgg-gate-uniform-v2/verify_delivery.py
"""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
PACKAGE = Path(__file__).resolve().parent
DELIVERY = ROOT / "docs/research/team-b-delivery"
GUARD = DELIVERY / "2026-10-18-srgg-distribution-guard-deepseek"
V1_PACKAGES = (
    "docs/research/team-b-delivery/2026-10-18-srgg-finite-chain",
    "docs/research/team-b-delivery/2026-10-18-srgg-source-issuance",
    "docs/research/team-b-delivery/2026-10-18-srgg-history-law-followup",
    "docs/research/team-b-delivery/2026-10-18-srgg-random-key-sign-law",
)
SCHEMA = "IBME/SRGG-GATE-UNIFORM-V2-MANIFEST/1"


def _load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _file_at(name):
    if type(name) is not str or not name or "\\" in name:
        raise ValueError("noncanonical path")
    relative = Path(name)
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        raise ValueError("unsafe path")
    path = (ROOT / relative).resolve()
    if not path.is_relative_to(ROOT) or not path.is_file():
        raise ValueError("missing or escaped package file: " + name)
    return path


def _check_manifest(path):
    manifest = _load(path)
    entries = manifest.get("entries")
    if type(entries) is not dict or not entries:
        raise ValueError("manifest entries required: " + str(path))
    for name, expected in entries.items():
        if type(expected) is not dict or set(expected) != {"bytes", "sha256"}:
            raise ValueError("manifest entry structure: " + str(name))
        file_path = _file_at(name)
        if file_path.stat().st_size != expected["bytes"]:
            raise ValueError("byte length mismatch: " + str(name))
        if sha256(file_path.read_bytes()).hexdigest() != expected["sha256"]:
            raise ValueError("sha mismatch: " + str(name))
    return manifest, len(entries)


def main():
    scope = _load(PACKAGE / "scope-correction.json")
    assert scope["schema"] == "IBME/SRGG-GATE-UNIFORM-SCOPE/1"
    assert scope["v1_numeric_receipts_unchanged"] is True
    assert scope["supersedes_scope_labels_only"] is True
    assert len(scope["v1_packages"]) == 4
    assert len(scope["complete_gate_set"]) == 10
    assert scope["corrected_statement"]["original_unguarded_algorithm_certified"] is False
    assert scope["guard"]["original_backend_executes_gates"] is False
    assert scope["guard"]["proves"].startswith("conditional bounds on the modified protected")
    assert scope["security"]["security_claim"] == "none"
    assert scope["security"]["backend_admitted"] is False
    assert scope["security"]["parameters_are_formal"] is False
    assert scope["security"]["nist_security_category"] is None

    total_v1_entries = 0
    for package in scope["v1_packages"]:
        name = package["package"]
        manifest_path = ROOT / name / "MANIFEST.json"
        digest = sha256(manifest_path.read_bytes()).hexdigest()
        assert digest == package["manifest_sha256"], name
        assert package["v1_frozen_bytes_preserved"] is True
        assert package["numeric_values_changed"] is False
        _manifest, count = _check_manifest(manifest_path)
        total_v1_entries += count

    v1_record = _load(PACKAGE / "v1-verification.json")
    assert v1_record["all_passed"] is True
    assert v1_record["package_count"] == 9
    assert len(v1_record["checks"]) == 18
    assert all(check["exit_code"] == 0 for check in v1_record["checks"])
    assert {check["optimized"] for check in v1_record["checks"]} == {False, True}

    guard = _load(GUARD / "distribution-guard.json")
    assert guard["schema"] == "IBME/SRGG-PAPER-DISTRIBUTION-GUARD/1/REPORT"
    assert len(guard["rows"]) == 6
    assert len(guard["complete_gate_set"]) == 10
    assert "modified protected accept set" in guard["scope_warning"]
    assert guard["security_claim"] == "none"
    for row in guard["rows"]:
        assert row["issuance_c_gate"]["certified"] is True
        assert row["finite_key_object_guard"]["raw_and_key_within_256bit_object_guard"] is True
        assert row["guarded_backend_ran_audit_at_setup_and_sign"] is True
        assert row["original_backend_runs_audit"] is False
        assert row["security_claim"] == "none"
        assert row["backend_admitted"] is False
        assert row["parameters_are_formal"] is False
        assert row["nist_security_category"] is None

    manifest = _load(PACKAGE / "MANIFEST.json")
    assert manifest["schema"] == SCHEMA
    _manifest, v2_entries = _check_manifest(PACKAGE / "MANIFEST.json")
    assert total_v1_entries == 61, total_v1_entries

    print(json.dumps({
        "ok": True,
        "v1_packages": 4,
        "v1_entries": total_v1_entries,
        "v2_entries": v2_entries,
        "v1_checks": 18,
        "guard_rows": 6,
        "security_claim": "none",
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
