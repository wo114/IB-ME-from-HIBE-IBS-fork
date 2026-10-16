"""Read-only check of structured SRGG service artifacts, not a test rerun."""
from __future__ import annotations

import json
from pathlib import Path
import xml.etree.ElementTree as ET

from srgg_reduction_delivery_check import _hash, _manifest
from srgg_classical_rom_delivery_check import verify as verify_classical


ROOT = Path(__file__).resolve().parents[2]
DELIVERY = ROOT/"docs/research/team-b-delivery/2026-10-16-srgg-structured-service"


def verify():
    manifest = json.loads((DELIVERY/"MANIFEST.json").read_text(encoding="utf-8"))
    if manifest.get("schema") != "IBME/SRGG-STRUCTURED-SERVICE-DELIVERY/1":
        raise ValueError("known structured service manifest required")
    checked = _manifest(manifest)
    _hash(manifest["frozen_base_manifest"], manifest["frozen_base_manifest_sha256"])
    classical = verify_classical()
    references = 0
    for filename in manifest["lifecycle_reports"]:
        report = json.loads((DELIVERY/filename).read_text(encoding="utf-8"))
        if report.get("completed") is not True or not report["checks"] or not all(report["checks"].values()):
            raise ValueError("lifecycle did not pass its recorded checks: "+filename)
        if report.get("roots_requested") != 1 or report.get("root_reselection") is not False:
            raise ValueError("lifecycle root selection differs")
        if report.get("key_reselection") is not False or report.get("production_randomness") is not True:
            raise ValueError("lifecycle randomness differs")
        for path, digest in report["source_sha256"].items():
            _hash(path, digest)
            references += 1
        for key, value in (("security_claim", "none"), ("backend_admitted", False),
                           ("parameters_are_formal", False), ("nist_security_category", None)):
            if key not in report or type(report[key]) is not type(value) or report[key] != value:
                raise ValueError("unexpected lifecycle security claim")
    validation = json.loads((DELIVERY/"validation.json").read_text(encoding="utf-8"))
    for name, expected in validation["required_test_suites"].items():
        root = ET.parse(DELIVERY/expected["receipt"]).getroot()
        suites = [root] if root.tag == "testsuite" else list(root)
        actual = {key: sum(int(s.attrib.get(key, "0")) for s in suites)
                  for key in ("tests", "failures", "errors", "skipped")}
        if actual != {key: expected[key] for key in actual} or actual["tests"] <= 0:
            raise ValueError("JUnit counts differ: "+name)
        if any(actual[key] for key in ("failures", "errors", "skipped")):
            raise ValueError("required suite did not pass: "+name)
        if any("hostname" in element.attrib for element in root.iter()):
            raise ValueError("hostname remains in public receipt")
    return {"verified": True, "manifest_files_checked": checked,
        "lifecycle_source_references_checked": references,
        "frozen_classical_delivery_verified": classical["verified"],
        "meaning": "artifact integrity and recorded consistency; no tests rerun",
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None}


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
