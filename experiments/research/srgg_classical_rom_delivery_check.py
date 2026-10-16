"""Read-only integrity check for the SRGG classical ideal-XOF follow-up."""
from __future__ import annotations

import json
from pathlib import Path
import xml.etree.ElementTree as ET

from srgg_reduction_delivery_check import _hash, _manifest, _path, verify as verify_base


ROOT = Path(__file__).resolve().parents[2]
DELIVERY = ROOT/"docs/research/team-b-delivery/2026-10-16-srgg-classical-rom"


def verify():
    manifest = json.loads((DELIVERY/"MANIFEST.json").read_text(encoding="utf-8"))
    if manifest.get("schema") != "IBME/SRGG-CLASSICAL-ROM-DELIVERY-MANIFEST/1":
        raise ValueError("known classical-ROM manifest required")
    checked = _manifest(manifest)
    _hash(manifest["frozen_base_manifest"], manifest["frozen_base_manifest_sha256"])
    base = verify_base()
    references = 0
    for filename in manifest["generated_reports"]:
        data = json.loads((DELIVERY/filename).read_text(encoding="utf-8"))
        for relative, digest in data["source_sha256"].items():
            _hash(relative, digest)
            references += 1
        if "input_path" in data:
            _hash(data["input_path"], data["input_sha256"])
            references += 1
        for field, expected in (("security_claim", "none"), ("backend_admitted", False),
                                ("parameters_are_formal", False), ("nist_security_category", None)):
            if field not in data or type(data[field]) is not type(expected) or data[field] != expected:
                raise ValueError("unexpected security flag: "+filename+":"+field)
    validation = json.loads((DELIVERY/"validation.json").read_text(encoding="utf-8"))
    cases = 0
    for name, expected in validation["test_suites"].items():
        receipt = _path(DELIVERY.relative_to(ROOT).as_posix()+"/"+expected["receipt"])
        root = ET.parse(receipt).getroot()
        suites = [root] if root.tag == "testsuite" else list(root)
        actual = {key: sum(int(s.attrib.get(key, "0")) for s in suites)
                  for key in ("tests", "failures", "errors", "skipped")}
        if actual != {key: expected[key] for key in actual}:
            raise ValueError("JUnit totals disagree: "+name)
        if actual["tests"] <= 0 or any(actual[key] for key in ("failures", "errors", "skipped")):
            raise ValueError("required suite did not pass completely: "+name)
        if any("hostname" in s.attrib for s in suites):
            raise ValueError("public receipt contains hostname: "+name)
        cases += actual["tests"]
    return {"verified": True, "manifest_files_checked": checked,
        "source_or_input_references_checked": references,
        "previous_reduction_delivery_verified": base["verified"],
        "previous_reduction_files_checked": base["manifest_files_checked"],
        "frozen_bridge_files_checked": base["frozen_base_files_checked"],
        "test_cases_in_receipts_including_overlapping_suites": cases,
        "meaning": "artifact hashes and receipt consistency; tests not rerun",
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None}


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
