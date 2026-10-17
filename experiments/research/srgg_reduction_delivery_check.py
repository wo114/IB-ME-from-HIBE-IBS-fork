"""Read-only verification of the SRGG conditional strong-reduction delivery."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
DELIVERY = ROOT/"docs/research/team-b-delivery/2026-10-16-srgg-reduction"


def _path(relative):
    if not isinstance(relative, str):
        raise ValueError("repository-relative text path required")
    path = (ROOT/relative).resolve()
    if not path.is_relative_to(ROOT) or not path.is_file():
        raise ValueError("missing or out-of-repository file: "+relative)
    return path


def _hash(relative, digest):
    if not isinstance(digest, str) or len(digest) != 64:
        raise ValueError("SHA-256 required: "+relative)
    if hashlib.sha256(_path(relative).read_bytes()).hexdigest() != digest:
        raise ValueError("hash mismatch: "+relative)


def _manifest(manifest):
    seen = set()
    for row in manifest["files"]+manifest["unchanged_dependencies"]:
        relative = row["path"]
        if relative in seen:
            raise ValueError("duplicate manifest entry: "+relative)
        seen.add(relative)
        path = _path(relative)
        if path.stat().st_size != row["bytes"]:
            raise ValueError("byte count mismatch: "+relative)
        _hash(relative, row["sha256"])
    return len(seen)


def verify():
    manifest = json.loads((DELIVERY/"MANIFEST.json").read_text(encoding="utf-8"))
    if manifest.get("schema") != "IBME/SRGG-REDUCTION-DELIVERY-MANIFEST/1":
        raise ValueError("known reduction manifest schema required")
    checked = _manifest(manifest)
    # Recheck the frozen base without rewriting its receipts or manifest.
    base = json.loads(_path(manifest["frozen_base_manifest"]).read_text(encoding="utf-8"))
    base_checked = _manifest({"files": base["files"],
        "unchanged_dependencies": base["unchanged_runtime_dependencies"]})
    references = 0
    for filename, module in (
        ("native-sig.json", "native_sig.py"),
        ("strong-structure.json", "strong_structure.py"),
        ("classical-cost.json", "classical_cost.py"),
    ):
        data = json.loads((DELIVERY/filename).read_text(encoding="utf-8"))
        sources = data["source_sha256"]
        if isinstance(sources, str):
            sources = {"experiments/research/candidates/srgg/"+module: sources}
        for relative, digest in sources.items():
            _hash(relative, digest)
            references += 1
        if "input_path" in data:
            _hash(data["input_path"], data["input_sha256"])
            references += 1
        for field, value in (("security_claim", "none"), ("backend_admitted", False),
                             ("parameters_are_formal", False)):
            if type(data.get(field)) is not type(value) or data[field] != value:
                raise ValueError("unexpected security claim: "+filename+":"+field)
    validation = json.loads((DELIVERY/"validation.json").read_text(encoding="utf-8"))
    test_cases = 0
    for name, expected in validation["test_suites"].items():
        tree = ET.parse(DELIVERY/expected["receipt"])
        suites = [tree.getroot()] if tree.getroot().tag == "testsuite" else list(tree.getroot())
        actual = {key: sum(int(s.attrib.get(key, "0")) for s in suites)
                  for key in ("tests", "failures", "errors", "skipped")}
        if any(actual[key] != expected[key] for key in actual):
            raise ValueError("JUnit statistics disagree: "+name)
        if any(actual[key] for key in ("failures", "errors", "skipped")):
            raise ValueError("required test suite unsuccessful: "+name)
        if any("hostname" in s.attrib for s in suites):
            raise ValueError("public JUnit hostname remains: "+name)
        test_cases += actual["tests"]
    return {"verified": True, "manifest_files_checked": checked,
        "meaning": "artifact integrity and receipt consistency only; tests not rerun",
        "frozen_base_files_checked": base_checked,
        "source_or_input_references_checked": references,
        "test_cases_in_receipts_including_overlapping_suites": test_cases,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None}


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
