"""Read-only proof-followup integrity checks; no cryptographic claims or reruns.

All checks use explicit exceptions and remain enabled under python -O. The
manifest is the Git-reviewed trust anchor, not a signature on mutable evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
DELIVERY = "docs/research/team-b-delivery/2026-10-16-srgg-proof-followup"
SCHEMA = "IBME/SRGG-PROOF-FOLLOWUP-DELIVERY/1"
FLAGS = {"security_claim": "none", "backend_admitted": False,
         "parameters_are_formal": False, "nist_security_category": None}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field: "+key)
        result[key] = value
    return result


def _load(path):
    data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_object_pairs)
    if not isinstance(data, dict):
        raise ValueError("JSON object required: "+str(path.name))
    return data


def _flags(data, name):
    for field, expected in FLAGS.items():
        if field not in data or type(data[field]) is not type(expected) or data[field] != expected:
            raise ValueError("unexpected security flag: "+name+":"+field)


def _path(root, relative):
    if not isinstance(relative, str) or not relative or "\\" in relative or ":" in relative:
        raise ValueError("canonical repository-relative path required")
    parts = PurePosixPath(relative)
    if parts.is_absolute() or any(part in (".", "..") for part in relative.split("/")):
        raise ValueError("out-of-repository path rejected: "+relative)
    if parts.as_posix() != relative:
        raise ValueError("noncanonical repository-relative path: "+relative)
    candidate = (root/relative).resolve()
    if not candidate.is_relative_to(root) or not candidate.is_file():
        raise ValueError("missing or out-of-repository file: "+relative)
    return candidate


def _digest(value):
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise ValueError("lowercase SHA-256 required")
    return value


def _hash(root, relative, expected):
    expected = _digest(expected)
    actual = hashlib.sha256(_path(root, relative).read_bytes()).hexdigest()
    if actual != expected:
        raise ValueError("hash mismatch: "+relative)


def _rows(root, rows):
    if not isinstance(rows, list) or not rows:
        raise ValueError("nonempty manifest rows required")
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"}:
            raise ValueError("exact manifest row fields required")
        relative = row["path"]
        if relative in seen:
            raise ValueError("duplicate manifest entry: "+relative)
        seen.add(relative)
        path = _path(root, relative)
        if type(row["bytes"]) is not int or row["bytes"] < 0 or path.stat().st_size != row["bytes"]:
            raise ValueError("byte count mismatch: "+relative)
        _hash(root, relative, row["sha256"])
    return seen


def _field(data, pointer):
    if not isinstance(pointer, list) or not pointer or any(not isinstance(key, str) for key in pointer):
        raise ValueError("nonempty object-field pointer required")
    for key in pointer:
        if not isinstance(data, dict) or key not in data:
            raise ValueError("missing referenced report field: "+"/".join(pointer))
        data = data[key]
    return data


def _report(root, row, sealed):
    relative = row["path"]
    if relative not in sealed:
        raise ValueError("report not sealed: "+relative)
    data = _load(_path(root, relative))
    if data.get("schema") != row["schema"]:
        raise ValueError("unexpected report schema: "+relative)
    _flags(data, relative)
    count = 0
    for reference in row["hash_references"]:
        value = _field(data, reference["field"])
        if "paths" in reference:
            if not isinstance(value, dict) or set(value) != set(reference["paths"]) or not value:
                raise ValueError("source-reference set differs: "+relative)
            references = value.items()
        else:
            references = ((reference["path"], value),)
        for path, digest in references:
            if path not in sealed:
                raise ValueError("source/input reference not sealed: "+path)
            _hash(root, path, digest)
            count += 1
    for condition in row.get("required_values", []):
        actual = _field(data, condition["field"])
        expected = condition["value"]
        if type(actual) is not type(expected) or actual != expected:
            raise ValueError("report boundary differs: "+relative+":"+"/".join(condition["field"]))
    return count


def _junit(path, expected):
    root = ET.parse(path).getroot()
    if root.tag not in ("testsuites", "testsuite"):
        raise ValueError("JUnit suite root required")
    if any("hostname" in element.attrib for element in root.iter()):
        raise ValueError("public JUnit contains hostname")
    suites = [s for s in root.iter("testsuite") if not list(s.iterfind("testsuite"))]
    if not suites:
        raise ValueError("JUnit contains no leaf suites")
    actual = {}
    for field in ("tests", "failures", "errors", "skipped"):
        values = [suite.attrib.get(field) for suite in suites]
        if any(value is None or not value.isdecimal() for value in values):
            raise ValueError("explicit nonnegative JUnit totals required")
        actual[field] = sum(int(value) for value in values)
        if type(expected.get(field)) is not int or actual[field] != expected[field]:
            raise ValueError("JUnit totals disagree: "+field)
    if actual["tests"] <= 0 or any(actual[k] for k in ("failures", "errors", "skipped")):
        raise ValueError("required JUnit suite did not pass completely")
    if len(list(root.iter("testcase"))) != actual["tests"]:
        raise ValueError("JUnit testcase count differs from totals")
    if any(list(root.iter(tag)) for tag in ("failure", "error", "skipped")):
        raise ValueError("JUnit contains unsuccessful testcase")
    return actual["tests"]


def verify(*, root=ROOT, delivery=DELIVERY):
    root = Path(root).resolve()
    manifest_path = _path(root, delivery+"/MANIFEST.json")
    manifest = _load(manifest_path)
    if manifest.get("schema") != SCHEMA:
        raise ValueError("known proof-followup manifest required")
    _flags(manifest, "manifest")
    sealed = _rows(root, manifest["files"]+manifest["unchanged_dependencies"])
    package = manifest_path.parent
    actual_package_files = {p.relative_to(root).as_posix() for p in package.rglob("*")
                            if p.is_file() and p != manifest_path}
    if not actual_package_files <= sealed:
        raise ValueError("unsealed file present in proof-followup package")
    frozen_count = 0
    for row in manifest["frozen_manifests"]:
        if row["path"] not in sealed:
            raise ValueError("frozen manifest not sealed")
        _hash(root, row["path"], row["sha256"])
        frozen = _load(_path(root, row["path"]))
        dependencies = frozen.get("unchanged_dependencies", frozen.get("unchanged_runtime_dependencies", []))
        frozen_count += len(_rows(root, frozen["files"]+dependencies))
    if not manifest["frozen_manifests"]:
        raise ValueError("frozen baseline manifest required")
    reports = manifest["reports"]
    if not isinstance(reports, list) or not reports or len({r["path"] for r in reports}) != len(reports):
        raise ValueError("nonempty unique report set required")
    references = sum(_report(root, row, sealed) for row in reports)
    validation_rel = delivery+"/validation.json"
    if validation_rel not in sealed:
        raise ValueError("validation receipt not sealed")
    validation = _load(_path(root, validation_rel))
    if validation.get("schema") != "IBME/SRGG-PROOF-FOLLOWUP-VALIDATION/1":
        raise ValueError("known proof-followup validation required")
    _flags(validation, "validation")
    suites = validation["required_test_suites"]
    if not isinstance(suites, dict) or not suites:
        raise ValueError("required test suite set is empty")
    cases = 0
    for name, expected in suites.items():
        path = delivery+"/"+expected["receipt"]
        if path not in sealed:
            raise ValueError("JUnit receipt not sealed: "+name)
        cases += _junit(_path(root, path), expected)
    for row in validation["copied_evidence"]:
        path = delivery+"/"+row["receipt"]
        if path not in sealed:
            raise ValueError("copied evidence not sealed")
        digest = _digest(row["original_sha256"])
        if row["transformation"] == "byte-copy":
            _hash(root, path, digest)
        elif row["transformation"] != "remove JUnit hostname; XML serialization and LF":
            raise ValueError("unknown evidence transformation")
    return {"verified": True, "manifest_files_checked": len(sealed),
        "frozen_manifest_file_entries_checked": frozen_count,
        "source_or_input_references_checked": references,
        "test_cases_in_receipts_including_overlapping_suites": cases,
        "meaning": "Git-reviewed manifest integrity and recorded receipt consistency; no tests rerun",
        **FLAGS}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--delivery", default=DELIVERY)
    args = parser.parse_args()
    print(json.dumps(verify(root=args.root, delivery=args.delivery), indent=2))
