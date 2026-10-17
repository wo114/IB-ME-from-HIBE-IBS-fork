"""Delivery integrity failures must still reject with Python assertions disabled."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from experiments.research import srgg_proof_followup_delivery_check as check


def _json(path, data):
    path.write_text(json.dumps(data, indent=2)+"\n", encoding="utf-8")


def _row(root, relative):
    value = (root/relative).read_bytes()
    return {"path": relative, "bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}


@pytest.fixture
def artifact(tmp_path):
    package = tmp_path/check.DELIVERY
    package.mkdir(parents=True)
    (tmp_path/"source.py").write_text("# frozen fixture\n", encoding="utf-8")
    (tmp_path/"baseline.txt").write_text("baseline\n", encoding="utf-8")
    _json(tmp_path/"baseline.json", {"files": [_row(tmp_path, "baseline.txt")],
                                   "unchanged_dependencies": []})
    _json(package/"report.json", {"schema": "FIXTURE/1", **check.FLAGS,
        "source_sha256": {"source.py": _row(tmp_path, "source.py")["sha256"]},
        "input_sha256": _row(tmp_path, "baseline.txt")["sha256"],
        "actual_entropy_bytes": 0})
    (package/"tests.junit.xml").write_text(
        '<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0">'
        '<testcase classname="fixture" name="pass" />'
        '</testsuite></testsuites>\n', encoding="utf-8")
    _json(package/"validation.json", {
        "schema": "IBME/SRGG-PROOF-FOLLOWUP-VALIDATION/1", **check.FLAGS,
        "required_test_suites": {"fixture": {"receipt": "tests.junit.xml",
            "tests": 1, "failures": 0, "errors": 0, "skipped": 0}},
        "copied_evidence": []})
    manifest = {"schema": check.SCHEMA, **check.FLAGS,
        "files": [_row(tmp_path, check.DELIVERY+"/"+name)
                  for name in ("report.json", "validation.json", "tests.junit.xml")],
        "unchanged_dependencies": [_row(tmp_path, name)
            for name in ("source.py", "baseline.txt", "baseline.json")],
        "frozen_manifests": [{"path": "baseline.json",
            "sha256": _row(tmp_path, "baseline.json")["sha256"]}],
        "reports": [{"path": check.DELIVERY+"/report.json", "schema": "FIXTURE/1",
            "hash_references": [
                {"field": ["source_sha256"], "paths": ["source.py"]},
                {"field": ["input_sha256"], "path": "baseline.txt"}],
            "required_values": [{"field": ["actual_entropy_bytes"], "value": 0}]}]}
    _json(package/"MANIFEST.json", manifest)
    return tmp_path


def _refresh(root, filename):
    package = root/check.DELIVERY
    path = package/"MANIFEST.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    relative = check.DELIVERY+"/"+filename
    for i, row in enumerate(manifest["files"]):
        if row["path"] == relative:
            manifest["files"][i] = _row(root, relative)
    _json(path, manifest)


def _fault(root, fault):
    package = root/check.DELIVERY
    if fault == "hash":
        (root/"source.py").write_text("# changed\n", encoding="utf-8")
    elif fault in ("source-reference", "input-reference", "security", "boundary", "source-set"):
        path = package/"report.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        if fault == "source-reference":
            data["source_sha256"]["source.py"] = "0"*64
        elif fault == "input-reference":
            data["input_sha256"] = "0"*64
        elif fault == "security":
            data["backend_admitted"] = 0  # equality with False must not hide wrong type
        elif fault == "boundary":
            data["actual_entropy_bytes"] = 1
        else:
            data["source_sha256"] = {}
        _json(path, data)
        _refresh(root, "report.json")
    elif fault in ("junit-totals", "junit-hostname", "junit-cases", "junit-failure"):
        path = package/"tests.junit.xml"
        text = path.read_text(encoding="utf-8")
        if fault == "junit-totals":
            text = text.replace('tests="1"', 'tests="2"')
        elif fault == "junit-hostname":
            text = text.replace('<testsuite tests=', '<testsuite hostname="fixture-host" tests=')
        elif fault == "junit-cases":
            text = text.replace('<testcase classname="fixture" name="pass" />', '')
        else:
            text = text.replace('<testcase classname="fixture" name="pass" />',
                '<testcase classname="fixture" name="pass"><failure /></testcase>')
        path.write_text(text, encoding="utf-8")
        _refresh(root, "tests.junit.xml")
    elif fault == "extra-package-file":
        (package/"unsealed.txt").write_text("unsealed", encoding="utf-8")
    elif fault == "frozen-dependency":
        (root/"baseline.txt").write_text("changed baseline\n", encoding="utf-8")
    else:
        raise ValueError("unknown test fixture fault")


def test_explicit_integrity_verification(artifact):
    result = check.verify(root=artifact)
    assert result["verified"] is True
    assert result["source_or_input_references_checked"] == 2
    assert result["test_cases_in_receipts_including_overlapping_suites"] == 1
    assert {k: result[k] for k in check.FLAGS} == check.FLAGS


@pytest.mark.parametrize("fault", ("hash", "source-reference", "input-reference", "security",
    "boundary", "source-set", "junit-totals", "junit-hostname", "junit-cases", "junit-failure",
    "extra-package-file", "frozen-dependency"))
def test_semantic_failure_rejects_even_when_changed_report_is_rehashed(artifact, fault):
    _fault(artifact, fault)
    with pytest.raises(ValueError):
        check.verify(root=artifact)


@pytest.mark.parametrize("optimized", (False, True))
@pytest.mark.parametrize("fault", (None, "hash", "source-reference", "input-reference",
                                  "security", "junit-totals", "junit-hostname"))
def test_cli_normal_and_optimized_validation(artifact, optimized, fault):
    if fault:
        _fault(artifact, fault)
    command = [sys.executable]+(["-O"] if optimized else [])+[
        str(Path(check.__file__).resolve()), "--root", str(artifact)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    assert (result.returncode == 0) is (fault is None)
    if fault is None:
        assert json.loads(result.stdout)["verified"] is True
    else:
        assert "ValueError" in result.stderr


@pytest.mark.parametrize("field,value", (("security_claim", "secure"),
    ("backend_admitted", True), ("parameters_are_formal", True),
    ("nist_security_category", 1)))
def test_all_security_flags_reject_escalation(artifact, field, value):
    path = artifact/check.DELIVERY/"validation.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data[field] = value
    _json(path, data)
    _refresh(artifact, "validation.json")
    with pytest.raises(ValueError, match="security flag"):
        check.verify(root=artifact)


@pytest.mark.parametrize("relative", ("../outside", "/outside", "a/../source.py",
                                     "source.py/", "a//source.py", "C:/source.py", "a\\b"))
def test_paths_cannot_escape_or_alias(artifact, relative):
    with pytest.raises(ValueError):
        check._path(artifact, relative)


def test_duplicate_json_field_rejects(artifact):
    path = artifact/check.DELIVERY/"MANIFEST.json"
    path.write_text('{"schema":"one","schema":"two"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON"):
        check.verify(root=artifact)


def test_public_copy_origin_digest_is_checked(artifact):
    path = artifact/check.DELIVERY/"validation.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["copied_evidence"] = [{"receipt": "report.json", "original_sha256": "0"*64,
                                 "transformation": "byte-copy"}]
    _json(path, data)
    _refresh(artifact, "validation.json")
    with pytest.raises(ValueError, match="hash mismatch"):
        check.verify(root=artifact)
