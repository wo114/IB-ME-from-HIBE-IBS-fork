"""Pure-Python delivery checks: copied files, no Git/Sage/entropy imports.

Negative controls refresh integrity hashes in selected cases. This distinguishes
semantic scope/security checks from accidental digest-only tamper detection.
"""
from __future__ import annotations

import json
from pathlib import Path
import runpy
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
BASE = Path("docs/research/team-b-delivery")
PACKAGES = {
    "guard": BASE / "2026-10-18-srgg-distribution-guard-deepseek",
    "chain": BASE / "2026-10-18-srgg-distribution-chain",
}


def _read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8", newline="\n")


def _module(root, package):
    return runpy.run_path(str(root / PACKAGES[package] / "verify_delivery.py"))


def _refresh(root, package):
    module = _module(root, package)
    path = root / PACKAGES[package] / "validation.json"
    data = _read(path)
    digest = lambda name: module["file_digest"](root / name)
    data["current_dependency_sha256"] = {
        name: digest(name) for name in sorted(module["REQUIRED_DEPENDENCIES"])}
    data["frozen_receipts"] = {
        name: digest(name) for name in sorted(module["REQUIRED_FROZEN"])}
    if package == "guard":
        data["digests"] = {name: digest(name) for name in sorted(module["REQUIRED_DIGESTS"])}
    else:
        data["delivery_file_sha256"] = {name: digest(PACKAGES[package] / name)
            for name in sorted(module["REQUIRED_DELIVERY"])}
        data["report_sha256"] = data["delivery_file_sha256"]["distribution-chain.json"]
    _write(path, data)


@pytest.fixture
def copied_delivery(tmp_path):
    files = set()
    for package, relative in PACKAGES.items():
        module = _module(ROOT, package)
        files.update(module["REQUIRED_DEPENDENCIES"])
        files.update(module["REQUIRED_FROZEN"])
        files.add((relative / "validation.json").as_posix())
        if package == "guard":
            files.update(module["REQUIRED_DIGESTS"])
        else:
            files.update((relative / name).as_posix() for name in module["REQUIRED_DELIVERY"])
    for name in files:
        destination = tmp_path / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
    # Refresh only the known file digests: source/report semantics are never
    # repaired by this helper. This also permits testing a live unstaged tree.
    for package in PACKAGES:
        _refresh(tmp_path, package)
    return tmp_path


def _run(root, package, optimized):
    command = [sys.executable]
    if optimized:
        command.append("-O")
    command.append(str(root / PACKAGES[package] / "verify_delivery.py"))
    return subprocess.run(command, cwd=root, text=True, capture_output=True,
                          check=False, timeout=30)


def _report_path(root, package):
    name = "distribution-guard.json" if package == "guard" else "distribution-chain.json"
    return root / PACKAGES[package] / name


@pytest.mark.parametrize("package", PACKAGES)
@pytest.mark.parametrize("optimized", [False, True])
def test_copied_receipts_pass_without_git(copied_delivery, package, optimized):
    assert not (copied_delivery / ".git").exists()
    result = _run(copied_delivery, package, optimized)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["ok"] is True


@pytest.mark.parametrize("package", PACKAGES)
@pytest.mark.parametrize("optimized", [False, True])
def test_crlf_working_files_match_git_normalized_digests(copied_delivery, package, optimized):
    path = copied_delivery / "experiments/research/candidates/srgg/paper_profiles.py"
    path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    result = _run(copied_delivery, package, optimized)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("package", PACKAGES)
@pytest.mark.parametrize("optimized", [False, True])
@pytest.mark.parametrize("mutation", ["source", "documentation", "digest", "missing_dependency",
                                      "extra_dependency", "predecessor"])
def test_integrity_failures_rejected(copied_delivery, package, optimized, mutation):
    relative = PACKAGES[package]
    if mutation in ("source", "documentation", "predecessor"):
        target = {
            "source": Path("experiments/research/candidates/srgg/paper_profiles.py"),
            "documentation": relative / "README_zh-CN.md",
            "predecessor": BASE / "2026-10-18-srgg-finite-chain/joint-fixed-root.json",
        }[mutation]
        path = copied_delivery / target
        path.write_bytes(path.read_bytes() + b"\n ")
    else:
        path = copied_delivery / relative / "validation.json"
        data = _read(path)
        dependencies = data["current_dependency_sha256"]
        key = next(iter(dependencies))
        if mutation == "digest":
            dependencies[key] = "0" * 64
        elif mutation == "missing_dependency":
            del dependencies[key]
        else:
            dependencies["unexpected.py"] = "0" * 64
        _write(path, data)
    result = _run(copied_delivery, package, optimized)
    assert result.returncode != 0, "integrity mutation accepted: " + mutation


@pytest.mark.parametrize("package", PACKAGES)
@pytest.mark.parametrize("optimized", [False, True])
@pytest.mark.parametrize("mutation", ["security", "row_security", "duplicate_row", "missing_row",
                                      "parameter", "scope", "history_scope", "numeric_bound", "missing_field"])
def test_semantic_failures_rejected_after_digest_refresh(copied_delivery, package, optimized, mutation):
    path = _report_path(copied_delivery, package)
    data = _read(path)
    row = data["rows"][0]
    if mutation == "security":
        data["parameters_are_formal"] = True
    elif mutation == "row_security":
        (row if package == "guard" else row["security"])["nist_security_category"] = 1
    elif mutation == "duplicate_row":
        data["rows"][1] = row
    elif mutation == "missing_row":
        data["rows"].pop()
    elif mutation == "parameter":
        (row["paper_parameters"] if package == "guard" else row["parameters"])[
            "perturbation_noise_factor" if package == "guard" else "w"] = 8
    elif mutation == "scope":
        data["scope"] = "all roots and complete timing histories certified"
    elif mutation == "history_scope":
        if package == "guard":
            row["timing_and_internal_sampling_traces_included"] = True
        else:
            data["history_scope"]["included"] = "all wall-clock timings"
    elif mutation == "numeric_bound":
        if package == "guard":
            row["full_history_tv"] = "0"
        else:
            row["accepted_root_distribution"]["TV_mu_A_mu_H_upper_exact"] = "0"
    else:
        del row["profile"]
    _write(path, data)
    _refresh(copied_delivery, package)
    result = _run(copied_delivery, package, optimized)
    assert result.returncode != 0, "semantic mutation accepted: " + mutation


@pytest.mark.parametrize("package", PACKAGES)
@pytest.mark.parametrize("optimized", [False, True])
def test_duplicate_json_keys_rejected_after_digest_refresh(copied_delivery, package, optimized):
    path = _report_path(copied_delivery, package)
    path.write_text(path.read_text(encoding="utf-8").replace("{", '{"security_claim":"none",', 1),
                    encoding="utf-8", newline="\n")
    _refresh(copied_delivery, package)
    result = _run(copied_delivery, package, optimized)
    assert result.returncode != 0
    assert "duplicate JSON key" in result.stderr


@pytest.mark.parametrize("optimized", [False, True])
def test_validation_probe_count_rejected_after_digest_refresh(copied_delivery, optimized):
    path = copied_delivery / PACKAGES["guard"] / "validation.json"
    data = _read(path)
    data["probes"]["unguarded_gate_gap"]["seeds_tried"] = 6
    _write(path, data)
    _refresh(copied_delivery, "guard")
    result = _run(copied_delivery, "guard", optimized)
    assert result.returncode != 0
    assert "validation probe summary differs" in result.stderr


@pytest.mark.parametrize("optimized", [False, True])
@pytest.mark.parametrize("mutation", ["missing", "extra", "security", "gap", "threshold", "gate"])
def test_boundary_failures_rejected_after_digest_refresh(copied_delivery, optimized, mutation):
    path = copied_delivery / PACKAGES["chain"] / "boundary-PARAM-I.json"
    if mutation == "missing":
        path.unlink()
        # Missing-file rejection itself is checked; cannot refresh absent bytes.
    elif mutation == "extra":
        shutil.copyfile(path, path.with_name("boundary-extra.json"))
    else:
        data = _read(path)
        if mutation == "security":
            data["backend_admitted"] = True
        elif mutation == "gap":
            data["witness_gap_to_C"] = -1
        elif mutation == "threshold":
            data["threshold_C_squared_exact"] = "1"
        else:
            data["all_gates"]["master_audit"] = False
        _write(path, data)
        _refresh(copied_delivery, "chain")
    result = _run(copied_delivery, "chain", optimized)
    assert result.returncode != 0, "boundary mutation accepted: " + mutation
