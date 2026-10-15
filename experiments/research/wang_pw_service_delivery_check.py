"""Read-only consistency checks for the Wang--PW fixed-issuer handoff."""

import hashlib
import json
from pathlib import Path, PurePosixPath
import xml.etree.ElementTree as ET


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _source_variant(raw, relative, expected):
    """Keep receipt byte hashes intact; report Python checkout newline variants."""
    observed = hashlib.sha256(raw).hexdigest()
    if observed == expected:
        return None
    _require(PurePosixPath(relative).suffix == ".py" and b"\r\n" in raw
             and hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest() == expected,
             "source mismatch: " + relative)
    return dict(path=relative, observed_sha256=observed, evidence_sha256=expected,
                conversion="Python source CRLF to LF only")


def check(repo):
    repo = Path(repo).resolve()
    folder = repo / "docs/research/team-b-delivery/2026-10-15-wang-pw-service"

    def load(name):
        return json.loads((folder / name).read_text(encoding="utf-8"))

    def content(relative):
        name = PurePosixPath(relative)
        _require(not name.is_absolute() and ".." not in name.parts and "\\" not in relative,
                 "unsafe evidence path")
        path = repo.joinpath(*name.parts).resolve()
        _require(path.is_relative_to(repo) and path.is_file(), "missing/escaped evidence file")
        return path.read_bytes()

    def digest(relative):
        return hashlib.sha256(content(relative)).hexdigest()

    variants = {}

    def check_source(relative, expected):
        variant = _source_variant(content(relative), relative, expected)
        if variant is not None:
            variants[relative] = variant

    manifest = load("MANIFEST.json")
    _require(bool(manifest["files_sha256"]), "empty delivery manifest")
    for name, expected in manifest["files_sha256"].items():
        _require(digest(name) == expected, "manifest mismatch: " + name)

    ci = load("ci.json")
    cases = list(ET.parse(folder / "ci.xml").iter("testcase"))
    _require(ci["status"] == "passed" and ci["exit_code"] == 0, "CI did not pass")
    _require(len(cases) == ci["counts"]["tests"] == ci["counts"]["passed"] > 0,
             "CI count mismatch")
    _require(not any(c.find(tag) is not None for c in cases for tag in ("failure", "error", "skipped")),
             "CI includes failure/error/skip")
    _require("tests/test_wang_pw_service.py" in ci["files"], "CI omitted issuer tests")
    _require(ci["security_claim"] == "none" and ci["combination_accepted"] is False,
             "CI security claim escalated")
    checked = 0
    for name in ("ci.json", "lifecycle.json", "installed.json"):
        data = load(name)
        for source, expected in data["source_sha256"].items():
            relative = "src/" + source if source.startswith("ibme/") else source
            check_source(relative, expected)
            checked += 1
    lifecycle, installed = load("lifecycle.json"), load("installed.json")
    for data in (lifecycle, installed):
        _require(data["security_claim"] == "none" and data["backend_admitted"] is False
                 and data["parameters_are_formal"] is False, "claim escalation")
        _require(data["all_requested_attempts_completed"] is True, "unfinished real lifecycle")
        attempts = len(data["attempts"])
        counts = data["counts"]
        users = attempts * len(data["identity_bytes"])
        signatures = users * len(data["message_bytes"])
        _require(counts["roots"] == attempts and counts["users"] == users, "real issuance counts")
        _require(counts["signatures"] == counts["verifications"] == signatures, "real signature counts")
        _require(counts["cached_recoveries"] == counts["restored_key_signatures"]
                 == counts["fresh_process_signatures"] == users, "recovery counts")
        _require(counts["public_forgery_accepts"] == attempts, "lost debug forgery negative control")
        _require("src/ibme/ibs/wang_pw_service.py" in data["source_sha256"]
                 or "ibme/ibs/wang_pw_service.py" in data["source_sha256"], "missing service provenance")
    _require(installed["status"] == "passed" and bool(installed["source_providers"]),
             "missing installed execution")
    for provider in installed["source_providers"].values():
        source = provider["file"]
        relative = "src/" + source if source.startswith("ibme/") else source
        check_source(relative, provider["sha256"])
        checked += 1
    return dict(status="passed", manifest_files=len(manifest["files_sha256"]),
        source_checks=checked, wang_pw_tests=len(cases),
        real_source_roots=lifecycle["counts"]["roots"],
        installed_providers=len(installed["source_providers"]),
        source_line_ending_variants=[variants[name] for name in sorted(variants)],
        scope="Read-only artifact consistency; no crypto rerun, remote CI or security proof")


if __name__ == "__main__":
    print(json.dumps(check(Path(__file__).resolve().parents[2]), indent=2))
