"""Audit the step-23 evidence bundle; never grants security admission."""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

from ibme.ibs.luo_module_profiles import c64b_params

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "docs/research/2026-10-11-luo-c64b-handoff"
CODE = (
    "src/ibme/ibs/luo_module_profiles.py", "src/ibme/protocol/luo_hybrid.py",
    "experiments/research/audit_luo_c64b_selection.py",
    "experiments/research/luo_cross_version.py", "experiments/research/luo_assembly_handoff.py",
    "experiments/research/audit_luo_c64b_delivery.py",
    "tests/test_luo_c64b_profile.py", "tests/test_luo_cross_version_harness.py",
)


def require(value, code):
    if not value:
        raise ValueError(code)


def read(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)


def hashes():
    paths = [p for p in BASE.rglob("*") if p.is_file() and p.name != "MANIFEST.json"]
    paths += [ROOT / name for name in CODE]
    return {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(paths)}


def audit():
    manifest = read(BASE / "MANIFEST.json")
    require(manifest["files"] == hashes(), "manifest content/coverage mismatch")
    profile = read(BASE / "profile.json")
    require(profile["params"] == asdict(c64b_params()), "profile differs from executable factory")
    require(profile["availability_example_budget"]["classical_fresh_oracle_queries"] == 2**64,
            "rounded large integer")
    require(profile["security_claim"] == "none" and profile["backend_admitted"] is False
            and profile["parameters_are_formal"] is False, "unexpected admission")
    ev = BASE / "evidence"
    for name in ("parameter-decision.json", "parameter-decision-optimized.json"):
        d = read(ev / name)
        require(len(d["predicates"]) == 28 and all(v is True for v in d["predicates"].values())
                and d["failed_predicates"] == [], "parameter predicates not all passed")
    negative = read(ev / "parameter-negative-control.json")
    require(negative["failed_predicates"] == ["budget_exact_integer_not_js_number"],
            "negative control did not reject the known corruption")
    for name, count in (("regression.xml", 122), ("cross-version-harness.xml", 19)):
        suites = list(ET.parse(ev / name).getroot().iter("testsuite"))
        require(sum(int(s.get("tests", "0")) for s in suites) == count
                and all(int(s.get(k, "0")) == 0 for s in suites
                        for k in ("failures", "errors", "skipped")), "regression count/status mismatch")
    cross = read(ev / "cross-version-current.json")
    require(cross["status"] == "functional_wire_compatible" and cross["independent_signatures"] == 1
            and cross["selected_source_sets_identical"] is True, "wrong wire compatibility scope")
    require(len(cross["contexts"]) == 3 and all(len(c["checks"]) == 37
            and all(x["result"] in ("pass", "rejected") for x in c["checks"])
            for c in cross["contexts"]), "wire checks incomplete")
    drift = read(ev / "cross-version.json")
    require(drift["status"] == "failed_closed" and drift["failure"]["code"] == "head_pin_mismatch",
            "historical head drift not preserved")
    assembly = read(ev / "assembly-final.json")
    require(assembly["status"] == "functional_teaching_assembly_pass"
            and len(set(assembly["checks"])) == len(assembly["checks"]) == 25
            and assembly["signature_bytes"] == 16383 and assembly["outer_payload_bytes"] == 20415
            and assembly["application_bytes"] == 3924 and assembly["private_artifacts_saved"] is False,
            "assembly evidence mismatch")
    require(assembly["profile_sha256"] == hashlib.sha256((BASE / "profile.json").read_bytes()).hexdigest(),
            "tested profile snapshot differs")
    require(assembly["target_head"] == cross["sources"]["new"]["head"] ==
            "0bf0855464a9902ad95c91ea5bdfb4d12e78f5b9", "mixed assembly source versions")
    return dict(status="evidence_consistent", manifest_files=len(manifest["files"]),
                pytest_passed=[122, 19], parameter_predicates=28, isolated_wire_checks=111,
                assembly_checks=25, security_claim="none", backend_admitted=False,
                parameters_are_formal=False)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--refresh-manifest", action="store_true", help="Explicit packaging step; otherwise read-only")
    args = ap.parse_args()
    if args.refresh_manifest:
        (BASE / "MANIFEST.json").write_text(json.dumps(dict(schema="IBME/LUO-C64B-HANDOFF/1", files=hashes()),
            ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(audit(), ensure_ascii=False, indent=2))
