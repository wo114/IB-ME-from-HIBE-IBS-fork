"""Read-only hash/counter checks for the scoped Yu delivery, no crypto rerun."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import xml.etree.ElementTree as ET


def check(repo):
    repo=repo.resolve()
    folder=repo/"docs/research/team-b-delivery/2026-10-15-yu-backend"
    def load(name): return json.loads((folder/name).read_text(encoding="utf-8"))
    def digest(relative):
        path=PurePosixPath(relative)
        if path.is_absolute() or ".." in path.parts or "\\" in relative:
            raise ValueError("unsafe delivery path")
        target=repo.joinpath(*path.parts).resolve()
        if not target.is_relative_to(repo) or not target.is_file(): raise ValueError("missing/escaped file")
        return hashlib.sha256(target.read_bytes()).hexdigest()
    manifest=load("MANIFEST.json")
    for name,expected in manifest["files_sha256"].items():
        if digest(name)!=expected: raise ValueError("manifest hash mismatch: "+name)
    checked=0
    for name in ("ci.json","qualification.json","lifecycle.json"):
        data=load(name)
        for path,expected in data["source_sha256"].items():
            if digest(path)!=expected: raise ValueError(name+" source hash mismatch: "+path)
            checked+=1
    installed=load("installed.json")
    for provider in installed["source_providers"].values():
        path=provider["file"]
        source="src/"+path if path.startswith("ibme/") else path
        if digest(source)!=provider["sha256"]: raise ValueError("installed source mismatch: "+source)
        checked+=1
    ci=load("ci.json"); cases=list(ET.parse(folder/"ci.xml").iter("testcase"))
    if len(cases)!=ci["counts"]["passed"] or ci["status"]!="passed": raise ValueError("CI count mismatch")
    if any(c.find(tag) is not None for c in cases for tag in ("failure","error","skipped")):
        raise ValueError("CI contains non-passing cases")
    common=list(ET.parse(folder/"common.xml").iter("testcase"))
    if len(common)!=57 or any(c.find(t) is not None for c in common for t in ("failure","error","skipped")):
        raise ValueError("common regression mismatch")
    q=load("qualification.json"); life=load("lifecycle.json")
    if len(q["cases"])!=15 or sum(x["semantic_comparisons"] for x in q["cases"])!=45:
        raise ValueError("qualification counts")
    if sum(x["homomorphism_checks"] for x in q["cases"])!=14: raise ValueError("homomorphism counts")
    if not life["all_requested_attempts_completed"] or life["counts"]["signatures"]!=18:
        raise ValueError("final lifecycle evidence mismatch")
    if life["counts"]["public_forgery_accepts"]!=3: raise ValueError("lost counterexample")
    if installed["status"]!="passed" or installed["checks"]!=15: raise ValueError("installed checks")
    history=load("historical-lifecycle-before-hardening.json")
    if history["all_requested_attempts_completed"] or history["attempts"][2]["status"]!="failed":
        raise ValueError("lost historical failed attempt")
    for value in (q,life,installed,history):
        if (value["security_claim"]!="none" or value["backend_admitted"] is not False
                or value["parameters_are_formal"] is not False): raise ValueError("claim escalation")
    return dict(status="passed",manifest_files=len(manifest["files_sha256"]),
        source_checks=checked,yu_tests=len(cases),common_tests=len(common),
        historical_source_hashes="retained, not equated to repaired checkout",
        scope="read-only packaging consistency, NOT rerun/security proof")


if __name__=="__main__":
    print(json.dumps(check(Path(__file__).resolve().parents[2]),indent=2))
