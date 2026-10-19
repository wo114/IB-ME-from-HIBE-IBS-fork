"""Offline verification of the fixed-source publication review; no private state."""
from collections import Counter
from hashlib import sha1, sha256
import json
from pathlib import Path, PurePosixPath
import runpy
import xml.etree.ElementTree as ET

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
SOURCE_HEAD="32d0c0bd8d9c75efc1464cbbf91d665ba3574f52"
ORIGINAL=HERE.parent/"2026-10-19-sageloli-ring-target"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe_path(relative):
    path=PurePosixPath(relative)
    require(not path.is_absolute() and ".." not in path.parts and ":" not in relative,
            "unsafe source inventory path")
    return ROOT/path


def cases(path):
    rows=list(ET.parse(path).getroot().iter("testcase"))
    require(rows and all(not any(row.find(tag) is not None for tag in
                ("failure","error","skipped")) for row in rows), "nonpassing JUnit")
    identities={(row.get("classname"),row.get("name")) for row in rows}
    require(len(identities)==len(rows), "duplicate test identity")
    return identities


def main():
    manifest=json.loads((HERE/"MANIFEST.json").read_text())
    for relative, expected in manifest["files"].items():
        path=safe_path(relative)
        require(path.is_file() and not path.is_symlink(), "missing review artifact")
        require(sha256(path.read_bytes()).hexdigest()==expected, "review artifact hash mismatch")
    report=json.loads((HERE/"verification.json").read_text())
    require(report["status"]=="passed" and report["head"]==SOURCE_HEAD and report["pr"]==59,
            "review source binding changed")
    inventory=report["inventory"]
    require(len(inventory)==37 and len({item["path"] for item in inventory})==37,
            "incomplete source upload inventory")
    for item in inventory:
        path=safe_path(item["path"])
        require(path.is_file() and not path.is_symlink(), "missing source upload")
        data=path.read_bytes()
        require(len(data)==item["bytes"] and sha256(data).hexdigest()==item["sha256"],
                "source hash or length changed: "+item["path"])
        require(sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()==item["remote_git_blob"],
                "source differs from reviewed remote Git blob")
    status=json.loads((HERE/"ci-status.json").read_text())
    require(status["headRefOid"]==SOURCE_HEAD, "CI source binding changed")
    checks=status["statusCheckRollup"]
    require(all(check["status"]=="COMPLETED" for check in checks), "unfinished historical CI")
    require(dict(Counter(check["conclusion"] for check in checks))=={"SUCCESS":23,"SKIPPED":1},
            "historical CI result changed")
    require([check["name"] for check in checks if check["conclusion"]=="SKIPPED"]==["strict-security"],
            "unexpected skipped CI")
    selected=[]
    for kind in ("sis","rsis"):
        receipt=json.loads((HERE/("ci-"+kind+".json")).read_text())
        require(receipt["status"]=="passed" and receipt["exit_code"]==0 and
                receipt["counts"]==dict(tests=165,passed=165,failed=0,errors=0,skipped=0,xfailed=0),
                "primitive CI receipt changed")
        for relative, expected in receipt["source_sha256"].items():
            require(sha256(safe_path(relative).read_bytes()).hexdigest()==expected, "CI source hash changed")
        identities=cases(HERE/("ci-"+kind+".xml"))
        require(len(identities)==165, "primitive CI count changed")
        selected.append(identities)
    clean=cases(HERE/"clean-native.xml")
    original=cases(ORIGINAL/"evidence/tests.xml")
    require(selected[0]==selected[1] and len(clean)==35 and len(original)==180 and
            selected[0]|clean==original, "test union does not cover published tests")
    runpy.run_path(str(ORIGINAL/"verify.py"),run_name="__main__")
    print(json.dumps(dict(status="passed",review_files=len(manifest["files"]),
        required_source_files=37,ci_success=23,expected_skipped=1,unique_tests=180,
        source_head=SOURCE_HEAD,private_state_read=False)))


if __name__=="__main__":
    main()
