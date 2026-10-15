"""Read-only validation of public A delivery receipts and pinned source hashes.

Does not load private keys, rerun samplers, infer security, or turn missing
execution into a pass. Each historical receipt is checked at its own declared
Git source revision; LF/CRLF variants are reported explicitly.
"""

import argparse
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]


def digest(raw): return hashlib.sha256(raw).hexdigest()


@lru_cache(maxsize=None)
def blob(ref,path):
    if not re.fullmatch(r"[0-9a-f]{7,40}",ref): raise ValueError("pinned hexadecimal Git revision required")
    return subprocess.run(["git","show",ref+":"+path],cwd=ROOT,capture_output=True,check=True).stdout


def source_path(path,installed_root):
    path=path.replace("\\","/")
    if installed_root:
        prefix=installed_root.replace("\\","/").rstrip("/")+"/"
        if not path.startswith(prefix): raise ValueError("installed provider outside sole import root")
        path=path[len(prefix):]
        return "src/"+path if path.startswith("ibme/") else path
    for marker,prefix in (("/src/ibme/","src/ibme/"),("/experiments/","experiments/")):
        if marker in path: return prefix+path.split(marker,1)[1]
    raise ValueError("unrecognized project provider path")


def flags(value):
    if isinstance(value,dict):
        for key,item in value.items():
            if key in ("backend_admitted","parameters_are_formal") and item is not False:
                raise ValueError("public evidence escalated safety flags")
            if key=="security_claim" and item!="none": raise ValueError("public evidence escalated security claim")
            if key in ("r","preimages","private_random_tape","entropy_tape","root_basis","parent_basis") and isinstance(item,(str,list,dict)):
                raise ValueError("private-bearing field in public artifact")
            flags(item)
    elif isinstance(value,list):
        for item in value: flags(item)


def run(directory):
    audit=json.loads((directory/"audit.json").read_bytes())
    manifest=audit["public_files"]
    if not manifest or len(manifest)>100: raise ValueError("bounded explicit public allowlist required")
    receipts={}; variants=[]; source_checks=0
    for name,metadata in manifest.items():
        path=(directory/name).resolve()
        if not path.is_relative_to(directory.resolve()) or path.suffix not in (".json",".xml",".txt"):
            raise ValueError("public allowlist path/type")
        raw=path.read_bytes()
        if digest(raw)!=metadata["sha256"] or len(raw)!=metadata["bytes"]: raise ValueError("artifact digest/size mismatch: "+name)
        if path.suffix==".json":
            record=json.loads(raw);flags(record);receipts[name]=record
            for logical,provider in record.get("providers",{}).items():
                relative=source_path(provider["path"],record.get("installed_root"))
                if ".." in Path(relative).parts or not relative.endswith(".py"): raise ValueError("provider source path")
                expected=blob(metadata["source_revision"],relative)
                actual=provider["sha256"]
                if digest(expected)!=actual:
                    current=ROOT/relative
                    if digest(expected.replace(b"\n",b"\r\n"))==actual:
                        variants.append(dict(receipt=name,provider=logical,path=relative,variant="CRLF"))
                    elif current.is_file() and digest(current.read_bytes())==actual and current.read_bytes().replace(b"\r\n",b"\n")==expected:
                        variants.append(dict(receipt=name,provider=logical,path=relative,variant="verified checkout newline variant"))
                    else: raise ValueError("provider differs from pinned revision: "+name+" / "+relative)
                source_checks+=1
        elif path.suffix==".xml":
            cases=list(ET.fromstring(raw).iter("testcase"))
            counts=dict(tests=len(cases),failed=sum(c.find("failure") is not None or c.find("error") is not None for c in cases),
                skipped=sum(c.find("skipped") is not None for c in cases))
            if counts!=metadata["counts"]: raise ValueError("JUnit actual counts mismatch: "+name)
    matrix_checks=0
    for name in audit["matrix_receipts"]:
        report=receipts[name]
        if report["status"]!="pass" or report["security_proof_count"]!=0 or report["executed_cases"]!=6:
            raise ValueError("six real research cases required")
        if report["executed_checks"]!=202: raise ValueError("actual case check count")
        for case in report["results"]:
            checks=case["checks"]
            if case["classification"]!="research" or case["status"]!="pass" or not all(c["status"]=="pass" for c in checks):
                raise ValueError("unexecuted/TEST-ONLY/failed case")
            names={c["name"] for c in checks}
            if not {"honest_roundtrip","wrong_sender","wrong_receiver","both_wrong","restored_decrypt",
                    "forged_outer_ots_valid","inner_authentication_rejects","inner_rejection_reached_ibs"}<=names:
                raise ValueError("incomplete shared attack acceptance")
            if case["executed_checks"]!=len(checks): raise ValueError("case counts disagree")
        matrix_checks+=report["executed_checks"]
    if matrix_checks!=404: raise ValueError("combined actual check count")
    for name in audit["installed_receipts"]:
        report=receipts[name]
        if report["status"]!="passed" or not report["installed_only"] or not report["isolated_children"]:
            raise ValueError("isolated installed replay required")
        if report["new_hibe_roots"] or report["new_hibe_keys"]: raise ValueError("replay generated substitutes")
        if report["kind"]=="structured":
            if any(c["entropy_reads"] for c in report["commands"]): raise ValueError("structured replay consumed entropy")
        else:
            honest=[c for c in report["commands"] if c["name"].startswith("decrypt-")]
            if len(honest)!=1 or honest[0]["fresh_preimages"]!=256 or honest[0]["entropy_bytes"]<=0:
                raise ValueError("ABB must execute 256 fresh decryption samples")
    return dict(status="passed",public_files=len(manifest),provider_source_checks=source_checks,
        newline_variants=variants,actual_research_cases=12,actual_combination_checks=matrix_checks,
        installed_original_state_replays=len(audit["installed_receipts"]),
        private_material_loaded=False,cryptographic_security_proved=False,security_claim="none")


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("directory",type=Path);p.add_argument("--output",type=Path)
    args=p.parse_args();result=run(args.directory)
    if args.output: args.output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k!="newline_variants"}))


if __name__=="__main__":main()
