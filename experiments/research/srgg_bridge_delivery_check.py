"""Read-only hash and receipt verification of the SRGG bridge delivery."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DELIVERY = ROOT/"docs/research/team-b-delivery/2026-10-16-srgg-bridge"


def _path(relative):
    if not isinstance(relative,str):
        raise ValueError("manifest path must be text")
    path = (ROOT/relative).resolve()
    if not path.is_relative_to(ROOT) or not path.is_file():
        raise ValueError("missing or out-of-repository manifest file: "+relative)
    return path


def verify():
    manifest = json.loads((DELIVERY/"MANIFEST.json").read_text(encoding="utf-8"))
    seen=set()
    for entry in manifest["files"]+manifest["unchanged_runtime_dependencies"]:
        relative=entry["path"]
        if relative in seen:
            raise ValueError("duplicate manifest file: "+relative)
        seen.add(relative)
        data=_path(relative).read_bytes()
        if len(data)!=entry["bytes"] or hashlib.sha256(data).hexdigest()!=entry["sha256"]:
            raise ValueError("delivery hash mismatch: "+relative)
    references=0
    for name in ("structured-execution-n512-d2w8.json","structured-samplef-n16-current.json",
                 "structured-samplef-n32-current.json","structured-samplef-signature-n512.json"):
        receipt=json.loads((DELIVERY/name).read_text(encoding="utf-8"))
        snapshots=[receipt.get("source_sha256",{})]
        for key,value in receipt.items():
            if key.startswith("source") and isinstance(value,dict):
                snapshots.append(value)
        # Nested runner snapshots have their own explicit source fields.
        def walk(value):
            if isinstance(value,dict):
                for key,item in value.items():
                    if "source" in key and "sha256" in key and isinstance(item,dict):
                        snapshots.append(item)
                    else:
                        walk(item)
            elif isinstance(value,list):
                for item in value: walk(item)
        walk(receipt)
        checked=set()
        for snapshot in snapshots:
            for relative,digest in snapshot.items():
                if not isinstance(digest,str) or len(digest)!=64 or not relative.endswith(".py"):
                    continue
                if (relative,digest) in checked:
                    continue
                checked.add((relative,digest))
                if hashlib.sha256(_path(relative).read_bytes()).hexdigest()!=digest:
                    raise ValueError("execution-source mismatch: "+relative)
                references+=1
        if not checked:
            raise ValueError("missing execution source snapshot: "+name)
    envelope=json.loads((DELIVERY/"structured-execution-entropy-envelope.json").read_text())
    source=(DELIVERY/envelope["input_receipt"]).resolve()
    if source.parent!=DELIVERY or hashlib.sha256(source.read_bytes()).hexdigest()!=envelope["input_receipt_sha256"]:
        raise ValueError("entropy-envelope input receipt mismatch")
    validation=json.loads((DELIVERY/"validation.json").read_text())
    for name,stats in validation["test_suites"].items():
        if stats["failures"] or stats["errors"] or stats["skipped"]:
            raise ValueError("unsuccessful required test suite: "+name)
    return {"verified":True,"manifest_files_checked":len(seen),
        "execution_source_references_checked":references,
        "security_claim":"none","backend_admitted":False,"parameters_are_formal":False}


if __name__=="__main__":
    print(json.dumps(verify(),indent=2))
