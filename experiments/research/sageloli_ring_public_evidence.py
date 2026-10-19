"""Export a fixed public RSIS receipt set; never copy private state or samples."""
import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[2]
CODE=Path("experiments/research/candidates/sageloli/ring")
DEST=Path("docs/research/team-b-delivery/2026-10-19-sageloli-ring-target")
NAMES=("param-I-fresh","param-I-recover","param-II-fresh","param-II-recover")
PRIVATE_STATS=("raw_norm_squared_upper","transform_component_error_upper")


def publish_once(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():
        if path.read_bytes()!=data:raise ValueError("public artifact differs; preserve and review existing file")
    else:path.write_bytes(data)


def export(output_directory,*,recovery_suffix="",cpu):
    dest=ROOT/DEST;evidence=dest/"evidence";evidence.mkdir(parents=True,exist_ok=True)
    for name in NAMES:
        source_name=name+recovery_suffix if name.endswith("recover") else name
        raw=json.loads((output_directory/(source_name+".json")).read_text())
        if raw.get("status")!="passed":raise ValueError("only completed actual receipts may enter this package")
        public=deepcopy(raw)
        for field in PRIVATE_STATS:public.get("sampler",{}).pop(field,None)
        public["publication"]=dict(omitted_private_sampler_fields=list(PRIVATE_STATS),
            scope="independent RSIS actual lifecycle, not a HIBE/IB-ME combination",
            test_only_seed=False,message_lengths_used=[raw["message_bytes"],raw["message_bytes"]+(9 if raw["mode"]=="recover" else 1)])
        public["environment"]["cpu"]=cpu
        data=(json.dumps(public,sort_keys=True,indent=2)+"\n").encode()
        publish_once(evidence/(name+".json"),data)
        for filename,expected in raw["source_sha256"].items():
            current=ROOT/CODE/filename
            commit=raw["source_commit"]
            if len(commit)!=40 or any(c not in "0123456789abcdef" for c in commit):raise ValueError("source commit format")
            old=subprocess.run(["git","show",commit+":"+(CODE/filename).as_posix()],
                cwd=ROOT,capture_output=True,check=True).stdout
            if sha256(old).hexdigest()!=expected:raise ValueError("historical source does not match receipt")
            if current.is_file() and sha256(current.read_bytes()).hexdigest()==expected:continue
            publish_once(evidence/"source-snapshots"/commit[:7]/filename,old)
    test_input=output_directory/"final-tests.xml"
    tree=ET.parse(test_input)
    for suite in tree.iter("testsuite"):suite.attrib.pop("hostname",None)
    publish_once(evidence/"tests.xml",ET.tostring(tree.getroot(),encoding="utf-8",xml_declaration=True))
    paths=[]
    for base in (ROOT/CODE,ROOT/"tests/sageloli_native",dest):
        paths.extend(p for p in base.rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.name!="MANIFEST.json")
    paths.extend((ROOT/"tests/test_sageloli_ring_structured.py",Path(__file__).resolve(),
                  ROOT/"docs/specs/sageloli-ibs.md",
                  ROOT/"papers/2023_shorter_faster_ibs_sageloli.pdf"))
    manifest={p.relative_to(ROOT).as_posix():sha256(p.read_bytes()).hexdigest() for p in sorted(set(paths))}
    (dest/"MANIFEST.json").write_text(json.dumps(dict(schema=1,files=manifest),indent=2,sort_keys=True)+"\n")
    print(json.dumps(dict(public_receipts=4,manifest_entries=len(manifest),private_material_exported=False)))


def main():
    p=argparse.ArgumentParser();p.add_argument("--output-directory",type=Path,required=True)
    p.add_argument("--recovery-suffix",default="");p.add_argument("--cpu",required=True)
    a=p.parse_args();export(a.output_directory,recovery_suffix=a.recovery_suffix,cpu=a.cpu)


if __name__=="__main__":main()
