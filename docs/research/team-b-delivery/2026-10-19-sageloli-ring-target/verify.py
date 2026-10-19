"""Stdlib-only public evidence verification; does not sample or read private state."""
import ast
from hashlib import sha256
import json
from pathlib import Path
import xml.etree.ElementTree as ET

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
CODE=ROOT/"experiments/research/candidates/sageloli/ring"


def require(value,message):
    if not value:raise ValueError(message)


def main():
    manifest=json.loads((HERE/"MANIFEST.json").read_text())
    constants={}
    for node in ast.parse((CODE/"run.py").read_text()).body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            if node.targets[0].id in ("IDENTITY","MESSAGE"):
                constants[node.targets[0].id]=ast.literal_eval(node.value)
    for relative,expected in manifest["files"].items():
        path=ROOT/relative
        require(not Path(relative).is_absolute() and ".." not in Path(relative).parts,"unsafe manifest path")
        require(path.is_file() and not path.is_symlink(),"missing/nonregular artifact")
        require(sha256(path.read_bytes()).hexdigest()==expected,"artifact hash mismatch: "+relative)
    for profile,k,l in (("I",65,132),("II",153,308)):
        for mode in ("fresh","recover"):
            r=json.loads((HERE/"evidence"/("param-"+profile+"-"+mode+".json")).read_text())
            require(r["status"]=="passed" and r["profile"]==profile and r["mode"]==mode,"wrong execution receipt")
            p=r["parameters"]
            require((p["d"],p["k"],p["l"])==(2048,k,l) and int(r["modulus"])==3**k,"paper structure changed")
            require(p["r_squared"]==49 and p["tail_bits"]==256 and p["mass_bits"]==320,"sampler profile changed")
            require(r["signatures_verified"]==2,"honest signature checks missing")
            require(r["identity_bytes"]==len(constants["IDENTITY"]) and r["message_bytes"]==len(constants["MESSAGE"]),"message/identity length mismatch")
            require(r["publication"]["message_lengths_used"]==[r["message_bytes"],r["message_bytes"]+(9 if mode=="recover" else 1)],"second message length mismatch")
            require(r["security_claim"]=="none" and r["backend_admitted"] is False and r["parameters_are_formal"] is False,"claim upgraded")
            require(r["sampler"]["dense_covariance_allocated"] is False and r["sampler"]["total_TV_certified"] is False,"sampler scope changed")
            require("raw_norm_squared_upper" not in r["sampler"] and "transform_component_error_upper" not in r["sampler"],"private sampler statistic")
            if mode=="fresh":
                require(len(r["negative_controls"])==10 and all(r["negative_controls"].values()),"negative controls missing")
                expected_public=2048*l*(((3**k).bit_length()+7)//8)
                require(r["sizes_bytes"]["public"]>=expected_public,"public size undercount")
                require(r["sizes_bytes"]["signing_key"]>=l*k*2048*8,"identity key size undercount")
            else:require(r["restore_entropy_bytes"]==0,"recovery sampled new material")
            for filename,expected in r["source_sha256"].items():
                require(Path(filename).name==filename,"unsafe source filename")
                candidates=[CODE/filename,HERE/"evidence/source-snapshots"/r["source_commit"][:7]/filename]
                require(any(x.is_file() and sha256(x.read_bytes()).hexdigest()==expected for x in candidates),"source provenance mismatch: "+filename)
                if filename=="native.cpp":
                    source=next(x.read_bytes() for x in candidates if x.is_file() and sha256(x.read_bytes()).hexdigest()==expected)
                    require(sha256(source+b"-O3 -fopenmp -lflint -lgmp v1").hexdigest()==r["native"]["source_id"],"native source identifier mismatch")
    tree=ET.parse(HERE/"evidence/tests.xml");cases=list(tree.iter("testcase"))
    require(len(cases)>0 and all(c.find("failure") is None and c.find("error") is None and c.find("skipped") is None for c in cases),"tests failed or skipped")
    print(json.dumps(dict(status="passed",manifest_entries=len(manifest["files"]),actual_receipts=4,testcases=len(cases),private_state_read=False)))


if __name__=="__main__":main()
