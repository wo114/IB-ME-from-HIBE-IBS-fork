"""Run outside the repository, against an isolated installation and saved states."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

parser=argparse.ArgumentParser()
parser.add_argument("--site",type=Path,required=True)
parser.add_argument("--state",type=Path,action="append",required=True)
parser.add_argument("--private-output",type=Path,required=True)
args=parser.parse_args();site=args.site.resolve();output=args.private_output.resolve()
output.mkdir(parents=True,exist_ok=False)
sys.path.insert(0,str(site))
before={str(path):hashlib.sha256(path.read_bytes()).hexdigest()
        for state in args.state for path in state.glob("*.bin")}
env=dict(os.environ,PYTHONPATH=str(site));replays=[]
for state in args.state:
    child=subprocess.run([sys.executable,"-m","experiments.research.candidates.xie.probe",
        "--private-directory",str(state.resolve()),"--restore-only"],cwd="/tmp",env=env,
        capture_output=True,text=True,timeout=60,check=False)
    assert child.returncode==0,child.stderr
    result=json.loads(child.stdout)
    assert result["entropy_calls"]==0 and not result["sage_imported"] and result["verified"]==32
    for provider in result["providers"].values():
        assert Path(provider["path"]).resolve().is_relative_to(site)
    replays.append(result)

from experiments.research.candidates.xie.objects import Public,Master,IdentitySecret
from experiments.research.candidates.xie import runtime
from experiments.research.candidates.xie.probe import CountedRandom,source_fingerprints
from experiments.research.candidates.xie.verification import verify
def forbidden(*args,**kwargs):raise AssertionError("installed restored-key signing generated or extracted")
runtime.setup=forbidden;runtime.preimage_sampler=forbidden;Master.extract=forbidden
source=CountedRandom();signed=[]
for state in args.state:
    public=Public.from_bytes((state/"public.bin").read_bytes())
    for i in range(2):
        key=IdentitySecret.from_bytes((state/f"user-{i}.bin").read_bytes())
        message=hashlib.sha256(b"installed restored Xie key new message/"+bytes([public.params.n,i])).digest()
        signature=runtime.sign(key,message,rng=source)
        assert verify(public,key.identity,message,signature)
        (output/f"signature-{public.params.n}-{i}.bin").write_bytes(signature.to_bytes())
        signed.append(dict(n=public.params.n,identity_hex=key.identity.hex(),message_hex=message.hex(),
            signature_hex=signature.to_bytes().hex()))
providers=source_fingerprints()
assert all(Path(item["path"]).resolve().is_relative_to(site) for item in providers.values())
assert before=={str(path):hashlib.sha256(path.read_bytes()).hexdigest()
               for state in args.state for path in state.glob("*.bin")}
print(json.dumps(dict(status="passed",site=str(site),original_instances=len(args.state),
    zero_entropy_verifications=sum(x["verified"] for x in replays),restored_keys=len(signed),
    new_signatures=signed,new_roots=0,new_extractions=0,entropy_bytes=source.bytes,
    original_states_unchanged=True,replays=replays,providers=providers),indent=2,sort_keys=True))
