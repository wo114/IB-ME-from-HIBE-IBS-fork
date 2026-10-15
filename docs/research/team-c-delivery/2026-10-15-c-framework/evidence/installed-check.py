"""Repository-external zero-entropy replay of five original C CLI states."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

parser=argparse.ArgumentParser();parser.add_argument('--site',type=Path,required=True)
parser.add_argument('--state',type=Path,action='append',required=True)
args=parser.parse_args();site=args.site.resolve();sys.path.insert(0,str(site))
environment=dict(os.environ,PYTHONPATH=str(site));results=[];providers={}
for original in args.state:
 state=original/'state'
 before={path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in state.iterdir()
         if path.is_file() and path.suffix in ('.bin','.json')}
 process=subprocess.run([sys.executable,'-m','experiments.research.c_framework_cli_probe',
     '--private-directory',str(original.resolve()),'--restore-only'],cwd='/tmp',env=environment,
     capture_output=True,text=True,timeout=300,check=False)
 assert process.returncode==0,process.stderr
 replay=json.loads(process.stdout);assert replay['status']=='passed' and replay['entropy_bytes']==0
 for name,value in replay['command']['providers'].items():
  assert Path(value['path']).resolve().is_relative_to(site),(name,value['path'])
  if name in providers:assert providers[name]==value
  providers[name]=value
 assert before=={path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in state.iterdir()
                if path.is_file() and path.suffix in ('.bin','.json')}
 results.append(dict(case=original.name,restore=replay))
entry=Path(importlib.util.find_spec('experiments.research.c_framework_cli_probe').origin).resolve()
assert entry.is_relative_to(site)
providers['experiments.research.c_framework_cli_probe']=dict(path=str(entry),sha256=hashlib.sha256(entry.read_bytes()).hexdigest())
print(json.dumps(dict(status='passed',site=str(site),original_instances=len(results),
     restored_decryptions=len(results),entropy_bytes=0,new_roots_or_keys_or_signatures=0,
     original_state_unchanged=True,providers=providers,results=results,
     native_environment='Reuses the previously source-ABI-checked local native engines; no rebuilt arithmetic',
     security_claim='none',backend_admitted=False,parameters_are_formal=False),indent=2,sort_keys=True))
