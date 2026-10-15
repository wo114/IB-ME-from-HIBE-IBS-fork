"""Verify an offline local wheel in a temporary target outside the checkout."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

WORKER=r'''
import hashlib,json,sys
from pathlib import Path
from ibme.ibs.yu import YuIBS,YuParams,PublicKey,SigningKey,MasterSecret
from ibme.ibs.yu.service import FixedIssuer
from ibme.ibs.yu.registration import backend_spec
class NoEntropy:
    def read(self,n): raise AssertionError('unexpected entropy')
root,target=Path(sys.argv[1]),Path(sys.argv[2]).resolve()
issuer=FixedIssuer(root/'issuer'); pk=issuer.initialize(YuParams())
keys=[issuer.key_extract(i) for i in (b'A',b'B')]
verifier=YuIBS(NoEntropy()); signer=YuIBS(); checks=0
recovered=FixedIssuer(root/'issuer',verifier)
for key in keys:
    assert recovered.key_extract(key.identity)==key; checks+=1
    key2=SigningKey.from_bytes(key.to_bytes()); pk2=PublicKey.from_bytes(pk.to_bytes())
    for msg in (b'',b'M',b'\0'):
        sig=signer.sign(key,msg)
        assert verifier.verify(pk2,key.identity,msg,verifier.load_signature(pk2,sig.to_bytes())); checks+=1
        sig2=signer.sign(key2,msg)
        assert verifier.verify(pk2,key.identity,msg,sig2); checks+=1
assert backend_spec().master_public_key(MasterSecret.from_bytes((root/'issuer/master.bin').read_bytes()))==pk
checks+=1; providers={}
for name,module in tuple(sys.modules.items()):
    if name=='ibme' or name.startswith('ibme.') or name=='experiments' or name.startswith('experiments.research'):
        file=getattr(module,'__file__',None)
        if file is not None:
            path=Path(file).resolve(); assert path.is_relative_to(target),(name,'source escaped target')
            providers[name]=dict(file=path.relative_to(target).as_posix(),sha256=hashlib.sha256(path.read_bytes()).hexdigest())
assert 'ibme.ibs.yu.service' in providers
print(json.dumps(dict(status='passed',checks=checks,users=len(keys),source_providers=providers,
    security_claim='none',parameters_are_formal=False,backend_admitted=False)))
'''


def run(wheel):
    wheel=wheel.resolve()
    with tempfile.TemporaryDirectory(prefix="yu-installed-") as folder:
        root=Path(folder); target=root/"site"
        install=subprocess.run([sys.executable,"-m","pip","install","--no-deps","--no-index",
            "--target",str(target),str(wheel)],cwd=root,capture_output=True,text=True,timeout=120)
        if install.returncode: raise RuntimeError("offline wheel installation failed")
        child=subprocess.run([sys.executable,"-c",WORKER,folder,str(target)],cwd=root,
            env={**os.environ,"PYTHONPATH":str(target),"PYTHONNOUSERSITE":"1"},capture_output=True,text=True,timeout=180)
        if child.returncode:
            # Tracebacks can expose secret diagnostic fields. Keep only status.
            raise RuntimeError(f"installed Yu validation failed, exit={child.returncode}")
        result=json.loads(child.stdout)
        result.update(wheel_sha256=hashlib.sha256(wheel.read_bytes()).hexdigest(),
            installation="temporary --target, no index, no dependencies; cwd outside repository")
        return result


if __name__=="__main__":
    parser=argparse.ArgumentParser(); parser.add_argument("--wheel",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True); args=parser.parse_args()
    result=run(args.wheel); args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(dict(status=result["status"],checks=result["checks"],providers=len(result["source_providers"]))))
