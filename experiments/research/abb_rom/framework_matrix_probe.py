"""Run common matrix checks with a genuine saved ABB tree and real fresh IBS.

Only HIBE Setup is replaced by explicit restoration through public codecs.
No mathematical operation is substituted: all six selected IBS families,
the registered ABB backend and the shared protocol execute their actual code.
The saved witness uses Alice/Charlie and Bob/Carol, so these four identities
are explicit inputs to the common driver. No new HIBE issuance is permitted.
"""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from ibme.hibe.abb_rom import ABBROMHIBE,ABBPublicKey,ABBMasterSecret
from ibme.protocol.hybrid_hibe import HybridPublicKey,HybridMasterSecret
from ibme.protocol.baseline import PublicKey,MasterSecret
from ibme.ibs.luo_module_profiles import c64b_params
from experiments.run_combination_matrix import run_case,summarize


class NoIssuance:
    calls=0
    def read(self,count):
        self.calls+=1
        raise AssertionError('saved witness attempted new HIBE issuance')


def source_files():
    import sys
    result={}
    for name,module in list(sys.modules.items()):
        path=getattr(module,'__file__',None)
        if path and path.endswith('.py') and (name.startswith('ibme.') or name.startswith('experiments.research.')):
            result[name]=dict(path=str(Path(path).resolve()),sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest())
    result[__name__]=dict(path=str(Path(__file__).resolve()),sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    path=Path(__file__).resolve().parents[2]/'run_combination_matrix.py'
    result['experiments.run_combination_matrix']=dict(path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    return result


def run(source,output,selected,commit):
    if not (source/'completed').is_file() or json.loads((source/'receipt.json').read_bytes())['status']!='passed':
        raise ValueError('a completed genuine ABB 2x2 tree is required')
    hashes={name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in ('public.bin','master.bin')}
    raw_public=(source/'public.bin').read_bytes();raw_master=(source/'master.bin').read_bytes()
    params=ABBPublicKey.from_bytes(raw_public).params
    cases={
        'luo-module-c64b-compact':('luo-module',asdict(c64b_params()),'compact'),
        'luo-matrix':('luo-matrix','research','reference'),
        'wang-pw':('wang-pw','research','reference'),
        'srgg':('srgg2025','research','reference'),
        'cert-ml-dsa':('cert-ml-dsa','ml-dsa-44','reference'),
        'cert-falcon':('cert-falcon','falcon-padded-512','reference'),
    }
    names=selected or list(cases)
    if any(name not in cases for name in names):raise ValueError('unknown ABB combination selection')
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('x') as stream:stream.write('{"status":"running"}\n')
    guard=NoIssuance();results=[]
    def setup(runtime,rng):
        public=ABBPublicKey.from_bytes(raw_public);master=ABBMasterSecret.from_bytes(raw_master)
        assert public==master.public_key and runtime.hibe_params.inner_params==params
        ipk,imsk=runtime.proto.ibs_backend.setup(runtime.ibs_params)
        hpk=HybridPublicKey(runtime.hibe_params.limits,public)
        return PublicKey(hpk,ipk),MasterSecret(HybridMasterSecret(hpk,master),imsk),dict(
            new_hibe_roots=0,new_ibs_roots=1,source_files_sha256=hashes,issuance_forbidden=True)
    def forbidden(*args,**kwargs):raise AssertionError('restoration called HIBE Setup')
    def issue(function):
        def call(self,*args,**kwargs):
            kwargs['rng']=guard;return function(self,*args,**kwargs)
        return call
    with patch.object(ABBROMHIBE,'setup',forbidden),patch.object(ABBROMHIBE,'extract',issue(ABBROMHIBE.extract)),\
         patch.object(ABBROMHIBE,'derive',issue(ABBROMHIBE.derive)):
        for name in names:
            route,ibs_params,fmt=cases[name]
            options=dict(hibe='abb-rom',hibe_params=params.to_record(),ibs=route,ibs_params=ibs_params,
                transport='hybrid',protocol='byteauth-v1',signature_format=fmt)
            receipt=run_case('abb-saved-'+name,options,setup_callback=setup,
                identities=(b'Alice',b'Bob',b'Carol',b'Charlie'))
            results.append(receipt)
            report=summarize(results)
            report.update(source_commit=commit,hibes_restored=True,new_hibe_roots=0,
                new_hibe_issuance_entropy_reads=guard.calls,original_source_files_sha256=hashes,
                fresh_IBS_setup_per_case=True,providers=source_files())
            output.write_text(json.dumps(report,indent=2)+'\n')
            print(name,receipt['status'],receipt['executed_checks'],flush=True)
            if receipt['status']!='pass':raise RuntimeError('ABB common matrix case failed: '+name)
    assert guard.calls==0
    assert hashes=={name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in hashes}
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--case',action='append')
    parser.add_argument('--source-commit',default='development')
    args=parser.parse_args();run(args.source.resolve(),args.output.resolve(),args.case,args.source_commit)


if __name__=='__main__':main()
