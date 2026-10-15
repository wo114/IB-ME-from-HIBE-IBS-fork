"""Read-only installed replay with only the selected native profile present."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

parser=argparse.ArgumentParser()
parser.add_argument('--site',type=Path,required=True)
parser.add_argument('--state-base',type=Path,required=True)
args=parser.parse_args();site=args.site.resolve();sys.path.insert(0,str(site))
assert Path.cwd().resolve()==Path('/tmp')
assert os.environ['PYTHONPATH']==str(site)
from ibme.assembly import make_suite,validate_suite
from ibme.core.randomness import SecureRandom
from ibme.ibs.certified.params import CertifiedIBSParams
from ibme.ibs.certified.ordinary import ordinary
from experiments.research.c_framework_cli_probe import replay

profiles=['ml-dsa-44','ml-dsa-65','ml-dsa-87','falcon-padded-512','falcon-padded-1024']
binaries={p:ordinary(CertifiedIBSParams(base_algorithm=p)).binary for p in profiles}
rows=[];providers={}


def forbidden(*args,**kwargs):
    raise AssertionError('read-only qualification consumed private entropy')


SecureRandom.read=forbidden
with tempfile.TemporaryDirectory(prefix='ibme-profile-only-') as temporary:
    for profile in profiles:
        family='cert-ml-dsa' if profile.startswith('ml-dsa') else 'cert-falcon'
        variable=('IBME_CERTIFIED_SIGNATURE_BIN_DIR' if family=='cert-ml-dsa'
                  else 'IBME_CERTIFIED_FALCON_BIN_DIR')
        previous=os.environ.get(variable)
        selected=Path(temporary)/profile;selected.mkdir()
        (selected/binaries[profile].name).symlink_to(binaries[profile])
        absent=Path(temporary)/(profile+'-absent');absent.mkdir()
        alternative=next(p for p in profiles if p!=profile and p.startswith(profile.split('-')[0]))
        (absent/binaries[alternative].name).symlink_to(binaries[alternative])
        try:
            config=make_suite(hibe='mock',ibs=family,ibs_params=profile,allow_mock=True)
            os.environ[variable]=str(selected)
            report=validate_suite(config)
            assert report.ok,report.errors
            restored=replay((args.state_base/('cli-'+profile)).resolve())
            assert restored['status']=='passed' and restored['entropy_bytes']==0
            for module,value in restored['command']['providers'].items():
                assert Path(value['path']).resolve().is_relative_to(site),(module,value['path'])
                if module in providers:assert providers[module]==value
                providers[module]=value
            # Another working family member must not satisfy a missing selection.
            os.environ[variable]=str(absent)
            rejected=validate_suite(config)
            assert not rejected.ok and any('missing' in error for error in rejected.errors)
            rows.append(dict(profile=profile,only_selected_binary=True,
                preflight_passed=True,original_state_restore=restored,
                selected_absent_alternative_present_rejected=True))
        finally:
            if previous is None:os.environ.pop(variable,None)
            else:os.environ[variable]=previous
entry=sys.modules['experiments.research.c_framework_cli_probe'].__file__
assert Path(entry).resolve().is_relative_to(site)
providers['experiments.research.c_framework_cli_probe']=dict(
    path=str(Path(entry).resolve()),sha256=hashlib.sha256(Path(entry).read_bytes()).hexdigest())
print(json.dumps(dict(status='passed',source_commit='30aebdf9d0b54a48644e1d69febe1019d5d6b802',
    site=str(site),profiles=5,original_instances_restored=5,entropy_bytes=0,
    new_roots_or_keys_or_signatures=0,original_state_unchanged=True,providers=providers,
    results=rows,native_environment='Previously source-ABI-checked engines; temporary directories contain symlinks only',
    security_claim='none',backend_admitted=False,parameters_are_formal=False),indent=2,sort_keys=True))
