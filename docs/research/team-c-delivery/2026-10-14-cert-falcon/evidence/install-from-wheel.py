import os,subprocess,sys,tempfile,shutil
from pathlib import Path
root=Path.cwd().resolve();evidence=root/'test-results/cert-falcon'
cache=Path.home()/'.cache/ibme-native-tools/cert-falcon-installed-14c44a6-v3'
cache.mkdir(parents=True,exist_ok=False)
python=sys.executable
def command(args,*,cwd=root,env=None,log):
    result=subprocess.run(args,cwd=cwd,env=env,capture_output=True,timeout=300)
    (evidence/log).write_bytes(result.stdout+result.stderr)
    if result.returncode:raise RuntimeError(f'{log}: operation failed ({result.returncode})')
wheel=evidence/'wheels-windows/ibme-0.1.0-py3-none-any.whl';site=cache/'site'
command([python,'-m','pip','install','--no-deps','--no-index','--target',str(site),str(wheel)],log='wheel-install.txt')
env=os.environ.copy();env['PYTHONPATH']=str(site)
env['IBME_CERTIFIED_FALCON_BIN_DIR']=str(cache/'falcon/bin')
env['IBME_CERTIFIED_SIGNATURE_BIN_DIR']=str(cache/'mldsa/bin')
env['IBME_FALCON_EVIDENCE_ROOT']=str(root)
with tempfile.TemporaryDirectory(prefix='ibme-falcon-isolated-') as temporary:
    outside=Path(temporary)
    command([python,'-m','ibme.ibs.certified.falcon_native.build','--prefix',str(cache/'falcon'),'--selftest'],
            cwd=outside,env=env,log='installed-falcon-build.json')
    command([python,'-m','ibme.ibs.certified.native.build','--prefix',str(cache/'mldsa')],
            cwd=outside,env=env,log='installed-mldsa-build.json')
    checker=outside/'installed-check.py';shutil.copyfile(evidence/'installed-check.py',checker)
    command([python,str(checker)],cwd=outside,env=env,log='installed-check.txt')
print((evidence/'installed-check.txt').read_text())
