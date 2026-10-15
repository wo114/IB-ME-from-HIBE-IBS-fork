"""Archive an explicit public allowlist and compare provider bytes with Git blobs."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

root=Path.cwd();base=root/'test-results/c-2026-10-15'
out=root/'docs/research/team-c-delivery/2026-10-15-xie-study/evidence'
out.mkdir(parents=True,exist_ok=True)
commit='7c139f4a064071bc8e13c95c50eecd88765a62d5'
allow={
 'real-16/receipt.json':'real-n16.json','real-32/receipt.json':'real-n32.json',
 'installed-check.json':'installed-check.json','installed-check.py':'installed-check.py',
 'archive-evidence.py':'archive-evidence.py',
 'ci-xie/xie-ntru-ibs.json':'xie-suite.json','ci-xie/xie-ntru-ibs.xml':'xie-suite.xml',
 'ci-lai/lai-ideal-hibe.json':'lai-suite.json','ci-lai/lai-ideal-hibe.xml':'lai-suite.xml',
 'framework/framework.json':'framework.json','framework/framework.xml':'framework.xml',
 'windows-c.txt':'windows-c.txt','windows-c.xml':'windows-c.xml',
 'xie-full.txt':'development-thread-failure.txt','xie-full.xml':'development-thread-failure.xml',
 'wheel.txt':'wheel.txt'
}
for source,target in allow.items():shutil.copyfile(base/source,out/target)
(out/'.gitattributes').write_text('* -text -eol whitespace=-blank-at-eol,-blank-at-eof\n',encoding='ascii')
providers={}
for name in ['real-n16.json','real-n32.json','installed-check.json']:
 receipt=json.loads((out/name).read_bytes())
 groups=[receipt['providers']]
 if name=='installed-check.json':groups.extend(x['providers'] for x in receipt['replays'])
 for group in groups:
  for module,value in group.items():
   # Historical experiments imports alias the installed lattice modules.
   # Bind the actual provider file, rather than guessing from the alias name.
   actual=value['path'].replace('\\','/')
   if '/src/ibme/' in actual:path='src/ibme/'+actual.split('/src/ibme/',1)[1]
   elif '/experiments/research/' in actual:path='experiments/research/'+actual.split('/experiments/research/',1)[1]
   elif name=='installed-check.json' and actual.startswith(receipt['site']+'/ibme/'):
    path='src/ibme/'+actual[len(receipt['site']+'/ibme/'):]
   else:raise AssertionError(('unmapped provider',module,actual))
   blob=subprocess.check_output(['git','show',commit+':'+path],cwd=root)
   expected=hashlib.sha256(blob).hexdigest()
   assert expected==value['sha256'],(module,expected,value['sha256'])
   providers[path]=expected
for path in ['ci/run.py','ci/suites.json','tests/test_ci_catalog.py','tests/test_xie_study.py',
             'tests/test_xie_public.py','tests/test_lai_qualification.py','tests/fixtures/xie_study/public.json',
             'experiments/research/candidates/lai/qualification.py']:
 blob=subprocess.check_output(['git','show',commit+':'+path],cwd=root)
 expected=hashlib.sha256(blob).hexdigest();assert expected==hashlib.sha256((root/path).read_bytes()).hexdigest()
 providers[path]=expected
wheel=base/'wheel/ibme-0.1.0-py3-none-any.whl'
result=dict(status='passed',source_commit=commit,files=providers,count=len(providers),
 wheel=dict(bytes=wheel.stat().st_size,sha256=hashlib.sha256(wheel.read_bytes()).hexdigest()),
 evidence={target:hashlib.sha256((out/target).read_bytes()).hexdigest() for target in allow.values()},
 private_outputs_copied=False)
(out/'source-check.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n',encoding='utf-8')
print(json.dumps(dict(status='passed',source_files=len(providers),public_artifacts=len(allow),wheel=result['wheel'])))
