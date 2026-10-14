import hashlib,json,os,sys
from pathlib import Path
from ibme.ibs.certified import CertifiedIBS,CertifiedMasterSecret,CertifiedSigningKey
from ibme.ibs.certified.ordinary import ordinary
from experiments.research.certified_ibs_probe import restore

root=Path(os.environ['IBME_FALCON_EVIDENCE_ROOT'])
site=Path(os.environ['PYTHONPATH']).resolve()
records=[]
directories=[root/f'test-results/cert-falcon/real-{n}-14c44a6' for n in (512,1024)]
directories += [root/f'test-results/cert-mldsa/real-{n}-c61b8eb' for n in (44,65,87)]
for directory in directories:
    replay=restore(directory)
    assert Path(replay['provider_path']).resolve().is_relative_to(site)
    raw=(directory/'master.bin').read_bytes()
    master=CertifiedMasterSecret.from_bytes(raw)
    sk=CertifiedSigningKey.from_bytes((directory/'key-0.bin').read_bytes())
    backend=CertifiedIBS();message=b'fresh installed-only signature from original restored key'
    sig=backend.sign(sk,message)
    assert backend.verify(master.public_key,sk.identity,message,sig)
    assert master.to_bytes()==raw
    records.append(dict(algorithm=master.params.base_algorithm,restore=replay,
        fresh_signature_from_restored_key=True,master_snapshot_unchanged=True,
        installed_native_binary_sha256=ordinary(master.params).binary_sha256))
providers={name:module.__file__ for name,module in tuple(sys.modules.items())
           if (name=='ibme' or name.startswith('ibme.') or name.startswith('experiments.')) and getattr(module,'__file__',None)}
assert all(Path(path).resolve().is_relative_to(site) for path in providers.values())
assert not any('worktrees' in path for path in sys.path)
wheel=root/'test-results/cert-falcon/wheels-windows/ibme-0.1.0-py3-none-any.whl'
report=dict(status='passed',source_commit='14c44a60e32399925e70c026aef4824031e0216c',cwd=str(Path.cwd()),
    wheel_sha256=hashlib.sha256(wheel.read_bytes()).hexdigest(),wheel_bytes=wheel.stat().st_size,
    installed_site=str(site),providers=providers,records=records,private_state_regenerated=False,
    security_claim='none',backend_admitted=False,parameters_are_formal=False)
(root/'test-results/cert-falcon/installed.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(dict(status='passed',provider_modules=len(providers),saved_instances=5,
    zero_entropy_saved_verifications=160,fresh_restored_key_signatures=5)))
