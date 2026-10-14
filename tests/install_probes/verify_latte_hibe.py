"""Isolated Sage verifier: installed target, saved real private directory, receipt."""
import hashlib
import json
from pathlib import Path
import sys
from unittest.mock import patch

target,private,output=(Path(s).resolve() for s in sys.argv[1:])
sys.path.insert(0,str(target))
import ibme.hibe.latte as package
from ibme.hibe.latte import backend,params,objects,codec,engine,math,registration
from ibme.hibe.latte.native import build
from ibme.core import randomness,encoding,types,errors

providers=[package,backend,params,objects,codec,engine,math,registration,build,randomness,encoding,types,errors]
assert all(Path(p.__file__).resolve().is_relative_to(target) for p in providers)
original=engine.Native.call
def no_entropy(*args,**kwargs): raise AssertionError("saved-key restore requested external entropy")
def no_keys(self,operation,data):
    if operation in ("setup","delegate","extract","encrypt"):
        raise AssertionError("saved key was regenerated")
    return original(self,operation,data)
with patch.object(randomness.SecureRandom,"read",no_entropy),patch.object(engine.Native,"call",no_keys):
    scheme=package.LATTEHIBE()
    master=package.LATTEMasterSecret.from_bytes((private/"master.bin").read_bytes())
    parent=scheme.extract(master,b"R"*85+b"0")
    leaf=scheme.derive(parent,b"S"*85+b"0")
    ct=scheme.load_ciphertext((private/"cipher-0-0.bin").read_bytes())
    message=hashlib.sha256(b"LATTE-3 independent honest-noise HIBE lifecycle").digest()
    assert scheme.decrypt(leaf,ct)==message
    assert master.to_bytes()==(private/"master.bin").read_bytes()

# Separate fresh installed-only system instance, not added to the saved 2x2 run.
public,fresh=scheme.setup(package.LATTEParams())
receiver=scheme.extract(fresh,b"installed receiver")
sender=scheme.derive(receiver,b"installed sender")
ct=scheme.encrypt(public,b"installed receiver",b"installed sender",message)
assert scheme.decrypt(sender,ct)==message
report=dict(status="passed",isolated_interpreter=True,source_repository_fallback=False,
    providers={p.__name__:str(Path(p.__file__).resolve().relative_to(target)) for p in providers},
    saved_real_key_reused=True,saved_key_restore_entropy_calls=0,saved_key_regenerations=0,
    separate_fresh_installed_HIBE_lifecycle=True,n=params.N,q=params.Q,message_bytes=32,
    native_source_id=build.source_id(),native_binary_sha256=engine.Native(public.params).binary_sha256,
    security_claim="none",backend_admitted=False,parameters_are_formal=False)
output.write_text(json.dumps(report,indent=2)+"\n")
print("Installed-only LATTE HIBE, fixed-key restore and separate fresh lifecycle passed")
