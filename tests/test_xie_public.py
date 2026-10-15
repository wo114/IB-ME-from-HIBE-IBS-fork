"""Public-only verification, strict objects and explicit small-domain attacks."""
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import sys

import pytest

from ibme.core.errors import SerializationError
from ibme.core.randomness import DeterministicRandom
from experiments.research.candidates.xie.objects import Public,Master,IdentitySecret,Signature
from experiments.research.candidates.xie.verification import verify,load_signature
from experiments.research.candidates.xie.negative_controls import modulus_shift,zero_challenge_forgery
from test_xie_study import instance,NoEntropy

FIXTURE=Path(__file__).parent/"fixtures/xie_study/public.json"


@pytest.fixture(params=[0,1])
def vector(request):
    return json.loads(FIXTURE.read_bytes())["vectors"][request.param]


def test_public_test_vector_and_rejections(vector):
    raw=lambda k:bytes.fromhex(vector[k])
    public=Public.from_bytes(raw("public_hex"));signature=load_signature(public,raw("signature_hex"))
    identity=raw("identity_hex");message=raw("message_hex")
    assert verify(public,identity,message,signature)
    assert not verify(public,identity,message,replace(signature,context=bytes(32)))
    assert not verify(public,identity,b"changed message",signature)
    assert not verify(public,b"different identity",message,signature)
    for value in (None,"identity",b"",b"x"*65):assert not verify(public,value,message,signature)
    assert not verify(public,identity,"message",signature)


def test_public_verification_in_fresh_process_forbids_sage_and_private_runtime():
    script="""import builtins,json,sys
original=builtins.__import__
def guarded(name,*args,**kwargs):
    if name=='sage' or name.startswith('sage.') or name.endswith('xie.runtime'):
        raise AssertionError('public verification imported private runtime')
    return original(name,*args,**kwargs)
builtins.__import__=guarded
from ibme.core.randomness import SecureRandom
SecureRandom.read=lambda *args: (_ for _ in ()).throw(AssertionError('public verification entropy'))
from experiments.research.candidates.xie.objects import Public
from experiments.research.candidates.xie.verification import load_signature,verify
for v in json.loads(sys.stdin.buffer.read())['vectors']:
    p=Public.from_bytes(bytes.fromhex(v['public_hex']))
    s=load_signature(p,bytes.fromhex(v['signature_hex']))
    assert verify(p,bytes.fromhex(v['identity_hex']),bytes.fromhex(v['message_hex']),s)
assert not any(x=='sage' or x.startswith('sage.') or x.endswith('xie.runtime') for x in sys.modules)
print('public-only vectors passed')
"""
    result=subprocess.run([sys.executable,"-c",script],input=FIXTURE.read_bytes(),capture_output=True,timeout=30)
    assert result.returncode==0,result.stderr.decode()
    assert result.stdout.strip()==b"public-only vectors passed"


def test_public_modulus_shift_counterexample_is_retained(vector):
    public=Public.from_bytes(bytes.fromhex(vector["public_hex"]))
    signature=load_signature(public,bytes.fromhex(vector["signature_hex"]))
    identity=bytes.fromhex(vector["identity_hex"]);message=bytes.fromhex(vector["message_hex"])
    forged=modulus_shift(public,identity,message,signature)
    assert forged is not None and forged.to_bytes()!=signature.to_bytes()
    assert verify(public,identity,message,forged)


def test_zero_challenge_public_forgery_on_explicit_tiny_challenge_domain(vector):
    public=Public.from_bytes(bytes.fromhex(vector["public_hex"]))
    changed=Public(replace(public.params,challenge_weight=1),public.h)
    witness=zero_challenge_forgery(changed,max_trials=4096)
    assert witness["status"]=="witness_found" and not witness["private_material_used"]
    sig=load_signature(changed,bytes.fromhex(witness["signature_hex"]))
    assert verify(changed,b"unissued",bytes.fromhex(witness["message_hex"]),sig)


def test_concurrent_cached_replay_and_capacity(instance):
    runtime,rng,public,master,alice,bob=instance
    copy=Master.from_bytes(master.to_bytes())
    issued=copy.extract(b"concurrent",rng=rng)
    with ThreadPoolExecutor(max_workers=8) as workers:
        keys=list(workers.map(lambda _:copy.extract(b"concurrent",rng=NoEntropy()),range(16)))
    assert all(key is issued for key in keys)
    assert copy.extract(b"concurrent",rng=NoEntropy()) is issued
    p=replace(public.params,max_identities=2)
    limited=Master(Public(p,public.h),master._f,master._g,master._F,master._G)
    limited.extract(b"a",rng=rng);limited.extract(b"b",rng=rng)
    with pytest.raises(ValueError,match="capacity"):limited.extract(b"c",rng=NoEntropy())


def test_fresh_worker_operations_rejected_before_entropy_or_reservation(instance):
    runtime,rng,public,master,alice,bob=instance
    from experiments.research.candidates.xie.execution import StudyExecutionError
    copy=Master.from_bytes(master.to_bytes());before=copy.to_bytes()
    operations=(lambda:copy.extract(b"worker",rng=NoEntropy()),
                lambda:runtime.setup(public.params,rng=NoEntropy()),
                lambda:runtime.sign(alice,b"worker",rng=NoEntropy()),
                lambda:runtime.preimage_sampler(copy))
    with ThreadPoolExecutor(max_workers=1) as workers:
        for operation in operations:
            with pytest.raises(StudyExecutionError,match="main thread"):
                workers.submit(operation).result(timeout=10)
    assert copy.to_bytes()==before
    # A rejected unsupported call never creates a pending identity.
    assert copy.extract(b"worker",rng=rng).identity==b"worker"


def test_first_private_runtime_import_from_worker_rejected_before_sage():
    script="""from concurrent.futures import ThreadPoolExecutor
import builtins
original=builtins.__import__
def guarded(name,*args,**kwargs):
    if name=='sage' or name.startswith('sage.'):
        raise AssertionError('unsupported worker reached Sage import')
    return original(name,*args,**kwargs)
builtins.__import__=guarded
from experiments.research.candidates.xie.execution import StudyExecutionError
def fresh_import():
    from experiments.research.candidates.xie import runtime
with ThreadPoolExecutor(max_workers=1) as workers:
    try:workers.submit(fresh_import).result(timeout=10)
    except StudyExecutionError:print('worker rejected before Sage')
    else:raise AssertionError('unsupported worker accepted')
"""
    result=subprocess.run([sys.executable,"-c",script],capture_output=True,timeout=30)
    assert result.returncode==0,result.stderr.decode()
    assert result.stdout.strip()==b"worker rejected before Sage"


@pytest.mark.parametrize("which",["public","master","user","signature"])
def test_all_object_wires_reject_truncation_append_duplicate_and_bad_fields(instance,which):
    runtime,rng,public,master,alice,bob=instance
    signature=runtime.sign(alice,b"wire",rng=rng)
    value,decoder={"public":(public,Public.from_bytes),"master":(master,Master.from_bytes),
        "user":(alice,IdentitySecret.from_bytes),"signature":(signature,lambda b:load_signature(public,b))}[which]
    raw=value.to_bytes();assert decoder(raw).to_bytes()==raw
    for bad in (raw[:-1],raw+b"!",raw+b" ",raw[:len(raw)//2],
                raw.replace(b'"kind":',b'"kind":"duplicate","kind":'),
                raw.replace(b'"fields":',b'"extra":0,"fields":')):
        with pytest.raises(SerializationError):decoder(bad)


def test_noncanonical_signature_and_private_contexts(instance):
    runtime,rng,public,master,alice,bob=instance
    from experiments.research.candidates.xie.codec import encode
    signature=runtime.sign(alice,b"strict",rng=rng)
    values=json.loads(signature.to_bytes())
    for field,value in (("z1",[True]*public.params.n),("z1",[1.0]*public.params.n),
                        ("z1",[0]*(public.params.n-1)),("u",[2]*public.params.n),("context","ff"*33)):
        changed=dict(values["fields"],**{field:value})
        with pytest.raises(SerializationError):load_signature(public,encode(values["kind"],changed))
    key=json.loads(alice.to_bytes());key["fields"]["identity"]=""
    with pytest.raises(SerializationError):IdentitySecret.from_bytes(encode(key["kind"],key["fields"]))
