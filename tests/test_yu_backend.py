"""Real Yu byte adapter plus explicitly labelled fault/format tests.

Only the first three public A1 draws are rank-conditioned in the success
fixture; remaining draws are SecureRandom. This is not a Setup-distribution
experiment. q=3 public forgery MUST continue to pass, not be hidden by tags.
"""
from dataclasses import asdict, replace
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

pytest.importorskip("sage.all",reason="Use WSL ~/miniconda3/envs/sage/bin/python")
from ibme.core.errors import EncodingError, InvalidParameterError, SerializationError
from ibme.core.randomness import SecureRandom
from ibme.ibs.api import IBSBackend
from ibme.ibs.yu import YuIBS,YuParams,PublicKey,MasterSecret,SigningKey,Signature,YuSamplingAbort,IssuancePending
from ibme.ibs.yu import codec
from ibme.ibs.yu.registration import backend_spec,check_object,signature_size,validate_configuration
from experiments.research.candidates.yu import standalone as raw
from experiments.research.gaussian_reference import SamplingAbort


class RankRandom:
    def __init__(self):
        self.prefix=iter((1,2,0)); self.source=SecureRandom(); self.calls=0
    def read(self,n):
        self.calls+=1
        value=next(self.prefix,None)
        if value is not None:
            assert n==1
            return bytes((value,))
        return self.source.read(n)


class NoEntropy:
    def read(self,n): raise AssertionError("unexpected entropy")


@pytest.fixture(scope="module")
def family():
    rng=RankRandom(); backend=YuIBS(rng); params=YuParams()
    public,master=backend.setup(params)
    key=backend.key_extract(master,b"A")
    signatures=tuple(backend.sign(key,b"M") for _ in range(3))
    return SimpleNamespace(rng=rng,b=backend,p=params,pk=public,msk=master,sk=key,sigs=signatures)


def test_real_five_methods_and_fresh_signing(family):
    f=family
    assert isinstance(f.b,IBSBackend)
    assert f.sk.identity==b"A" and len(f.sk.identity_digest)==32
    assert len({s.to_bytes() for s in f.sigs})==3
    for s in f.sigs:
        assert f.b.verify(f.pk,b"A",b"M",s) is True
        loaded=f.b.load_signature(f.pk,s.to_bytes())
        assert loaded==s and f.b.verify(f.pk,b"A",b"M",loaded)
        assert len(s.to_bytes())<=signature_size(f.p,"reference")
    assert f.p.security_claim=="none" and not f.p.backend_admitted and not f.p.parameters_are_formal


def test_public_key_only_fresh_process(family):
    payload=dict(pk=family.pk.to_bytes().hex(),sig=family.sigs[0].to_bytes().hex())
    script='''
import json,sys
from ibme.ibs.yu import YuIBS,PublicKey
x=json.load(sys.stdin); b=YuIBS(); p=PublicKey.from_bytes(bytes.fromhex(x['pk']))
assert b.verify(p,b'A',b'M',b.load_signature(p,bytes.fromhex(x['sig'])))
print('PUBLIC_ONLY_OK')
'''
    result=subprocess.run([sys.executable,"-c",script],input=json.dumps(payload),text=True,
        capture_output=True,timeout=90,env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1"))
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()=="PUBLIC_ONLY_OK"


def test_real_roundtrip_master_key_and_empty_message(family):
    f=family
    for cls,obj in ((PublicKey,f.pk),(SigningKey,f.sk),(MasterSecret,f.msk)):
        restored=cls.from_bytes(obj.to_bytes())
        assert restored==obj and restored.to_bytes()==obj.to_bytes()
    master=MasterSecret.from_bytes(f.msk.to_bytes())
    key=YuIBS(NoEntropy()).key_extract(master,b"A")
    assert key.to_bytes()==f.sk.to_bytes()
    signature=YuIBS().sign(key,b"")
    assert YuIBS(NoEntropy()).verify(master.public_key,b"A",b"",signature)


def test_cached_concurrent_reads_consume_no_entropy(family):
    backend=YuIBS(NoEntropy())
    with ThreadPoolExecutor(8) as pool:
        keys=list(pool.map(lambda _:backend.key_extract(family.msk,b"A"),range(16)))
    assert all(k is family.sk for k in keys)


@pytest.mark.parametrize("stage",["setup","new_issue","sign","restore_master","restore_key"])
def test_thread_guard_precedes_sage_entropy_and_state(family,stage):
    from ibme.ibs.yu import YuThreadError
    master=MasterSecret.from_bytes(family.msk.to_bytes()); before=master.to_bytes()
    b=YuIBS(NoEntropy())
    actions=dict(setup=lambda:b.setup(family.p),new_issue=lambda:b.key_extract(master,b"B"),
        sign=lambda:b.sign(family.sk,b"M"),restore_master=lambda:MasterSecret.from_bytes(before),
        restore_key=lambda:SigningKey.from_bytes(family.sk.to_bytes()))
    with ThreadPoolExecutor(1) as pool:
        with pytest.raises(YuThreadError): pool.submit(actions[stage]).result(timeout=30)
    assert master.to_bytes()==before and master._active is False


def test_injective_length_encoding_and_binary_bytes():
    values=[b""]+[bytes((i,)) for i in range(256)]
    assert len({codec.input_bits(v,1) for v in values})==257
    assert codec.input_bits(b"",1)!=codec.input_bits(b"\0",1)
    assert codec.input_bits(b"A",2)!=codec.input_bits(b"A\0",2)
    assert len(codec.input_bits(b"\xff",1))==40


@pytest.mark.parametrize("bad",[None,"A",1,True,[],b"AB",memoryview(bytearray(4)).cast("I")])
def test_input_rejected_before_entropy(family,bad):
    b=YuIBS(NoEntropy())
    with pytest.raises(EncodingError): b.key_extract(family.msk,bad)
    with pytest.raises(EncodingError): b.sign(family.sk,bad)
    assert not b.verify(family.pk,bad,b"M",family.sigs[0])
    assert not b.verify(family.pk,b"A",bad,family.sigs[0])


class ShortBytes(bytes):
    def __len__(self): return 1


class ExplodingBytes(bytes):
    def __bytes__(self): raise RuntimeError("must not be called")


@pytest.mark.parametrize("bad",[ShortBytes(b"AB"),ExplodingBytes(b"A")])
def test_review_byte_subclass_rejected_before_ledger_or_conversion(family,bad):
    master=MasterSecret.from_bytes(family.msk.to_bytes()); before=master.to_bytes()
    with pytest.raises(EncodingError): YuIBS(NoEntropy()).key_extract(master,bad)
    assert master.to_bytes()==before
    assert not family.b.verify(family.pk,bad,b"M",family.sigs[0])
    for cls in (PublicKey,SigningKey,MasterSecret):
        with pytest.raises(SerializationError): cls.from_bytes(bad)


def test_released_buffer_is_canonical_failure(family):
    view=memoryview(b"A"); view.release()
    with pytest.raises(EncodingError): codec.input_bits(view,1)
    with pytest.raises(SerializationError): PublicKey.from_bytes(view)
    assert not family.b.verify(family.pk,view,b"M",family.sigs[0])


@pytest.mark.parametrize("field",["params","public_key","raw"])
def test_review_key_binding_fields_are_readonly(family,field):
    for obj in (family.msk,family.sk):
        with pytest.raises(AttributeError): setattr(obj,field,replace(family.p,max_users=17))
        check_object(obj,family.p)
        assert obj.params is obj.public_key.params


def test_review_full_issuer_capacity_not_mutable(family):
    from ibme.ibs.yu.keys import MasterSecret as Master
    one=replace(family.p,max_users=1)
    # raw mathematical parameters are unchanged: max_users is the service cap.
    pk=PublicKey(one,family.pk.raw); master=Master(pk,family.msk.raw)
    master._ledger[b"A"]="issued"
    master._keys[b"A"]=SigningKey(pk,b"A",family.sk.raw)
    with pytest.raises(AttributeError): master.params=replace(one,max_users=2)
    with pytest.raises(InvalidParameterError): YuIBS(NoEntropy()).key_extract(master,b"B")
    assert Master.from_bytes(master.to_bytes()).to_bytes()==master.to_bytes()


def test_empty_identity_rejected(family):
    with pytest.raises(EncodingError): YuIBS(NoEntropy()).key_extract(family.msk,b"")
    assert not family.b.verify(family.pk,b"",b"M",family.sigs[0])


@pytest.mark.parametrize("field",list(asdict(YuParams())))
@pytest.mark.parametrize("bad",[None,"1",1.0])
def test_parameter_exact_types(field,bad):
    with pytest.raises((ValueError,TypeError)): replace(YuParams(),**{field:bad})


@pytest.mark.parametrize("kwargs",[dict(q=9),dict(q=4),dict(m2=5),dict(m1=2),
    dict(max_users=0),dict(prf_dimension=2),dict(identity_max_bytes=4,message_max_bytes=4),
    dict(max_vectors=1),dict(n=True),dict(postprocess=1)])
def test_parameter_resource_and_algebra_gates(kwargs):
    with pytest.raises(ValueError): YuParams(**kwargs)


def test_wire_types_context_and_parameter_binding(family):
    f=family
    for cls in (PublicKey,MasterSecret,SigningKey):
        for value in (None,{},"secret",b"x",b"x"*(codec.MAX_OBJECT+1)):
            with pytest.raises(SerializationError): cls.from_bytes(value)
    for sig in (None,{},b"x",f.pk,replace(f.sigs[0],context=bytes(32))):
        assert not f.b.verify(f.pk,b"A",b"M",sig)
    with pytest.raises(SerializationError):
        Signature.from_bytes(replace(f.sigs[0],context=bytes(32)).to_bytes(),f.pk)
    with pytest.raises(SerializationError): check_object(f.pk,replace(f.p,max_users=17))
    assert "<redacted>" in repr(f.sk) and "<redacted>" in repr(f.msk)


@pytest.mark.parametrize("kind",["PK","MSK","SK","SIG"])
def test_truncation_append_duplicates_noncanonical_json(family,kind):
    objects={"PK":family.pk,"MSK":family.msk,"SK":family.sk,"SIG":family.sigs[0]}
    load=(lambda data: Signature.from_bytes(data,family.pk)) if kind=="SIG" else type(objects[kind]).from_bytes
    value=objects[kind].to_bytes()
    cuts=range(len(value)) if kind=="SIG" else [0,1,10,len(value)//2,len(value)-1]
    for i in cuts:
        with pytest.raises(SerializationError): load(value[:i])
    for suffix in (b"\0",value):
        with pytest.raises(SerializationError): load(value+suffix)
    prefix=codec.MAGIC+kind.encode()+b"\0"
    for body in (b'{"x":1,"x":2}',b'{ "x": 1 }',b'{"x":1.0}',b'{"x":NaN}',
                 b'{"x":'+b'1'*311+b'}',b'['*1100+b']'*1100):
        with pytest.raises(SerializationError): load(prefix+len(body).to_bytes(4,"big")+body)


@pytest.mark.parametrize("bad",[True,0.0,-1,3,"0",None])
def test_public_matrix_exact_residues(family,bad):
    data=codec.decode("PK",family.pk.to_bytes()); data["a"][0][0]=bad
    with pytest.raises(SerializationError): PublicKey.from_bytes(codec.encode("PK",data))


@pytest.mark.parametrize("mutation",["missing","extra","wrong_count","wrong_shape","param","huge"])
def test_public_schema_precedes_expensive_work(family,mutation,monkeypatch):
    data=codec.decode("PK",family.pk.to_bytes())
    if mutation=="missing": del data["hat"]
    elif mutation=="extra": data["secret"]=1
    elif mutation=="wrong_count": data["tilde"].pop()
    elif mutation=="wrong_shape": data["a"][0].pop()
    elif mutation=="param": data["params"]["q"]=9
    elif mutation=="huge": data["a"][0][0]=1<<1024
    with pytest.raises(SerializationError): PublicKey.from_bytes(codec.encode("PK",data))


@pytest.mark.parametrize("mutation",["zero_basis","non_kernel","identity","pattern","huge"])
def test_private_restore_validates_lattice_and_binding(family,mutation):
    data=codec.decode("SK",family.sk.to_bytes()); user=data["user"]
    if mutation=="zero_basis": user["basis"][0]=[0]*len(user["basis"])
    elif mutation=="non_kernel":
        # q times an entry can stay in kernel but changes determinant; zero
        # basis test above covers rank, this covers concrete congruence.
        j=next(j for j,a in enumerate(family.pk.raw.a[0]) if a)
        user["basis"][j][0]+=1
    elif mutation=="identity": user["identity"]=""
    elif mutation=="pattern": user["r_hat"]=[2]
    elif mutation=="huge": user["basis"][0][0]=1<<1024
    with pytest.raises(SerializationError): SigningKey.from_bytes(codec.encode("SK",data))


@pytest.mark.parametrize("mutation",["duplicate","state","identity_mismatch","empty","missing_key"])
def test_master_ledger_rejects_malformed_state(family,mutation):
    data=codec.decode("MSK",family.msk.to_bytes()); entry=data["ledger"][0]
    if mutation=="duplicate": data["ledger"].append(entry)
    elif mutation=="state": entry["status"]="ready"
    elif mutation=="identity_mismatch": entry["user"]["identity"]="42"
    elif mutation=="empty": entry["identity"]=""
    elif mutation=="missing_key": del entry["user"]
    with pytest.raises(SerializationError): MasterSecret.from_bytes(codec.encode("MSK",data))


@pytest.mark.parametrize("status",["pending","failed"])
def test_restored_tombstone_blocks_automatic_redraw(family,status):
    data=codec.decode("MSK",family.msk.to_bytes())
    data["ledger"].append(dict(identity="42",status=status))
    master=MasterSecret.from_bytes(codec.encode("MSK",data))
    with pytest.raises(IssuancePending): YuIBS(NoEntropy()).key_extract(master,b"B")


@pytest.mark.parametrize("stage",["setup","keygen","sign"])
def test_fault_injected_sampler_abort_is_not_retried(family,stage,monkeypatch):
    calls=[]
    def abort(*args,**kwargs): calls.append(1); raise SamplingAbort("private diagnostics must not escape")
    monkeypatch.setattr(raw,stage,abort)
    backend=YuIBS(NoEntropy()); master=MasterSecret.from_bytes(family.msk.to_bytes())
    with pytest.raises(YuSamplingAbort) as error:
        if stage=="setup": backend.setup(family.p)
        elif stage=="keygen": backend.key_extract(master,b"B")
        else: backend.sign(family.sk,b"M")
    assert len(calls)==1 and "private" not in str(error.value)
    if stage=="keygen":
        assert master._ledger[b"B"]=="failed" and b"B" not in master._keys
        with pytest.raises(IssuancePending): backend.key_extract(master,b"B")


def test_fault_injected_reservation_failure_never_draws(family):
    master=MasterSecret.from_bytes(family.msk.to_bytes()); states=[]
    def fail(current):
        states.append(current._ledger[b"B"])
        raise OSError("storage fault")
    master.persist_callback=fail
    with pytest.raises(OSError): YuIBS(NoEntropy()).key_extract(master,b"B")
    assert states==["pending","failed"] and b"B" not in master._keys


def test_registry_handoff_is_explicit_and_rejects_wang_capacity(family):
    from ibme.assembly import make_suite,validate_suite
    from ibme.assembly.registry import BackendRegistry,default_registry
    default=default_registry()
    # The existing candidate entry is not overwritten by importing Yu.
    assert not default.get("ibs","yu2026").available
    spec=backend_spec(); registry=BackendRegistry((default.get("hibe","mock"),spec))
    for name,obj in (("ipk",family.pk),("imsk",family.msk),("sk",family.sk)):
        assert spec.decoders[name].from_bytes(obj.to_bytes())==obj
    config=make_suite(hibe="mock",ibs="yu2026",allow_mock=True,registry=registry)
    report=validate_suite(config,registry=registry)
    assert not report.ok and any("capacity" in e for e in report.errors)
    validate_configuration(family.p,None)
    assert spec.master_public_key(family.msk)==family.pk


def test_public_forgery_and_wrong_identity_counterexample_remain_visible(family):
    p=family.p
    forged=Signature(family.pk.context,raw.Signature((p.q,)+(0,)*(p.signature_dimension-1),
        (0,)*p.output_bits,(0,)*p.output_bits,(0,)*p.salt_bits))
    # No secret key, no signature query, valid wire/context, wrong ID/message.
    for ident,msg in ((b"A",b"M"),(b"B",b"N"),(b"\xff",b"")):
        assert family.b.verify(family.pk,ident,msg,forged)
    zero=replace(forged,raw=replace(forged.raw,s=(0,)*p.signature_dimension))
    assert not family.b.verify(family.pk,b"A",b"M",zero)
