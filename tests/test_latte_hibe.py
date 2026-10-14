"""Real LATTE-3 primitive contracts; Sage + explicit native build, no mock fallback."""
import hashlib
import json
from dataclasses import replace
from pathlib import Path
import struct
import subprocess
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
pytest.importorskip("sage.all",reason="prescribed WSL ~/miniconda3/envs/sage required")

from ibme.core.errors import EncodingError,SerializationError,InvalidParameterError
from ibme.core.randomness import SecureRandom,DeterministicRandom
from ibme.hibe.latte import (LATTEHIBE,LATTEParams,LATTEPublicKey,LATTEMasterSecret,
    LATTELevel1SecretKey,LATTELevel2SecretKey,LATTECiphertext,backend_spec)
from ibme.hibe.latte.engine import Native,NativeOperationError,pack
from ibme.hibe.latte.params import Q,N
from ibme.hibe.latte.codec import canonical


class NoEntropy:
    def __init__(self): self.calls=0
    def read(self,n):
        self.calls+=1
        raise AssertionError("unexpected private entropy")


@pytest.fixture(scope="module")
def saved():
    # Explicit TEST randomness. Independent lifecycle probe uses system CSPRNG.
    backend=LATTEHIBE(); p=LATTEParams()
    pk,master=backend.setup(p,rng=DeterministicRandom(b"LATTE real test root"))
    parent=backend.extract(master,b"Bob",rng=DeterministicRandom(b"LATTE real test receiver"))
    leaf=backend.derive(parent,b"Alice")
    return backend,pk,master.to_bytes(),parent.to_bytes(),leaf.to_bytes()


def test_real_six_methods_fresh_encryption_and_five_object_roundtrips(saved):
    backend,pk,mraw,praw,lraw=saved
    master=LATTEMasterSecret.from_bytes(mraw)
    parent=LATTELevel1SecretKey.from_bytes(praw)
    leaf=LATTELevel2SecretKey.from_bytes(lraw)
    message=bytes(range(32))
    a=backend.encrypt(pk,b"Bob",b"Alice",message,rng=DeterministicRandom(b"LATTE cipher one"))
    b=backend.encrypt(pk,b"Bob",b"Alice",message,rng=DeterministicRandom(b"LATTE cipher two"))
    assert a.to_bytes()!=b.to_bytes()
    assert backend.decrypt(leaf,a)==backend.decrypt(leaf,b)==message
    for value in (pk,master,parent,leaf,a):
        restored=type(value).from_bytes(value.to_bytes())
        assert restored.to_bytes()==value.to_bytes()
    assert backend.load_ciphertext(a.to_bytes()).to_bytes()==a.to_bytes()
    assert all(backend.validate_key_binding(pk,key) is True for key in (master,parent,leaf))


def test_same_root_two_receivers_four_real_leaf_keys_and_mismatches(saved):
    backend,pk,mraw,_,_=saved
    master=LATTEMasterSecret.from_bytes(mraw)
    parents={p:backend.extract(master,p,rng=DeterministicRandom(b"receiver "+p)) for p in (b"Bob",b"Carol")}
    keys={(p,s):backend.derive(key,s) for p,key in parents.items() for s in (b"Alice",b"Eve")}
    message=hashlib.sha256(b"LATTE same root 2x2").digest()
    for path,key in keys.items():
        ct=backend.encrypt(pk,*path,message)
        for other,other_key in keys.items():
            assert backend.decrypt(other_key,ct)==(message if path==other else None)
    assert len(master._entries)==2 and all(len(k._entries)==2 for k in parents.values())


def test_terminal_extract_is_original_deterministic_sampling_not_fresh_external_rng(saved):
    backend,_,_,praw,_=saved
    a=LATTELevel1SecretKey.from_bytes(praw)
    b=LATTELevel1SecretKey.from_bytes(praw)
    guard=NoEntropy()
    first=backend.derive(a,b"Another",rng=guard)
    second=backend.derive(b,b"Another",rng=guard)
    assert first.to_bytes()==second.to_bytes() and guard.calls==0


def test_restore_and_same_address_reuse_never_construct_native_or_sample(saved,monkeypatch):
    backend,pk,mraw,_,_=saved
    def forbidden(*args,**kwargs): raise AssertionError("restore/reuse invoked native sampling")
    monkeypatch.setattr("ibme.hibe.latte.backend.Native",forbidden)
    monkeypatch.setattr(SecureRandom,"read",forbidden)
    master=LATTEMasterSecret.from_bytes(mraw)
    parent=backend.extract(master,b"Bob",rng=NoEntropy())
    leaf=backend.derive(parent,b"Alice",rng=NoEntropy())
    assert master.to_bytes()==mraw and backend.validate_key_binding(pk,leaf)


def test_native_failure_keeps_pending_and_restore_blocks_reissue(saved,monkeypatch):
    _,_,mraw,_,_=saved
    master=LATTEMasterSecret.from_bytes(mraw)
    snapshots=[]
    backend=LATTEHIBE(persist_pending=lambda obj:snapshots.append(obj.to_bytes()))
    original=Native.call
    def fail(self,operation,data):
        if operation=="delegate": raise NativeOperationError("injected actual-operation abort")
        return original(self,operation,data)
    monkeypatch.setattr(Native,"call",fail)
    with pytest.raises(NativeOperationError,match="injected"):
        backend.extract(master,b"failed",rng=DeterministicRandom(b"LATTE abort"))
    assert len(snapshots)==1 and master.to_bytes()==snapshots[0]
    restored=LATTEMasterSecret.from_bytes(snapshots[0]); guard=NoEntropy()
    with pytest.raises(NativeOperationError,match="reissue forbidden"):
        backend.extract(restored,b"failed",rng=guard)
    assert guard.calls==0


def test_pending_persistence_failure_precedes_private_entropy(saved):
    _,_,mraw,_,_=saved
    master=LATTEMasterSecret.from_bytes(mraw); guard=NoEntropy()
    def fail(obj): raise OSError("private store unavailable")
    backend=LATTEHIBE(persist_pending=fail)
    with pytest.raises(OSError): backend.extract(master,b"failed",rng=guard)
    assert master._entries[b"failed"] is None and guard.calls==0


def test_same_address_concurrency_performs_one_real_delegation(saved,monkeypatch):
    backend,_,mraw,_,_=saved; master=LATTEMasterSecret.from_bytes(mraw)
    barrier=Barrier(2); calls=[]; original=Native.call
    def counted(self,operation,data):
        if operation=="delegate": calls.append(1)
        return original(self,operation,data)
    monkeypatch.setattr(Native,"call",counted)
    def worker(i):
        barrier.wait(timeout=10)
        return backend.extract(master,b"concurrent",rng=DeterministicRandom(b"LATTE thread"+bytes([i]))).to_bytes()
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures=[pool.submit(worker,i) for i in range(2)]
        values=[f.result(timeout=60) for f in futures]
    assert values[0]==values[1] and len(calls)==1


@pytest.mark.parametrize("kind",["public","master","parent","leaf","ciphertext"])
def test_each_object_rejects_truncation_append_duplicates_and_unknown_fields(saved,kind):
    backend,pk,mraw,praw,lraw=saved
    ct=backend.encrypt(pk,b"Bob",b"Alice",bytes(32))
    cls,raw={"public":(LATTEPublicKey,pk.to_bytes()),"master":(LATTEMasterSecret,mraw),
        "parent":(LATTELevel1SecretKey,praw),"leaf":(LATTELevel2SecretKey,lraw),
        "ciphertext":(LATTECiphertext,ct.to_bytes())}[kind]
    value=json.loads(raw); value["unknown"]=1
    bad=[raw[:-1],raw+b"x",raw+raw,b'{"schema":"duplicate",'+raw[1:],canonical(value),raw+b" "]
    for data in bad:
        with pytest.raises(SerializationError): cls.from_bytes(data)


@pytest.mark.parametrize("change",["sub-lattice","kernel","path","context","pending-key"])
def test_real_private_snapshot_tampering_is_rejected(saved,change):
    _,_,mraw,praw,_=saved
    value=json.loads(praw)
    if change=="sub-lattice": value["basis"][0]=[2*x for x in value["basis"][0]]; value["basis"][1]=[2*x for x in value["basis"][1]]; value["basis"][2]=[2*x for x in value["basis"][2]]
    elif change=="kernel": value["basis"][0][0]+=1
    elif change=="path": value["identity"]=b"Carol".hex()
    elif change=="context": value["public"]["h"][0]=(value["public"]["h"][0]+1)%Q
    else:
        value["entries"][0]["identity"]=b"Eve".hex()
    with pytest.raises(SerializationError): LATTELevel1SecretKey.from_bytes(canonical(value))


@pytest.mark.parametrize("what",["z","c0","c1","c2","public_digest","mode"])
def test_native_reencryption_rejects_ciphertext_tampering(saved,what):
    backend,pk,_,_,lraw=saved; leaf=LATTELevel2SecretKey.from_bytes(lraw)
    value=backend.encrypt(pk,b"Bob",b"Alice",bytes(range(32))).record()
    if what in ("z","public_digest"):
        raw=bytes.fromhex(value[what]); value[what]=(bytes([raw[0]^1])+raw[1:]).hex()
    elif what=="mode": value["params"]["message_mode"]="framed32"
    else:
        c=[list(row) for row in value["c"]]; i=int(what[1:]); c[i][0]=(c[i][0]+1)%Q; value["c"]=c
    ct=LATTECiphertext.from_bytes(canonical(value))
    assert backend.decrypt(leaf,ct) is None


@pytest.mark.parametrize("payload",[b"",b"a",bytes(28)])
def test_framed_mode_supports_empty_and_bounded_messages(payload):
    backend=LATTEHIBE(); pk,master=backend.setup(LATTEParams(message_mode="framed32"))
    leaf=backend.derive(backend.extract(master,b"R"*86),b"S"*86)
    ct=backend.encrypt(pk,b"R"*86,b"S"*86,payload)
    assert backend.decrypt(leaf,ct)==payload
    assert b"R"*86 not in ct.to_bytes() and (b"R"*86).hex().encode() not in ct.to_bytes()


@pytest.mark.parametrize("target",[b"",b"x"*87,"string",True])
def test_invalid_id_before_entropy(saved,target):
    backend,pk,mraw,_,_=saved; guard=NoEntropy()
    with pytest.raises(EncodingError): backend.encrypt(pk,target,b"Alice",bytes(32),rng=guard)
    with pytest.raises(EncodingError): backend.extract(LATTEMasterSecret.from_bytes(mraw),target,rng=guard)
    assert guard.calls==0


@pytest.mark.parametrize("field,value",[("identity_bytes",True),("max_children",0),("max_receivers",9),("native_timeout_seconds",301),("message_mode","silent")])
def test_parameter_resource_limits_are_explicit(field,value):
    with pytest.raises(InvalidParameterError): LATTEParams(**{field:value})


def test_missing_native_source_mismatch_and_bad_entropy_never_fall_back(saved,monkeypatch,tmp_path):
    backend,pk,_,_,_=saved; guard=NoEntropy()
    monkeypatch.setenv("IBME_LATTE3_EXECUTABLE",str(tmp_path/"absent"))
    with pytest.raises(InvalidParameterError): backend.encrypt(pk,b"Bob",b"Alice",bytes(32),rng=guard)
    assert guard.calls==0
    monkeypatch.delenv("IBME_LATTE3_EXECUTABLE")
    monkeypatch.setattr("ibme.hibe.latte.native.build.source_id",lambda:"0"*64)
    with pytest.raises(InvalidParameterError,match="frozen source"):
        backend.setup(pk.params,rng=guard)
    assert guard.calls==0


def test_shake_shim_is_exact_and_gaussian_moments_are_only_diagnostics():
    engine=Native(LATTEParams()); seed=bytes(range(32))
    assert engine.call("shake",seed)==hashlib.shake_256(seed).digest(64)
    for kind,sigma in ((0,3),(1,6777.587966298392)):
        values=struct.unpack("<4096q",engine.call("scalar",seed+bytes([kind])))
        mean=sum(values)/4096/sigma
        second=sum(x*x for x in values)/4096/sigma**2
        assert abs(mean)<0.08 and 0.80<second<1.20


@pytest.mark.parametrize("operation",["setup","delegate","extract","encrypt","decrypt"])
def test_native_rejects_truncated_private_inputs_without_output(operation):
    engine=Native(LATTEParams())
    result=subprocess.run([str(engine.path),operation],input=b"truncated",capture_output=True,timeout=10)
    assert result.returncode==65 and result.stdout==b""


def test_explicit_spec_and_installed_payload_are_not_silent_global_registration(saved):
    from ibme.assembly.registry import BackendRegistry,default_registry
    spec=backend_spec(); registry=BackendRegistry([spec])
    assert registry.get("hibe","latte3-research").two_level
    assert default_registry().get("hibe","latte").available is False
    assert spec.ciphertext_size(LATTEParams(),32,86)>3*N*8
    assert spec.default_preset({"transport":"hybrid"})=="seed32"


def test_short_entropy_after_pending_is_not_retried(saved):
    backend,_,mraw,_,_=saved; master=LATTEMasterSecret.from_bytes(mraw)
    class Short:
        def read(self,n): return b"short"
    with pytest.raises(ValueError,match="short seed"):
        backend.extract(master,b"short-source",rng=Short())
    assert master._entries[b"short-source"] is None
    with pytest.raises(NativeOperationError,match="reissue forbidden"):
        backend.extract(master,b"short-source",rng=NoEntropy())


def test_cross_root_binding_and_receiver_capacity(saved):
    backend,pk,mraw,_,lraw=saved
    other,_=backend.setup(pk.params,rng=DeterministicRandom(b"independent LATTE root"))
    key=LATTELevel2SecretKey.from_bytes(lraw)
    assert backend.validate_key_binding(other,key) is False
    assert backend.decrypt(key,backend.encrypt(other,b"Bob",b"Alice",bytes(32))) is None
    master=LATTEMasterSecret.from_bytes(mraw)
    backend.extract(master,b"Carol")
    guard=NoEntropy()
    with pytest.raises(InvalidParameterError,match="capacity"):
        backend.extract(master,b"Third",rng=guard)
    assert guard.calls==0


@pytest.mark.parametrize("value",[True,1.0,-1,Q,2**100])
def test_noncanonical_polynomial_values_rejected(saved,value):
    _,pk,_,_,_=saved; record=pk.record(); record["h"]=list(record["h"]); record["h"][0]=value
    with pytest.raises(SerializationError): LATTEPublicKey.from_bytes(canonical(record))


def test_hybrid_adapter_uses_same_real_hibe_and_full_width_identities():
    pytest.importorskip("cryptography")
    from ibme.protocol.hybrid_hibe import HybridHIBE,HybridHIBEParams,HybridLimits
    backend=HybridHIBE(LATTEHIBE(),backend_id=b"latte3-research",public_key_type=LATTEPublicKey,
        master_type=LATTEMasterSecret,level1_type=LATTELevel1SecretKey,level2_type=LATTELevel2SecretKey)
    p=HybridHIBEParams(LATTEParams(),HybridLimits(backend_id=b"latte3-research"))
    pk,master=backend.setup(p)
    leaf=backend.derive(backend.extract(master,b"Receiver"),b"Sender")
    message=b"real LATTE hybrid capacity check"*10
    ct=backend.encrypt(pk,b"Receiver",b"Sender",message)
    assert backend.decrypt(leaf,ct)==message


def test_whole_tree_pending_persistence_and_concurrent_parent_leaf_do_not_deadlock(saved):
    _,_,mraw,_,_=saved
    master=LATTEMasterSecret.from_bytes(mraw)
    snapshots=[]; barrier=Barrier(2)
    backend=LATTEHIBE(persist_pending=lambda owner:snapshots.append(master.to_bytes()))
    parent=backend.extract(master,b"Bob")
    def leaf():
        barrier.wait(timeout=10)
        return backend.derive(parent,b"NewChild")
    def receiver():
        barrier.wait(timeout=10)
        return backend.extract(master,b"NewReceiver")
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures=[pool.submit(leaf),pool.submit(receiver)]
        values=[future.result(timeout=60) for future in futures]
    assert len(snapshots)==2 and all(LATTEMasterSecret.from_bytes(raw) for raw in snapshots)
    assert master._entries[b"NewReceiver"] is values[1]
    assert master._entries[b"Bob"]._entries[b"NewChild"] is values[0]
