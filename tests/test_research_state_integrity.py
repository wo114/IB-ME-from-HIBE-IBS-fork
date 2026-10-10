"""Fixed research profiles and concurrent real CLI identity issuance."""

from dataclasses import replace
from hashlib import sha256
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

pytest.importorskip("cryptography")
from ibme.cli import _sender_key_path
from ibme.core.errors import SerializationError
from ibme.protocol.baseline import MasterSecret, PublicKey
from ibme.protocol.hybrid_hibe import HybridPublicKey, HybridMasterSecret, HybridLevel1SecretKey, HybridLevel2SecretKey
from ibme.protocol.luo_hybrid import make_research_runtime, RESEARCH_HIBE_PARAMS, RESEARCH_IBS_PARAMS
from ibme.core.randomness import DeterministicRandom


@pytest.fixture(scope="module")
def initial():
    protocol, readers = make_research_runtime(ibs_rng=DeterministicRandom(b"state-fixed-ibs"))
    public, master = protocol.setup(RESEARCH_HIBE_PARAMS, ibs_params=RESEARCH_IBS_PARAMS,
                                   rng=DeterministicRandom(b"state-fixed-hibe"))
    receiver = protocol.rkgen(master, b"Bob", rng=DeterministicRandom(b"state-fixed-rk"))
    child = protocol.hibe_backend.derive(receiver.level1_key, b"Alice",
                                        rng=DeterministicRandom(b"state-fixed-child"))
    return public, master, receiver.level1_key, child, readers


def write_initial_state(root, initial):
    from ibme.cli import _write_state_meta
    public, master, _, _, _ = initial
    state = root/"state"
    state.mkdir()
    (state/"mpk.bin").write_bytes(public.to_bytes())
    (state/"msk.bin").write_bytes(master.to_bytes())
    _write_state_meta(state,mock=False,preset="luo-module-research",
                      hibe_params=RESEARCH_HIBE_PARAMS,ibs_params=RESEARCH_IBS_PARAMS)
    return state


@pytest.mark.parametrize("field,value", [
    ("identity_bytes",85), ("max_message_bytes",31),
    ("s0",4.0), ("s_enc",2.0), ("s_pre",2.0),
])
def test_profile_rejects_changed_inner_public_metadata(initial, field, value):
    public, _, _, _, readers = initial
    inner = replace(public.hpk.inner, meta=replace(public.hpk.inner.meta, **{field:value}))
    changed = HybridPublicKey(public.hpk.limits, inner)
    with pytest.raises(SerializationError):
        readers["hpk"].from_bytes(changed.to_bytes())


@pytest.mark.parametrize("kind", ["hmsk","sk1","sk2"])
def test_profile_rejects_secret_metadata_hidden_behind_unchanged_public(initial, kind):
    _, master, receiver, child, readers = initial
    value = {"hmsk":master.hmsk,"sk1":receiver,"sk2":child}[kind]
    inner = replace(value.inner, meta=replace(value.inner.meta, s_pre=2.0))
    changed = replace(value, inner=inner)
    with pytest.raises(SerializationError):
        readers[kind].from_bytes(changed.to_bytes())


WORKER = r"""
import argparse, pathlib, time, shutil
from types import SimpleNamespace
from ibme import cli
root=pathlib.Path(__import__('sys').argv[1])
label,name,role=__import__('sys').argv[2:]
original=cli._load_msk
def load(*args,**kwargs):
    result=original(*args,**kwargs)
    (root/('loaded-'+label)).write_text('ready')
    if label=='A':
        end=time.monotonic()+20
        while not (root/'release-A').exists():
            if time.monotonic()>=end: raise RuntimeError('worker release timeout')
            time.sleep(0.01)
    return result
cli._load_msk=load
(root/('started-'+label)).write_text('ready')
args=SimpleNamespace(state=root/'state',mock=False,name=name)
code=(cli.cmd_issue_sender_key if role=='sender' else cli.cmd_issue_receiver_key)(args)
if code!=0: raise RuntimeError('CLI issuance failed')
path=(cli._sender_key_path if role=='sender' else cli._receiver_key_path)(args.state,name.encode())
shutil.copyfile(path,root/('issued-'+label+'.bin'))
"""


def wait_file(path, process, timeout=20):
    end=time.monotonic()+timeout
    while not path.exists():
        if process.poll() is not None:
            _,error=process.communicate()
            pytest.fail("issuance worker exited before barrier: "+error)
        if time.monotonic()>=end:
            pytest.fail("issuance barrier timeout")
        time.sleep(0.01)


@pytest.mark.parametrize("other_name,first_role", [
    ("Alice","sender"), ("Carol","sender"), ("Alice","receiver"),
])
def test_concurrent_issuance_preserves_fixed_key_and_all_cached_identities(initial, tmp_path, other_name, first_role):
    import json
    _, _, _, _, readers=initial
    state=write_initial_state(tmp_path,initial)
    source=Path(__file__).resolve().parents[1]/"src"
    environment={**os.environ,"PYTHONPATH":str(source),"PYTHONDONTWRITEBYTECODE":"1"}
    first_name="Alice" if first_role=="sender" else "Bob"
    processes=[]
    try:
        a=subprocess.Popen([sys.executable,"-B","-c",WORKER,str(tmp_path),"A",first_name,first_role],
                           env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        processes.append(a)
        wait_file(tmp_path/"loaded-A",a)
        b=subprocess.Popen([sys.executable,"-B","-c",WORKER,str(tmp_path),"B",other_name,"sender"],
                           env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        processes.append(b)
        wait_file(tmp_path/"started-B",b)
        # Before the fix B reads A's stale master and can finish while A is held.
        # With an issuance transaction B cannot read until A commits and releases.
        end=time.monotonic()+1
        while not (tmp_path/"loaded-B").exists() and time.monotonic()<end:
            time.sleep(0.01)
        if (tmp_path/"loaded-B").exists():
            _,error=b.communicate(timeout=20)
            assert b.returncode==0,error
        (tmp_path/"release-A").write_text("go")
        for child in processes:
            _,error=child.communicate(timeout=25)
            assert child.returncode==0,error
        restored=MasterSecret.from_bytes((state/"msk.bin").read_bytes(),readers["hmsk"],readers["imsk"])
        expected={other_name.encode()}
        if first_role=="sender": expected.add(b"Alice")
        assert set(restored.imsk.cached_identities)==expected
        if first_role=="sender" and other_name=="Alice":
            assert sha256((tmp_path/"issued-A.bin").read_bytes()).digest()==sha256((tmp_path/"issued-B.bin").read_bytes()).digest()
        protocol,_=make_research_runtime()
        saved=(tmp_path/"issued-B.bin").read_bytes()
        replay=protocol.skgen(restored,other_name.encode()).to_bytes()
        assert sha256(saved).digest()==sha256(replay).digest()
        assert json.loads((state/"state.json").read_text())["security_claim"]=="none"
    finally:
        (tmp_path/"release-A").write_text("go")
        for child in processes:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=5)


def test_fixed_profile_rejects_a_coherent_other_HIBE_modulus():
    from ibme.protocol.hybrid_hibe import HybridHIBEParams
    from ibme.protocol.luo_hybrid import make_hybrid_abb10, RESEARCH_INNER_PARAMS
    hibe=make_hybrid_abb10()
    other=replace(RESEARCH_INNER_PARAMS,q=65536,m_matrix=144)
    public,_=hibe.setup(HybridHIBEParams(other,RESEARCH_HIBE_PARAMS.limits),
                        rng=DeterministicRandom(b"coherent-other-HIBE"))
    assert hibe.load_public_key(public.to_bytes()).to_bytes()==public.to_bytes()
    _,readers=make_research_runtime()
    with pytest.raises(SerializationError): readers["hpk"].from_bytes(public.to_bytes())


@pytest.mark.parametrize("profile,mock", [("education",True),("luo-module-research",False)])
def test_setup_cannot_overwrite_existing_research_state_by_switching_profile(initial,tmp_path,profile,mock):
    from types import SimpleNamespace
    from ibme.cli import cmd_setup
    state=write_initial_state(tmp_path,initial)
    before={name:sha256((state/name).read_bytes()).digest() for name in ("state.json","mpk.bin","msk.bin")}
    with pytest.raises(ValueError):
        cmd_setup(SimpleNamespace(state=state,params=profile,mock=mock,signature_format="reference"))
    assert before=={name:sha256((state/name).read_bytes()).digest() for name in before}


@pytest.mark.parametrize("fail_master", [True,False])
def test_snapshot_publication_failure_has_safe_retry_semantics(initial,tmp_path,monkeypatch,fail_master):
    from types import SimpleNamespace
    from ibme import cli
    _,_,_,_,readers=initial
    state=write_initial_state(tmp_path,initial)
    output=_sender_key_path(state,b"Alice")
    destination=state/"msk.bin" if fail_master else output
    original=cli.os.replace
    def fail(source,target):
        if Path(target)==destination: raise OSError("injected publication failure")
        return original(source,target)
    args=SimpleNamespace(state=state,name="Alice",mock=False)
    with monkeypatch.context() as patch:
        patch.setattr(cli.os,"replace",fail)
        with pytest.raises(OSError): cli.cmd_issue_sender_key(args)
    assert not output.exists()
    assert not list(state.glob(".ibme-state-*.tmp"))
    restored=MasterSecret.from_bytes((state/"msk.bin").read_bytes(),readers["hmsk"],readers["imsk"])
    assert restored.imsk.cached_identities==(() if fail_master else (b"Alice",))
    if not fail_master:
        protocol,_=make_research_runtime()
        cached_digest=sha256(protocol.skgen(restored,b"Alice").to_bytes()).digest()
    assert cli.cmd_issue_sender_key(args)==0
    if not fail_master: assert sha256(output.read_bytes()).digest()==cached_digest


@pytest.mark.parametrize("second_operation", ["extract","snapshot"])
def test_shared_module_master_serializes_threaded_extraction_and_snapshots(second_operation):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from ibme.ibs.luo_module import LuoModuleIBSBackend, LuoModuleParams, LuoModuleMasterSecret
    p=LuoModuleParams(degree=8,k=2,l=1,q=769,root=27,kappa=1,gamma1=16,
                      gamma2=256,gamma3=128,dropped_bits=3)
    a=LuoModuleIBSBackend(rng=DeterministicRandom(b"cache-thread-A"))
    b=LuoModuleIBSBackend(rng=DeterministicRandom(b"cache-thread-B"))
    public,master=a.setup(p)
    entered,release,started=Event(),Event(),Event()
    original=a._draw
    first=True
    def held_draw(*args):
        nonlocal first
        if first:
            first=False
            entered.set()
            if not release.wait(10): raise RuntimeError("thread release timeout")
        return original(*args)
    a._draw=held_draw
    def second():
        started.set()
        return b.key_extract(master,b"Alice") if second_operation=="extract" else master.to_bytes()
    with ThreadPoolExecutor(max_workers=2) as pool:
        first_result=pool.submit(a.key_extract,master,b"Alice")
        try:
            assert entered.wait(5)
            second_result=pool.submit(second)
            assert started.wait(5)
            time.sleep(0.1)
            assert not second_result.done()
        finally:
            release.set()
        key=first_result.result(timeout=5)
        other=second_result.result(timeout=5)
    if second_operation=="snapshot":
        restored=LuoModuleMasterSecret.from_bytes(other)
        other=b.key_extract(restored,b"Alice")
    assert sha256(key.to_bytes()).digest()==sha256(other.to_bytes()).digest()
    assert master.cached_identities==(b"Alice",)
