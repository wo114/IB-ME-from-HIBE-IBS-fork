"""Source/Sage HIBE contracts and persisted failure controls, not security proof."""

from dataclasses import replace
from pathlib import Path
import json
import os

import pytest
pytest.importorskip("sage.all",reason="Prescribed WSL Sage required; skip is not pass")

from ibme.assembly import build_runtime,make_suite,validate_suite
from ibme.core.errors import InvalidParameterError,RandomnessError,SerializationError
from ibme.core.errors import EncodingError
from ibme.core.randomness import DeterministicRandom
from ibme.protocol.baseline import PublicKey,MasterSecret
from experiments.research.gaussian_reference import SamplingAbort
from experiments.research.first_suite.computational_root import ComputationalRootParams,ComputationalRootGenerator
from experiments.research.first_suite.hibe_reference import (MP12HIBEParams,MP12HIBEPublicKey,
    MP12HIBEMasterSecret,MP12HIBEReceiver,MP12HIBELeaf,MP12HIBECiphertext,MP12CHKPResearchHIBE)
from experiments.research.first_suite.hibe_registry import research_suite,raw_ciphertext_size,check_object
from experiments.research.first_suite.seed_kem import SeedCapsule

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = Path(os.environ.get("IBME_A_HIBE_PRIVATE_DIR",str(ROOT/"test-results/a-hibe-contract/private")))
ENGINE = ROOT/"test-results/qfall-target/release/ibme-qfall-private-root"


class NoEntropy:
    def read(self,n): raise AssertionError("invalid/reuse input consumed entropy")


class BadEntropy:
    def __init__(self): self.reads=0
    def read(self,n): self.reads+=1;return b""


@pytest.fixture(scope="module")
def saved():
    if not (PRIVATE/"master-Bob.bin").is_file():
        pytest.skip("explicit real saved probe required; no mock/reseed fallback")
    config,registry=research_suite(ENGINE);runtime=build_runtime(config,registry=registry)
    public=PublicKey.from_bytes((PRIVATE/"public.bin").read_bytes(),runtime.decoders["hpk"],runtime.decoders["ipk"])
    return runtime,public


@pytest.mark.parametrize("change",[
    dict(n=True),dict(n=1),dict(q=15),dict(n=4),dict(r_width_squared=True),
    dict(r_width_squared=1),dict(identity_bytes=87),dict(max_children=3),
    dict(max_receivers=0),dict(security_claim="128-bit"),dict(backend_admitted=True),
    dict(parameters_are_formal=True),dict(backend_admitted=0),
])
def test_invalid_full_profile_has_no_entropy_or_fallback(change):
    with pytest.raises(InvalidParameterError): MP12HIBEParams(**change)


def test_all_same_input_conditions_and_profile_roundtrip_are_explicit():
    p=MP12HIBEParams()
    assert p.root_params.m_bar==4 and p.m==84 and 3*p.m==252
    assert p.root_params.quality_squared==5120
    assert p.parent_width_squared==28063080
    assert p.parent_gs_squared_bound==1975640832010
    assert p.leaf_width_squared==1082651175941480
    assert p.noise_budget()["conditional_noise_sufficient"]
    assert not p.noise_budget()["lwe_hardness_or_reduction_verified"]
    assert MP12HIBEParams.from_configuration(p.configuration())==p


@pytest.mark.parametrize("change",["unknown","duplicate","wrong-model","dimension-bool","noncanonical"])
def test_parameter_snapshot_rejects_confusion(change):
    p=MP12HIBEParams();d=json.loads(p.configuration())
    if change=="unknown":d["ignored"]=True
    if change=="wrong-model":d["root_profile"]="statistical-LHL"
    if change=="dimension-bool":d["parameters"]["n"]=True
    raw=json.dumps(d,sort_keys=True,separators=(",", ":")).encode()
    if change=="duplicate":raw=raw[:-1]+b',"profile":"duplicate"}'
    if change=="noncanonical":raw=b" "+raw
    with pytest.raises(SerializationError): MP12HIBEParams.from_configuration(raw)


@pytest.mark.parametrize("bad",[b"["*1500+b"]"*1500,b"\xff",b"x"*4097])
def test_parameter_parser_bounds_malformed_and_recursive_input(bad):
    with pytest.raises(SerializationError):MP12HIBEParams.from_configuration(bad)


def test_missing_engine_and_whole_entropy_budget_reject_before_draw():
    g=ComputationalRootGenerator(ComputationalRootParams(2,549755813911,16),ROOT/"missing-engine")
    with pytest.raises(InvalidParameterError,match="missing"):g.generate(rng=NoEntropy())
    with pytest.raises(InvalidParameterError,match="entropy"):
        ComputationalRootGenerator(ComputationalRootParams(2,549755813911,16,max_entropy_bytes=1),ENGINE)


def test_norm_failure_aborts_before_native_conversion(monkeypatch,tmp_path):
    engine=tmp_path/"would-be-engine";engine.write_bytes(b"not executed")
    g=ComputationalRootGenerator(ComputationalRootParams(2,549755813911,16),engine)
    monkeypatch.setattr(g.scalar,"sample",lambda *a,**k:g.params.quality_squared+1)
    def forbidden(*a,**k):raise AssertionError("failed norm reached native conversion")
    monkeypatch.setattr("experiments.research.first_suite.computational_root.convert_private_input",forbidden)
    with pytest.raises(SamplingAbort,match="norm"):
        g.generate(rng=DeterministicRandom(b"norm-guard-test-only"))


def test_actual_computational_generation_modes_layout_and_reproducibility():
    if not ENGINE.is_file():pytest.skip("explicit native build required")
    p=ComputationalRootParams(2,549755813911,16)
    g=ComputationalRootGenerator(p,ENGINE)
    a=g.generate(rng=DeterministicRandom(b"explicit-computational-root-test"))
    b=g.generate(rng=DeterministicRandom(b"explicit-computational-root-test"))
    assert a.basis==b.basis
    assert [row[:p.n] for row in a.basis.public.rows]==[(1,0),(0,1)]
    cert=a.public_generation_certificate
    assert cert["root_statistical_regularity_bound"] is None
    assert cert["root_lwe_samples_per_secret"]==p.n
    assert cert["root_lwe_independent_secret_columns"]==80
    assert cert["actual_entropy_bytes"]<=cert["worst_entropy_bytes"]
    assert cert["entropy_source"]=="deterministic-test" and not cert["native_entropy_generated"]
    actual=g.generate()
    assert actual.public_generation_certificate["entropy_source"]=="system"
    assert actual.basis.public!=a.basis.public


def test_old_statistical_generator_still_rejects_thin_entropy_class():
    from experiments.research.first_suite.root_generation import MP12RootParams,MP12RootGenerator
    p=MP12RootParams(2,549755813911,4,16,regularity_bits=128)
    with pytest.raises(InvalidParameterError,match="regularity"):
        MP12RootGenerator(p,ENGINE)


def test_parameter_projection_is_same_input_but_not_generation_or_hardness():
    from experiments.research.first_suite.computational_parameter_plan import projection
    actual=projection(2,549755813911)
    assert actual["leaf_width_squared"]==MP12HIBEParams().leaf_width_squared
    assert actual["all_listed_arithmetic_resource_gates_pass"]
    larger=projection(128,2**61-1)
    assert not larger["existing_reference_execution_gates"]["leaf_finite_gpv"]
    assert not larger["root_lwe"]["attack_estimation_run"]
    assert not larger["generated_or_sampled"] and not larger["backend_admitted"]
    omitted=projection(512,2**61-1)
    assert omitted["noise_budget"] is None
    assert omitted["existing_reference_execution_gates"]["conditional_noise"] is None
    assert omitted["noise_check_status"]=="not-evaluated-dimension-cap"


def test_custom_registration_is_preflight_and_buildable():
    config,registry=research_suite(ENGINE)
    v=validate_suite(config,registry=registry)
    assert v.ok and not v.metadata["combination_tested"]
    runtime=build_runtime(config,registry=registry,ibs_rng=NoEntropy(),ots_rng=NoEntropy())
    assert runtime.capacity["inner_hibe_ciphertext_max_bytes"]==2664
    assert runtime.capacity["max_application_bytes"]==3924
    assert isinstance(runtime.hibe.inner_backend,MP12CHKPResearchHIBE)
    with pytest.raises(InvalidParameterError,match="unknown"):
        make_suite(hibe="mp12-chkp-reference",hibe_params="absent",ibs="luo-module",registry=registry)


@pytest.mark.parametrize("length",[0,1,31,32])
def test_raw_wire_capacity_matches_codec_including_all_headers(length):
    p=MP12HIBEParams()
    ct=MP12HIBECiphertext(SeedCapsule(b"c"*64,p.q,(0,)*(3*p.m),(0,)*256),length)
    assert len(ct.to_bytes())==raw_ciphertext_size(p,length,p.identity_bytes)==2664
    assert MP12HIBECiphertext.from_bytes(ct.to_bytes())==ct


def test_actual_saved_public_master_binding_and_wire_roundtrip(saved):
    runtime,public=saved
    raw=(PRIVATE/"master-root.bin").read_bytes()
    master=MasterSecret.from_bytes(raw,runtime.decoders["hmsk"],runtime.decoders["imsk"])
    assert master.to_bytes()==raw
    assert runtime.hibe.inner_backend.validate_key_binding(public.hpk.inner,master.hmsk.inner)
    assert not runtime.hibe.inner_backend.validate_key_binding(public.hpk.inner,object())
    p=replace(public.hpk.inner.params,identity_bytes=85)
    with pytest.raises(SerializationError,match="snapshot"):check_object(public.hpk.inner,p)


@pytest.mark.parametrize("kind",["public","master","receiver"])
@pytest.mark.parametrize("edit",["truncate","append","duplicate","version"])
def test_saved_object_strict_parsing(saved,kind,edit):
    runtime,public=saved
    master=MasterSecret.from_bytes((PRIVATE/"master-Bob.bin").read_bytes(),runtime.decoders["hmsk"],runtime.decoders["imsk"])
    if kind=="public":obj,loader=public.hpk.inner,MP12HIBEPublicKey
    elif kind=="master":obj,loader=master.hmsk.inner,MP12HIBEMasterSecret
    else:
        obj=next(v for v in master.hmsk.inner.receivers.values() if v is not None);loader=MP12HIBEReceiver
    raw=obj.to_bytes()
    bad=(raw[:-1] if edit=="truncate" else raw+b"x" if edit=="append" else raw+raw
         if edit=="duplicate" else b"x"+raw[1:])
    with pytest.raises(SerializationError):loader.from_bytes(bad)


def test_failed_receiver_and_child_survive_restore_and_do_not_retry(saved):
    runtime,public=saved
    outer=MasterSecret.from_bytes((PRIVATE/"master-root.bin").read_bytes(),runtime.decoders["hmsk"],runtime.decoders["imsk"])
    master=outer.hmsk.inner;backend=runtime.hibe.inner_backend
    bad=BadEntropy()
    with pytest.raises(RandomnessError):backend.extract(master,b"failed-receiver",rng=bad)
    assert bad.reads>0
    restored=MP12HIBEMasterSecret.from_bytes(master.to_bytes())
    with pytest.raises(InvalidParameterError,match="blocked"):
        backend.extract(restored,b"failed-receiver",rng=NoEntropy())
    outer=MasterSecret.from_bytes((PRIVATE/"master-Bob.bin").read_bytes(),runtime.decoders["hmsk"],runtime.decoders["imsk"])
    receiver=next(v for v in outer.hmsk.inner.receivers.values() if v is not None)
    bad=BadEntropy()
    with pytest.raises(RandomnessError):backend.derive(receiver,b"failed-child",rng=bad)
    assert bad.reads>0
    restored=MP12HIBEReceiver.from_bytes(receiver.to_bytes())
    with pytest.raises(InvalidParameterError,match="blocked"):
        backend.derive(restored,b"failed-child",rng=NoEntropy())


def test_finished_real_lifecycle_and_public_attack_receipt_has_actual_scope():
    path=PRIVATE.parent/"result.json"
    if not path.exists():pytest.skip("live probe is not finished; no claim from partial state")
    r=json.loads(path.read_text())
    assert r["root_generations"]==1 and r["parent_generations"]==2 and r["leaf_generations"]==4
    assert r["dimensions"]==[84,168,252] and r["seed_bits"]==256
    assert all(r["checks"].values()) and r["fresh_process"]["new_root_parent_or_leaf_generations"]==0
    assert r["public_negative_control"]["challenge_plaintext_recovered"]
    assert not r["public_negative_control"]["secret_keys_supplied"]
    assert r["security_claim"]=="none" and r["backend_admitted"] is False


def test_real_raw_payload_boundaries_fixed_leaf_and_leaf_codec(saved):
    runtime,public=saved
    path=PRIVATE/"master-final.bin"
    if not path.exists():pytest.skip("explicit completed real lifecycle required")
    outer=MasterSecret.from_bytes(path.read_bytes(),runtime.decoders["hmsk"],runtime.decoders["imsk"])
    from ibme.protocol.hybrid_hibe import encoded_identity
    receiver_id=encoded_identity(b"Bob",public.hpk.limits,b"P")
    sender_id=encoded_identity(b"Alice",public.hpk.limits,b"C")
    backend=runtime.hibe.inner_backend
    receiver=backend.extract(outer.hmsk.inner,receiver_id,rng=NoEntropy())
    leaf=backend.derive(receiver,sender_id,rng=NoEntropy())
    data=leaf.to_bytes();restored=MP12HIBELeaf.from_bytes(data)
    assert restored.to_bytes()==data and backend.validate_key_binding(public.hpk.inner,restored)
    for length in [0,1,31,32]:
        message=bytes(range(length))
        ct=backend.encrypt(public.hpk.inner,receiver_id,sender_id,message,
            rng=DeterministicRandom(b"explicit-raw-test-entropy"+bytes([length])))
        assert backend.decrypt(restored,backend.load_ciphertext(ct.to_bytes()),rng=NoEntropy())==message
        wrong_context=replace(ct.capsule,context=b"x"*64)
        assert backend.decrypt(restored,replace(ct,capsule=wrong_context),rng=NoEntropy()) is None
    for bad in [data[:-1],data+b"x",data+data,b"x"+data[1:]]:
        with pytest.raises(SerializationError):MP12HIBELeaf.from_bytes(bad)
    with pytest.raises(EncodingError):
        backend.encrypt(public.hpk.inner,receiver_id,sender_id,b"x"*33,rng=NoEntropy())
