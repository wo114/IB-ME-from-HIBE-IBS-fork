"""Selection/persistence contracts, not cryptographic security evidence."""
from dataclasses import asdict, replace
import json

import pytest

from ibme.assembly import (BackendRegistry, SuiteConfig, build_runtime, default_registry,
                           list_backends, make_suite, validate_suite)
from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.core.randomness import DeterministicRandom
from ibme.ibs.luo import LuoMatrixParams
from ibme.ibs.luo_module import LuoModuleParams
from ibme.protocol.baseline import PublicKey, MasterSecret, SenderKey, ReceiverKey, is_bottom


class NoRead:
    def read(self, count): raise AssertionError("preflight consumed entropy")


def test_primitive_wire_parameter_binding_limits_are_explicit():
    report = validate_suite(make_suite(ibs="sis"))
    assert report.metadata["raw_object_parameter_binding"] == {
        "hibe": "partial-legacy-wire", "ibs": "partial-legacy-wire"}
    report = validate_suite(make_suite(ibs="luo-module", transport="hybrid"))
    assert report.metadata["raw_object_parameter_binding"]["ibs"] == "full-parameter-snapshot"
    backends = list_backends()
    assert next(s for s in backends["ibs"] if s["id"] == "sis")["object_parameter_binding"] == "partial-legacy-wire"


def test_preflight_is_entropy_free_and_never_builds_backends():
    registry=default_registry()
    def forbidden(*args,**kwargs): raise AssertionError("preflight instantiated backend")
    alternate=BackendRegistry([replace(registry.get("hibe","abb10"),factory=forbidden),
                               replace(registry.get("ibs","luo-module"),factory=forbidden)])
    c=make_suite(ibs="luo-module",transport="hybrid",registry=alternate)
    result=validate_suite(c,registry=alternate)
    assert result.ok and result.metadata["combination_tested"] is False
    assert result.capacity["max_application_bytes"]==3924
    assert result.capacity["signature_max_bytes"]==29455
    # Creating a runtime is also entropy-free; only Setup/sign/Encrypt read RNG.
    build_runtime(c,ibs_rng=NoRead(),ots_rng=NoRead())


def test_strict_configuration_roundtrip_and_nested_copy():
    config=make_suite(ibs="luo-matrix",transport="hybrid")
    restored=SuiteConfig.from_json(config.to_json())
    assert restored==config and restored.digest==config.digest
    data=config.to_dict(); data["ibs_params"]["q"]=65537
    assert config.to_dict()["ibs_params"]["q"]==2147483647
    for edit in (dict(extra=1),dict(version="IBME/SUITE/2"),dict(backend_admitted=True),
                 dict(parameters_are_formal=0),dict(allow_mock=1)):
        with pytest.raises(InvalidParameterError): SuiteConfig.from_dict({**config.to_dict(),**edit})
    with pytest.raises(InvalidParameterError):
        SuiteConfig.from_json(config.to_json()[:-1]+',"version":"IBME/SUITE/1"}')


@pytest.mark.parametrize("field,value",[("hibe_version","abb10-v0"),("ibs_version","luo-v0"),
    ("signature_format","compact"),("state_policy","stateless"),("transport","automatic"),
    ("protocol","automatic")])
def test_selection_rejects_unsupported_versions_and_policies(field,value):
    config=make_suite(ibs="luo-matrix",transport="hybrid")
    changed=SuiteConfig.from_dict({**config.to_dict(),field:value})
    assert not validate_suite(changed).ok
    with pytest.raises(InvalidParameterError): build_runtime(changed,ibs_rng=NoRead())


def test_missing_implementations_and_unknown_ids_do_not_fall_back():
    config=make_suite(hibe="lai-ideal-hibe",ibs="luo-module",transport="hybrid")
    result=validate_suite(config)
    assert not result.ok and "unavailable" in result.errors[0]
    with pytest.raises(InvalidParameterError): build_runtime(config)
    with pytest.raises(InvalidParameterError): make_suite(hibe="typo")
    assert not next(x for x in list_backends()["hibe"] if x["id"]=="lai-ideal-hibe")["available"]


def test_mock_requires_explicit_optin_independently():
    for hibe,ibs in (("mock","sis"),("abb10","mock"),("mock","mock")):
        assert not validate_suite(make_suite(hibe=hibe,ibs=ibs)).ok
        result=validate_suite(make_suite(hibe=hibe,ibs=ibs,allow_mock=True))
        assert result.ok and result.metadata["test_only"]


def test_independent_moduli_params_and_capacity_rejection():
    p=LuoMatrixParams(k=32,kappa=8,q=2**31-1,gamma1=4096,gamma2=131072,
                      identity_max_bytes=64,message_max_bytes=4096)
    c=make_suite(ibs="luo-matrix",transport="hybrid",ibs_params=p)
    assert validate_suite(c).ok
    assert c.to_dict()["hibe_params"]["q"]!=c.to_dict()["ibs_params"]["q"]
    assert not validate_suite(make_suite(ibs="luo-matrix",transport="hybrid",ibs_params=LuoMatrixParams())).ok
    assert not validate_suite(make_suite(ibs="luo-module",transport="direct")).ok
    data=c.to_dict(); data["hibe_params"]["max_message_bytes"]=31
    assert "32-byte" in " ".join(validate_suite(SuiteConfig.from_dict(data)).errors)
    data=c.to_dict(); data["hibe_params"]["identity_bytes"]=85
    assert "identity" in " ".join(validate_suite(SuiteConfig.from_dict(data)).errors)


def test_compact_capacity_and_parameter_extension_are_explicit():
    p=replace(LuoModuleParams(),gamma1=190000,gamma2=60000000000,
              gamma3=(LuoModuleParams().q-1)//10,max_extract_attempts=4096,max_sign_attempts=4096)
    c=make_suite(ibs="luo-module",ibs_params=p,transport="hybrid",signature_format="compact")
    report=validate_suite(c)
    assert report.ok and report.capacity["signature_max_bytes"]==16383
    assert report.capacity["max_application_bytes"]==3924
    assert c.to_dict()["parameters_are_formal"] is False


def test_capsule_budget_and_invalid_sis_dimensions_fail_before_setup():
    for hibe in ("mock","abb10"):
        c=make_suite(hibe=hibe,ibs="mock",transport="hybrid",allow_mock=True)
        data=c.to_dict(); data["hybrid_limits"]["max_capsule_bytes"]=1
        report=validate_suite(SuiteConfig.from_dict(data))
        assert not report.ok and "capsule budget" in " ".join(report.errors)
    c=make_suite(); data=c.to_dict();data["ibs_params"]["m_matrix"]=1
    assert "IBS: parameters leave no trapdoor" in " ".join(validate_suite(SuiteConfig.from_dict(data)).errors)
    data=c.to_dict();data["hibe_params"]["n"]=2**31
    assert "resource budget" in " ".join(validate_suite(SuiteConfig.from_dict(data)).errors)


def test_registry_extension_duplicate_and_missing_capability():
    registry=default_registry()
    spec=replace(registry.get("hibe","abb10"),id="test-alias",key_binding=False)
    registry.register(spec)
    assert validate_suite(make_suite(hibe="test-alias",registry=registry),registry=registry).ok
    hybrid=make_suite(hibe="test-alias",transport="hybrid",registry=registry)
    assert not validate_suite(hybrid,registry=registry).ok
    with pytest.raises(InvalidParameterError): registry.register(spec)
    with pytest.raises(InvalidParameterError):
        registry.register(replace(spec,id="empty",decoders={}))


def test_byteauth_capacity_counts_baseline_frame_without_large_allocation():
    from ibme.lattice.params import Params
    hp = Params(name="wire-boundary", security_parameter=8, n=1, m_matrix=46, q=65537,
                s0=4.0, s=1.0, s_prime=12.0, identity_bytes=64,
                max_message_bytes=34381)
    config = make_suite(hibe_params=hp, ibs_params=replace(
        default_registry().get("ibs", "sis").presets["education"], max_message_bytes=65536))
    report = validate_suite(config)
    assert report.capacity["inner_hibe_ciphertext_max_bytes"] == 67108857
    assert not report.ok and "including Baseline frame" in " ".join(report.errors)
    data = config.to_dict()
    data["hibe_params"]["max_message_bytes"] -= 1
    assert validate_suite(SuiteConfig.from_dict(data)).ok


def test_missing_hybrid_dependency_is_a_preflight_error(monkeypatch):
    import importlib.util
    original = importlib.util.find_spec
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: None if name == "cryptography" else original(name))
    report = validate_suite(make_suite(ibs="luo-module", transport="hybrid"))
    assert not report.ok and "cryptography extra" in " ".join(report.errors)


def test_ibs_master_binding_uses_registered_public_adapter():
    from ibme.ibs.api import IBSMasterSecret
    from ibme.ibs.mock import MockIBSBackend, MockMasterSecret

    class OpaqueMaster(IBSMasterSecret):
        def __init__(self, delegate): self._delegate = delegate
        def to_bytes(self): return self._delegate.to_bytes()
        @classmethod
        def from_bytes(cls, raw): return cls(MockMasterSecret.from_bytes(raw))
        def export_public(self): return self._delegate.public_key

    class OpaqueBackend(MockIBSBackend):
        def setup(self, params):
            pk, master = super().setup(params)
            return pk, OpaqueMaster(master)

    registry = default_registry()
    original = registry.get("ibs", "mock")
    spec = replace(original, id="opaque-test", factory=lambda rng, fmt: OpaqueBackend(rng=rng),
                   decoders={**original.decoders, "imsk": OpaqueMaster},
                   master_public_key=lambda master: master.export_public())
    registry.register(spec)
    config = make_suite(hibe="mock", ibs="opaque-test", allow_mock=True, registry=registry)
    runtime = build_runtime(config, registry=registry)
    pk, master = runtime.proto.setup(runtime.hibe_params, ibs_params=runtime.ibs_params)
    assert not hasattr(master.imsk, "public_key")
    runtime.validate_master(pk, master)
    with pytest.raises(InvalidParameterError):
        registry.register(replace(spec, id="missing-public-adapter", master_public_key=None))


@pytest.fixture
def small_runtime():
    c=make_suite(hibe="mock",ibs="luo-matrix",ibs_params="test-small",allow_mock=True,transport="hybrid")
    r=build_runtime(c,ibs_rng=DeterministicRandom(b"assembly:ibs"),ots_rng=DeterministicRandom(b"assembly:ots"))
    pk,msk=r.proto.setup(r.hibe_params,ibs_params=r.ibs_params,rng=DeterministicRandom(b"assembly:hibe"))
    return r,pk,msk


def test_recover_objects_config_and_cached_sender_without_entropy(small_runtime):
    r,pk,msk=small_runtime
    ek=r.proto.skgen(msk,b"Alice"); dk=r.proto.rkgen(msk,b"Bob")
    recovered=build_runtime(SuiteConfig.from_json(r.config.to_json()),ibs_rng=NoRead())
    readers=recovered.decoders
    public=PublicKey.from_bytes(pk.to_bytes(),readers["hpk"],readers["ipk"])
    master=MasterSecret.from_bytes(msk.to_bytes(),readers["hmsk"],readers["imsk"])
    recovered.validate_master(public,master)
    assert recovered.proto.skgen(master,b"Alice").to_bytes()==ek.to_bytes()
    sender=SenderKey.from_bytes(ek.to_bytes(),readers["sk"])
    receiver=ReceiverKey.from_bytes(dk.to_bytes(),readers["sk1"])
    recovered.validate_sender(public,sender); recovered.validate_receiver(public,receiver)
    ct=r.proto.encrypt(pk,ek,b"Bob",b"hello",rng=DeterministicRandom(b"assembly:encrypt"))
    assert recovered.proto.decrypt(public,receiver,b"Alice",ct.to_bytes())==b"hello"


def test_valid_but_different_parameter_snapshot_is_rejected(small_runtime):
    r,pk,msk=small_runtime
    d=r.config.to_dict(); d["ibs_params"]["max_sign_attempts"]-=1
    changed=build_runtime(SuiteConfig.from_dict(d))
    with pytest.raises(SerializationError): changed.decoders["ipk"].from_bytes(pk.ipk.to_bytes())
    changed=build_runtime(SuiteConfig.from_dict(d),ibs_rng=NoRead())
    with pytest.raises(SerializationError): changed.proto.skgen(msk,b"uncached")
    d=r.config.to_dict();d["hibe_params"]["s0"]+=1
    changed=build_runtime(SuiteConfig.from_dict(d))
    # Mock ignores widths: only its actually implemented capacity fields bind.
    d["hybrid_limits"]["max_payload_bytes"]-=1
    changed=build_runtime(SuiteConfig.from_dict(d))
    with pytest.raises(SerializationError): changed.decoders["hpk"].from_bytes(pk.hpk.to_bytes())


def test_cross_public_master_sender_and_receiver_rejected_before_rng(small_runtime):
    r,pk,msk=small_runtime
    ek=r.proto.skgen(msk,b"Alice");dk=r.proto.rkgen(msk,b"Bob")
    other,other_master=r.proto.setup(r.hibe_params,ibs_params=r.ibs_params,rng=DeterministicRandom(b"another-root"))
    with pytest.raises(SerializationError): r.validate_master(other,msk)
    with pytest.raises(SerializationError): r.validate_sender(other,ek)
    with pytest.raises(SerializationError): r.validate_receiver(other,dk)
    guarded=build_runtime(r.config,ibs_rng=NoRead(),ots_rng=NoRead())
    with pytest.raises(InvalidParameterError):
        guarded.proto.encrypt(pk,ek,b"Bob",b"x"*(r.capacity["max_application_bytes"]+1),rng=NoRead())
    with pytest.raises(SerializationError):
        guarded.proto.encrypt(other,ek,b"Bob",b"x",rng=NoRead())
    assert is_bottom(guarded.proto.decrypt(other,dk,b"Alice",b"invalid",rng=NoRead()))


def test_signature_capacity_matches_real_matrix_and_small_module():
    for name,fmt in (("luo-matrix","reference"),("luo-module","reference"),("luo-module","compact")):
        r=build_runtime(make_suite(hibe="mock",ibs=name,ibs_params="test-small",allow_mock=True,
                                   transport="hybrid",signature_format=fmt),ibs_rng=DeterministicRandom(b"sizes:"+name.encode()+fmt.encode()))
        pk,msk=r.ibs.setup(r.ibs_params)
        key=r.ibs.key_extract(msk,b"A")
        sig=r.ibs.sign(key,b"check")
        assert len(sig.to_bytes())==r.capacity["signature_max_bytes"]
