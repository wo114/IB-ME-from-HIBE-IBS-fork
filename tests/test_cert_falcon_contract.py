"""Falcon uses the same five-method conversion, state and attack contract."""
from dataclasses import replace
import json

import pytest

from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.ibs.certified import (CertifiedIBS, CertifiedIBSParams, CertifiedPublicKey,
    CertifiedMasterSecret, CertifiedSigningKey, CertifiedSignature, IssuancePending)
from ibme.ibs.certified.falcon import Falcon, PROFILES
from ibme.ibs.certified.mldsa import NativeFailure
from ibme.ibs.certified.ordinary import ordinary
from test_cert_falcon_vectors import native
import test_cert_ml_dsa_contract as contract


@pytest.fixture(params=list(PROFILES))
def instance(request):
    rng=contract.CountingRandom();backend=CertifiedIBS(rng)
    pk,master=backend.setup(CertifiedIBSParams(base_algorithm=request.param,message_max_bytes=32,max_identities=4))
    alice=backend.key_extract(master,b"alice");bob=backend.key_extract(master,b"bob")
    return backend,rng,pk,master,alice,bob,backend.sign(alice,b"m"*32)


@pytest.mark.parametrize("algorithm",list(PROFILES))
def test_portable_discriminated_objects_and_explicit_descriptor(algorithm,monkeypatch):
    import ibme.ibs.certified.registration as registration
    def forbidden(*args,**kwargs):pytest.fail("descriptor starts native engine")
    monkeypatch.setattr(registration,"Falcon",forbidden)
    params=CertifiedIBSParams(base_algorithm=algorithm)
    assert CertifiedIBSParams.from_bytes(params.to_bytes())==params
    profile=PROFILES[algorithm]
    pk=CertifiedPublicKey(params,bytes([profile.logn])+bytes(profile.public_key_bytes-1))
    assert CertifiedPublicKey.from_bytes(pk.to_bytes())==pk
    for raw in (bytes(profile.public_key_bytes), bytes([profile.logn])+b"\xff\xff"+bytes(profile.public_key_bytes-3)):
        with pytest.raises(SerializationError):CertifiedPublicKey(params,raw)
        with pytest.raises(SerializationError):
            CertifiedSignature(algorithm,bytes(32),raw,bytes(profile.signature_bytes),bytes(profile.signature_bytes))
    spec=registration.falcon_backend_spec()
    assert spec.id=="cert-falcon" and spec.persistent_identity_cache
    assert spec.parse_params(__import__('dataclasses').asdict(params))==params
    spec.validate_configuration(params,{})
    with pytest.raises(InvalidParameterError):registration.backend_spec().validate_configuration(params,{})
    with pytest.raises(InvalidParameterError):spec.validate_configuration(CertifiedIBSParams(),{})
    assert registration.signature_size(params,"reference")>2*PROFILES[algorithm].signature_bytes
    for change in (dict(base_algorithm="falcon-512"),dict(base_algorithm="fn-dsa-512"),
                   dict(backend_admitted=True),dict(security_claim="NIST-5")):
        with pytest.raises(InvalidParameterError):replace(params,**change)
    values=json.loads(params.to_bytes());del values["base_algorithm"]
    with pytest.raises(SerializationError):CertifiedIBSParams.from_bytes(json.dumps(values).encode())


@native
def test_full_contract_fixed_key_and_zero_entropy_restoration(instance):
    b,rng,pk,master,sk,bob,sig=instance
    assert isinstance(ordinary(pk.params),Falcon)
    assert rng.bytes==192
    for msg in (b"",b"x",b"m"*32):
        signature=b.sign(sk,msg)
        assert b.verify(pk,b"alice",msg,b.load_signature(pk,signature.to_bytes()))
        assert not b.verify(pk,b"bob",msg,signature)
    raw=master.to_bytes()
    restored=CertifiedMasterSecret.from_bytes(raw)
    assert CertifiedIBS(contract.NoEntropy()).key_extract(restored,b"alice")==sk
    assert CertifiedIBS(contract.NoEntropy()).key_extract(restored,b"bob")==bob
    assert CertifiedSigningKey.from_bytes(sk.to_bytes())==sk and restored.to_bytes()==raw
    assert sk.user_secret.hex() not in repr(sk)


@native
def test_identity_capacity_and_invalid_inputs(instance):
    contract.test_identity_capacity_inputs_and_entropy_accounting(instance)


@native
def test_actual_replacement_and_cross_context_attacks(instance,monkeypatch):
    # Run the same independent conversion attacks with actual Falcon equations.
    monkeypatch.setattr(contract,"MLDSA",Falcon)
    contract.test_replacement_and_cross_context_attacks(instance)


@native
@pytest.mark.parametrize("kind",["public","master","signing","signature"])
def test_strict_wire_all_objects(instance,kind):
    contract.test_wire_rejects_truncation_append_duplicate_order_and_length(instance,kind)


@native
def test_private_equations_and_cache_binding(instance):
    contract.test_private_restore_rejects_wrong_equations_and_cache_binding(instance)
    _,_,_,_,sk,_,_=instance
    # F starts after f and g. Modifying it leaves h=g/f unchanged, so a
    # make_public-only decoder would incorrectly accept this corrupted key.
    logn=PROFILES[sk.params.base_algorithm].logn
    start=1+2*((1<<logn)*(6 if logn==9 else 5)//8)
    raw=bytearray(sk.user_secret);raw[start]^=1
    assert Falcon(sk.params.base_algorithm).public_from_secret(bytes(raw)) is None
    with pytest.raises(SerializationError):replace(sk,user_secret=bytes(raw))


@native
@pytest.mark.parametrize("fail_at",[1,2])
def test_publication_failure_remains_pending(instance,fail_at):
    contract.test_callback_failure_retains_pending_after_restore(instance,fail_at)


@native
def test_entropy_failure_and_concurrent_single_issuance(instance):
    contract.test_entropy_failure_is_tombstoned_and_concurrent_issuance_is_once(instance)


@native
def test_missing_engine_does_not_reserve_or_consume_entropy(instance,monkeypatch,tmp_path):
    b,rng,pk,master,sk,_,_=instance;before=rng.bytes
    monkeypatch.setenv("IBME_CERTIFIED_FALCON_BIN_DIR",str(tmp_path))
    assert CertifiedIBS(contract.NoEntropy()).key_extract(master,b"alice") is sk
    with pytest.raises(NativeFailure):b.key_extract(master,b"carol")
    assert rng.bytes==before
    monkeypatch.delenv("IBME_CERTIFIED_FALCON_BIN_DIR")
    assert b.key_extract(master,b"carol").identity==b"carol"


@native
def test_algorithm_discriminator_prevents_mldsa_or_other_falcon_reinterpretation(instance):
    b,_,pk,_,_,_,sig=instance
    for algorithm in ("ml-dsa-44","falcon-padded-512" if sig.algorithm.endswith("1024") else "falcon-padded-1024"):
        params=replace(pk.params,base_algorithm=algorithm)
        from ibme.ibs.certified.ordinary import PROFILES as ALL
        profile=ALL[algorithm]
        public=(bytes([profile.logn])+bytes(profile.public_key_bytes-1) if algorithm in PROFILES
                else bytes(profile.public_key_bytes))
        other=CertifiedPublicKey(params,public)
        assert not b.verify(other,b"alice",b"m"*32,sig)
        with pytest.raises(SerializationError):b.load_signature(other,sig.to_bytes())
        with pytest.raises(SerializationError):replace(sig,algorithm=algorithm)
