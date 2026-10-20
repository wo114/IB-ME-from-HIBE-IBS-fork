"""The five-method IBS contract, fixed issuance, and public-only attacks."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json

import pytest

from ibme.core.errors import EncodingError, InvalidParameterError, RandomnessError, SerializationError
from ibme.core.hashing import hash_identity
from ibme.core.randomness import DeterministicRandom
from ibme.ibs.api import IBSBackend, IBSPublicKey, IBSMasterSecret, IBSSigningKey, IBSSignature
from ibme.ibs.certified import (CertifiedIBSParams, CertifiedIBS, IssuancePending, CertifiedPublicKey,
                               CertifiedMasterSecret, CertifiedSigningKey, CertifiedSignature)
from ibme.ibs.certified.codec import blob, decode, encode
from ibme.ibs.certified.objects import PK_MAGIC, MSK_MAGIC, SK_MAGIC, SIG_MAGIC, application_message
from ibme.ibs.certified.mldsa import MLDSA, NativeFailure, PROFILES
from test_cert_ml_dsa_vectors import NATIVE


native = pytest.mark.skipif(not NATIVE, reason="requires explicitly built ML-DSA engines in WSL/Linux")


class CountingRandom:
    def __init__(self, seed=b"certified IBS TEST randomness only"):
        self.source = DeterministicRandom(seed)
        self.bytes = 0

    def read(self, size):
        self.bytes += size
        return self.source.read(size)


class NoEntropy:
    def read(self, size):
        raise AssertionError("unexpected entropy during fixed-key reuse/restoration")


@pytest.fixture
def instance():
    rng = CountingRandom()
    backend = CertifiedIBS(rng)
    pk, master = backend.setup(CertifiedIBSParams(message_max_bytes=32, max_identities=4))
    a = backend.key_extract(master, b"alice")
    b = backend.key_extract(master, b"bob")
    signature = backend.sign(a, b"m" * 32)
    return backend, rng, pk, master, a, b, signature


@pytest.mark.parametrize("changes", [dict(base_algorithm="dilithium2"), dict(identity_bytes=True),
    dict(message_max_bytes=1.0), dict(max_identities=0), dict(timeout_seconds=301),
    dict(backend_admitted=0), dict(parameters_are_formal=False), dict(security_claim="NIST-2")])
def test_parameter_rejections(changes):
    with pytest.raises(InvalidParameterError):
        CertifiedIBSParams(**changes)


def test_complete_parameters_and_public_codec_are_portable():
    p = CertifiedIBSParams()
    assert CertifiedIBSParams.from_bytes(p.to_bytes()) == p
    pk = CertifiedPublicKey(p, bytes(PROFILES[p.base_algorithm].public_key_bytes))
    assert CertifiedPublicKey.from_bytes(pk.to_bytes()) == pk
    assert replace(pk, params=replace(p, timeout_seconds=31)).context != pk.context
    values = json.loads(p.to_bytes())
    malformed = [p.to_bytes() + b" ", p.to_bytes().replace(
                 b'"project-admitted"',b'"project-admitted","security_claim":"project-admitted"'),
                 json.dumps({k:v for k,v in values.items() if k != "identity_bytes"}).encode(),
                 json.dumps(dict(values, extra=1)).encode(), b'[]', b'"text"']
    for data in malformed:
        with pytest.raises(SerializationError):
            CertifiedIBSParams.from_bytes(data)


def test_exact_legacy_admission_snapshot_remains_decodable():
    legacy=CertifiedIBSParams(security_claim="none",backend_admitted=False,
                              parameters_are_formal=False)
    assert CertifiedIBSParams.from_bytes(legacy.to_bytes())==legacy


def test_buffer_limits_use_all_dimensions_before_copying():
    with pytest.raises(SerializationError,match="resource limit"):
        decode(memoryview(b"x"*32).cast("B",shape=[1,32]),b"x",0,limit=16)
    with pytest.raises(SerializationError,match="resource limit"):
        decode(memoryview(b"x"*32).cast("I"),b"x",0,limit=16)
    released=memoryview(b"x");released.release()
    with pytest.raises(SerializationError,match="released"):
        decode(released,b"x",0)
    public=CertifiedPublicKey(CertifiedIBSParams(),bytes(1312))
    raw=public.to_bytes()
    assert CertifiedPublicKey.from_bytes(memoryview(raw).cast("B",shape=[1,len(raw)]))==public


def test_explicit_descriptor_does_not_start_native_engine_or_consume_entropy(monkeypatch):
    from ibme.assembly.registry import BackendRegistry
    from ibme.ibs.certified.registration import backend_spec, signature_size
    import ibme.ibs.certified.registration as registration
    def forbidden(*args, **kwargs):
        pytest.fail("descriptor construction started native engine")
    monkeypatch.setattr(registration,"MLDSA",forbidden)
    spec=backend_spec()
    registry=BackendRegistry([spec])
    for params in spec.presets.values():
        assert spec.parse_params(__import__("dataclasses").asdict(params))==params
        assert signature_size(params,"reference")>PROFILES[params.base_algorithm].signature_bytes
    assert registry.get("ibs","cert-ml-dsa").persistent_identity_cache


@native
def test_descriptor_full_parameter_binding_and_size(instance):
    from ibme.ibs.certified.registration import backend_spec, signature_size
    b,_,pk,master,sk,_,sig=instance
    spec=backend_spec()
    assert spec.master_public_key(master)==pk
    for obj in (pk,master,sk):
        spec.check_object(obj,pk.params)
        with pytest.raises(SerializationError):
            spec.check_object(obj,replace(pk.params,timeout_seconds=31))
    assert signature_size(pk.params,"reference")==len(sig.to_bytes())
    with pytest.raises(InvalidParameterError):
        signature_size(pk.params,"compact")


@native
@pytest.mark.parametrize("algorithm", list(PROFILES))
def test_full_contract_all_standard_parameter_sets(algorithm):
    rng = CountingRandom()
    b = CertifiedIBS(rng)
    pk, master = b.setup(CertifiedIBSParams(base_algorithm=algorithm))
    sk = b.key_extract(master, b"alice")
    assert isinstance(b, IBSBackend)
    assert isinstance(pk, IBSPublicKey) and isinstance(master, IBSMasterSecret)
    assert isinstance(sk, IBSSigningKey) and sk.identity_digest == hash_identity(b"alice", 32)
    for message in (b"", b"x", b"m" * 32):
        signature = b.sign(sk, message)
        assert isinstance(signature, IBSSignature)
        assert b.verify(pk, b"alice", message, b.load_signature(pk, signature.to_bytes())) is True
        assert b.verify(pk, b"bob", message, signature) is False
        assert b.verify(pk, b"alice", message + b"!", signature) is False
    assert rng.bytes == 32 + 64 + 3 * 32
    before = rng.bytes
    assert b.key_extract(master, b"alice") is sk
    assert rng.bytes == before
    assert CertifiedIBS(NoEntropy()).key_extract(CertifiedMasterSecret.from_bytes(master.to_bytes()), b"alice") == sk
    assert CertifiedSigningKey.from_bytes(sk.to_bytes()) == sk
    assert sk.user_secret.hex() not in repr(sk)
    assert "private" in repr(master)


@native
def test_identity_capacity_inputs_and_entropy_accounting(instance):
    b, rng, pk, master, alice, bob, sig = instance
    assert rng.bytes == 32 + 2 * 64 + 32
    for identity in (b"", "alice", b"x" * 65, None):
        with pytest.raises(EncodingError):
            b.key_extract(master, identity)
    with pytest.raises(EncodingError):
        b.sign(alice, b"x" * 33)
    before = rng.bytes
    b.key_extract(master, b"c"); b.key_extract(master, b"d")
    with pytest.raises(EncodingError, match="capacity"):
        b.key_extract(master, b"e")
    assert rng.bytes == before + 128
    for bad in (None, b"", object()):
        assert b.verify(bad, b"alice", b"m" * 32, sig) is False
        assert b.verify(pk, b"alice", b"m" * 32, bad) is False
        assert b.verify(pk, bad, b"m" * 32, sig) is False
    assert b.verify(pk, b"alice", "not bytes", sig) is False
    assert b.verify(pk, b"alice", b"m" * 33, sig) is False
    for method, args in ((b.setup, (None,)), (b.sign, (None,b"")),
                         (b.key_extract, (None,b"alice")), (b.load_signature, (None,b""))):
        with pytest.raises(TypeError):
            method(*args)


@native
def test_replacement_and_cross_context_attacks(instance):
    b, rng, pk, master, alice, bob, sig = instance
    message = b"m" * 32
    bob_sig = b.sign(bob, message)
    for field, value in (("certificate", bob.certificate), ("user_public", bob.user_public),
                         ("message_signature", bob_sig.message_signature), ("context", bytes(32))):
        assert not b.verify(pk, b"alice", message, replace(sig, **{field:value}))
    assert not b.verify(pk, b"bob", message, sig)
    other_pk, _ = b.setup(pk.params)
    # Change the outer context too: the actual authority equation still rejects.
    assert not b.verify(other_pk, b"alice", message, replace(sig, context=other_pk.context))
    for name, value in (("message_max_bytes", 33), ("identity_bytes", 63), ("max_identities", 5), ("timeout_seconds", 31)):
        changed = replace(pk, params=replace(pk.params, **{name:value}))
        assert not b.verify(changed, b"alice", message, replace(sig, context=changed.context))
        with pytest.raises(SerializationError):
            b.load_signature(changed, sig.to_bytes())
    engine = MLDSA(pk.params.base_algorithm)
    attacker_public, attacker_secret = engine.keypair(bytes(32))
    # A real new user signature cannot replace the authority's certificate.
    attacker_signature = engine.sign(attacker_secret, application_message(
        pk, b"alice", attacker_public, sig.certificate, message), bytes(32))
    forged = replace(sig, user_public=attacker_public, message_signature=attacker_signature)
    assert not b.verify(pk, b"alice", message, forged)
    random = DeterministicRandom(b"public malformed signature test")
    for _ in range(8):
        forged = replace(sig, certificate=random.read(len(sig.certificate)),
                         message_signature=random.read(len(sig.message_signature)))
        assert not b.verify(pk, b"alice", message, forged)
    for name in ("certificate", "message_signature", "user_public"):
        raw = bytearray(getattr(sig, name));raw[len(raw)//2] ^= 1
        assert not b.verify(pk, b"alice", message, replace(sig, **{name:bytes(raw)}))


@native
@pytest.mark.parametrize("kind", ["public", "master", "signing", "signature"])
def test_wire_rejects_truncation_append_duplicate_order_and_length(instance, kind):
    b, _, pk, master, sk, _, sig = instance
    obj, magic, count, decoder = {
        "public":(pk,PK_MAGIC,2,CertifiedPublicKey.from_bytes),
        "master":(master,MSK_MAGIC,3,CertifiedMasterSecret.from_bytes),
        "signing":(sk,SK_MAGIC,5,CertifiedSigningKey.from_bytes),
        "signature":(sig,SIG_MAGIC,5,lambda raw:b.load_signature(pk,raw)),
    }[kind]
    raw = obj.to_bytes()
    assert decoder(raw).to_bytes() == raw
    values = decode(raw, magic, count)
    malformed = [raw[:n] for n in (0,1,len(magic),len(raw)//2,len(raw)-1)]
    malformed += [raw+b"\0", raw+raw[len(magic):], b"?"+raw[1:],
                  magic + b"\1\xff\xff\xff\xff" + raw[len(magic)+5:],
                  magic + b"\2" + raw[len(magic)+1:],
                  magic + b"\1"+blob(values[0])+b"\1"+blob(values[1])+raw[len(magic)+10+len(values[0])+len(values[1]):],
    ]
    for encoded in malformed:
        with pytest.raises(SerializationError):
            decoder(encoded)


@native
def test_private_restore_rejects_wrong_equations_and_cache_binding(instance):
    _, _, pk, master, a, b, sig = instance
    for field, value in (("user_public",b.user_public),("certificate",b.certificate),
                         ("bound_identity",b"bob"),("user_secret",b.user_secret)):
        with pytest.raises(SerializationError):
            replace(a, **{field:value})
    # tr, rho, t0 and short-secret encodings all participate in reconstruction.
    for position in (0,64,128,len(a.user_secret)-1):
        raw=bytearray(a.user_secret);raw[position]^=255
        with pytest.raises(SerializationError):
            replace(a,user_secret=bytes(raw))
    fields = decode(master.to_bytes(), MSK_MAGIC, 3)
    for entries in (b"\0\0\1\1", b"\0\0\0\2"+blob(b"alice")+blob(a.to_bytes())+blob(b"alice")+blob(a.to_bytes()),
                    b"\0\0\0\1"+blob(b"bob")+blob(a.to_bytes()),
                    b"\0\0\0\1"+blob(b"alice")+blob(a.to_bytes())+b"!"):
        with pytest.raises(SerializationError):
            CertifiedMasterSecret.from_bytes(encode(MSK_MAGIC, fields[0],fields[1],entries))
    with pytest.raises(SerializationError):
        CertifiedIBS().load_signature(pk, replace(sig, message_signature=bytes(len(sig.message_signature))).to_bytes())


@native
@pytest.mark.parametrize("fail_at", [1,2])
def test_callback_failure_retains_pending_after_restore(instance, fail_at):
    b, rng, pk, master, a, bob, sig = instance
    snapshots=[]
    def persist(state):
        snapshots.append(state.to_bytes())
        if len(snapshots)==fail_at:
            raise OSError("simulated uncertain storage publication")
    master.persist_callback=persist
    before=rng.bytes
    with pytest.raises(OSError):
        b.key_extract(master,b"carol")
    assert rng.bytes == before + (0 if fail_at==1 else 64)
    for state in (master,CertifiedMasterSecret.from_bytes(master.to_bytes()),
                  CertifiedMasterSecret.from_bytes(snapshots[0])):
        with pytest.raises(IssuancePending):
            CertifiedIBS(NoEntropy()).key_extract(state,b"carol")
    # If the successful key snapshot was stored before an exception, replaying
    # it returns that same key, never another key. External atomicity is separate.
    if fail_at==2:
        stored=CertifiedMasterSecret.from_bytes(snapshots[-1])
        key=CertifiedIBS(NoEntropy()).key_extract(stored,b"carol")
        assert key.identity==b"carol"


@native
def test_entropy_failure_is_tombstoned_and_concurrent_issuance_is_once(instance):
    b,rng,pk,master,a,bob,sig=instance
    bad=CertifiedIBS(type("Short",(),{"read":lambda self,n:b""})())
    with pytest.raises(RandomnessError):
        bad.key_extract(master,b"carol")
    with pytest.raises(IssuancePending):
        b.key_extract(master,b"carol")
    before=rng.bytes
    with ThreadPoolExecutor(max_workers=8) as pool:
        keys=list(pool.map(lambda _:b.key_extract(master,b"dave"),range(16)))
    assert all(key is keys[0] for key in keys)
    assert rng.bytes==before+64
    assert CertifiedMasterSecret.from_bytes(master.to_bytes()).to_bytes()==master.to_bytes()


@native
def test_missing_runtime_fails_before_entropy_or_new_reservation(instance, monkeypatch, tmp_path):
    b,rng,pk,master,a,bob,sig=instance
    before=rng.bytes
    monkeypatch.setenv("IBME_CERTIFIED_SIGNATURE_BIN_DIR",str(tmp_path))
    assert CertifiedIBS(NoEntropy()).key_extract(master,b"alice") is a
    with pytest.raises(NativeFailure):
        b.key_extract(master,b"carol")
    assert rng.bytes==before
    monkeypatch.delenv("IBME_CERTIFIED_SIGNATURE_BIN_DIR")
    assert b.key_extract(master,b"carol").identity==b"carol"
