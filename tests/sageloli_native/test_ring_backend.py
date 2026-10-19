"""Full ring v3 lifecycle, strict recovery and fixed state at bounded sizes."""
import numpy as np
import pytest
from ibme.core.randomness import DeterministicRandom
from experiments.research.candidates.sageloli.ring.backend import RingBackend
from experiments.research.candidates.sageloli.ring.params import small
from experiments.research.candidates.sageloli.ring.objects import PublicKey,SigningKey,MasterSecret
from experiments.research.candidates.sageloli.ring.issuer import FixedIssuer
from experiments.research.candidates.sageloli.ring.native import build


@pytest.fixture(scope="module")
def backend(tmp_path_factory):
    path=build(tmp_path_factory.mktemp("ring-build"))
    return RingBackend(DeterministicRandom(b"v3 lifecycle test only"),native_path=path)


@pytest.fixture(scope="module")
def issued(backend):
    pk,msk=backend.setup(small());key=backend.key_extract(msk,b"Alice")
    return pk,msk,key


def test_complete_lifecycle_strict_wire_and_fixed_identity(backend,issued):
    pk,msk,key=issued;sig=backend.sign(key,b"message")
    assert backend.verify(pk,b"Alice",b"message",sig)
    assert backend.key_extract(msk,b"Alice") is key
    assert not backend.verify(pk,b"Bob",b"message",sig)
    assert not backend.verify(pk,b"Alice",b"other",sig)
    recovered=backend.load_signature(pk,sig.to_bytes())
    assert backend.verify(pk,b"Alice",b"message",recovered)
    for raw in [sig.to_bytes()[:-1],sig.to_bytes()+b"x"]:
        with pytest.raises(ValueError):backend.load_signature(pk,raw)


def test_master_and_identity_roundtrip_check_every_ring_column(backend,issued):
    pk,msk,key=issued
    restored=backend.load_master(msk.to_bytes())
    assert restored.public_key.to_bytes()==pk.to_bytes()
    assert restored.states[b"Alice"][1].to_bytes()==key.to_bytes()
    restored_key=backend.load_signing_key(key.to_bytes(),pk)
    sig=backend.sign(restored_key,b"recovered")
    assert backend.verify(pk,b"Alice",b"recovered",sig)
    broken=key.trapdoor.copy();broken[0,0,0]+=1
    with pytest.raises(ValueError):
        backend.load_signing_key(SigningKey(pk,b"Alice",key.identity_salt,broken).to_bytes())


def test_private_objects_reject_old_wire_and_root_support(issued):
    pk,msk,key=issued
    for cls,obj in [(PublicKey,pk),(MasterSecret,msk),(SigningKey,key)]:
        with pytest.raises(ValueError):cls.from_bytes(b"IBME:SAGELOLI-IBS:v2"+obj.to_bytes())
    bad=msk.root.copy();bad[0,0,0]=3
    with pytest.raises(ValueError):MasterSecret(pk,bad)


def test_issuer_restore_reuses_key_without_new_entropy(backend,issued,tmp_path):
    pk,msk,key=issued
    tmp_path.mkdir(exist_ok=True);(tmp_path/"master.bin").write_bytes(msk.to_bytes())
    class NoEntropy:
        def read(self,n):raise AssertionError("restore drew entropy")
    other=RingBackend(NoEntropy(),native_path=backend.library.path)
    issuer=FixedIssuer(tmp_path,other,expected_public=pk,expected_params=small())
    assert issuer.key_extract(b"Alice").to_bytes()==key.to_bytes()
    assert other.source.used==0


def test_pending_damage_and_pin_fail_without_reissue(backend,issued,tmp_path):
    pk,msk,key=issued;(tmp_path/"master.bin").write_bytes(msk.to_bytes())
    issuer=FixedIssuer(tmp_path,backend)
    (tmp_path/"master.bin.pending").write_bytes(b"pending")
    with pytest.raises(ValueError,match="pending"):issuer.key_extract(b"Alice")
    (tmp_path/"master.bin.pending").unlink()
    raw=(tmp_path/"master.bin").read_bytes();(tmp_path/"master.bin").write_bytes(raw[:-1])
    with pytest.raises(ValueError):issuer.key_extract(b"Alice")
    assert (tmp_path/"master.bin").read_bytes()==raw[:-1]


def test_first_issuance_durably_publishes_and_recovers(backend,tmp_path):
    issuer=FixedIssuer(tmp_path,backend);pk=issuer.initialize(small())
    key=issuer.key_extract(b"first")
    assert not (tmp_path/"master.bin.pending").exists()
    assert issuer.key_extract(b"first").to_bytes()==key.to_bytes()
    assert pk.to_bytes()==issuer.public_key().to_bytes()


def test_hash_resource_failure_rejects_and_corrupt_cache_never_reissues(backend,issued,monkeypatch):
    from experiments.research.candidates.sageloli.uniform import UniformSamplingAbort
    from experiments.research.candidates.sageloli.ring import backend as module
    pk,msk,key=issued;sig=backend.sign(key,b"message")
    def failure(*args):raise UniformSamplingAbort("test budget exhausted")
    monkeypatch.setattr(module,"h2",failure)
    assert not backend.verify(pk,b"Alice",b"message",sig)
    restored=MasterSecret.from_bytes(msk.to_bytes())
    restored.states[b"Alice"]=("issued",SigningKey(pk,b"Bob",key.identity_salt,key.trapdoor))
    before=backend.source.used
    with pytest.raises(RuntimeError):backend.key_extract(restored,b"Alice")
    assert restored.states[b"Alice"]==("failed",None) and backend.source.used==before


def test_publication_fault_keeps_durable_pending_and_blocks_new_entropy(backend,tmp_path,monkeypatch):
    issuer=FixedIssuer(tmp_path,backend);issuer.initialize(small())
    original=issuer._save;calls=0
    def fail_after_pending(master):
        nonlocal calls
        calls+=1
        if calls>=2:raise OSError("test publication fault")
        return original(master)
    monkeypatch.setattr(issuer,"_save",fail_after_pending)
    with pytest.raises(OSError):issuer.key_extract(b"uncertain")
    assert (tmp_path/"master.bin.pending").exists()
    before=backend.source.used
    with pytest.raises(ValueError,match="pending"):issuer.key_extract(b"uncertain")
    assert backend.source.used==before
