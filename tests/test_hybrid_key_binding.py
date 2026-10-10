"""Real same-parameter HIBE keys must match the public key they advertise."""

from dataclasses import replace

import pytest

pytest.importorskip("cryptography")
from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.core.randomness import DeterministicRandom
from ibme.protocol.hybrid_hibe import HybridCiphertext, HybridHIBE, encoded_identity
from ibme.hibe.abb10 import ABB10HIBE
from ibme.hibe.api import HIBEKeyBindingValidator
from ibme.lattice.modmat import ModVector
from ibme.protocol.luo_hybrid import make_hybrid_abb10, RESEARCH_HIBE_PARAMS


@pytest.fixture(scope="module")
def real_pairs():
    backend = make_hybrid_abb10()
    values = []
    for label in (b"A", b"B"):
        public, master = backend.setup(RESEARCH_HIBE_PARAMS, rng=DeterministicRandom(b"binding-setup:"+label))
        parent = backend.extract(master, b"Receiver", rng=DeterministicRandom(b"binding-parent:"+label))
        child = backend.derive(parent, b"Sender", rng=DeterministicRandom(b"binding-child:"+label))
        values.append(dict(hpk=public,hmsk=master,sk1=parent,sk2=child))
    return backend, values[0], values[1]


@pytest.mark.parametrize("kind", ["hmsk","sk1","sk2"])
def test_loader_rejects_foreign_secret_under_same_parameter_public_key(real_pairs, kind):
    backend, a, b = real_pairs
    changed = replace(a[kind], inner=b[kind].inner)
    assert a["hpk"].limits == b["hpk"].limits
    assert a["hpk"].inner.meta == b["hpk"].inner.meta
    with pytest.raises(SerializationError):
        backend.component_decoders()[kind].from_bytes(changed.to_bytes())


@pytest.mark.parametrize("kind,field", [("sk1","r1"),("sk2","r2")])
def test_loader_rejects_invalid_private_equation_with_matching_public_metadata(real_pairs, kind, field):
    backend, a, _ = real_pairs
    key = a[kind]
    entries = getattr(key.inner, field)
    changed_rows = ((entries[0][0]+1,)+entries[0][1:],)+entries[1:]
    # The changed coefficient has a nonzero public image, not a zero column.
    assert any(a["hpk"].inner.a.row(i)[0] for i in range(a["hpk"].inner.meta.n))
    altered = replace(key, inner=replace(key.inner, **{field:changed_rows}))
    with pytest.raises(SerializationError):
        backend.component_decoders()[kind].from_bytes(altered.to_bytes())


@pytest.mark.parametrize("operation,kind", [("extract","hmsk"),("derive","sk1"),("decrypt","sk2")])
def test_runtime_rejects_misbound_keys_before_entropy_or_capsule_parsing(real_pairs, operation, kind):
    backend, a, b = real_pairs
    key = replace(a[kind],inner=b[kind].inner)
    class NoEntropy:
        def read(self,count): raise AssertionError("invalid key reached randomness")
    with pytest.raises(InvalidParameterError):
        if operation == "extract": backend.extract(key,b"Other",rng=NoEntropy())
        elif operation == "derive": backend.derive(key,b"Other",rng=NoEntropy())
        else:
            cipher=HybridCiphertext(a["hpk"].context,b"invalid capsule",bytes(12),bytes(16))
            backend.decrypt(key,cipher,rng=NoEntropy())


def adapter(backend=None, **kwargs):
    original=make_hybrid_abb10()
    return HybridHIBE(original.inner_backend if backend is None else backend,
                      backend_id=original.backend_id,public_key_type=original.public_key_type,
                      master_type=original.master_type,level1_type=original.level1_type,
                      level2_type=original.level2_type,**kwargs)


def test_binding_capability_is_explicit_and_accepts_genuine_keys(real_pairs):
    backend,a,_=real_pairs
    assert isinstance(backend.inner_backend,HIBEKeyBindingValidator)
    for kind in ("hmsk","sk1","sk2"):
        assert backend.inner_backend.validate_key_binding(a["hpk"].inner,a[kind].inner) is True
        assert backend.component_decoders()[kind].from_bytes(a[kind].to_bytes()).to_bytes()==a[kind].to_bytes()
    assert backend.inner_backend.validate_key_binding(object(),a["hmsk"].inner) is False
    assert backend.inner_backend.validate_key_binding(a["hpk"].inner,object()) is False


def test_adapter_refuses_missing_validator_and_allows_explicit_injection(real_pairs):
    with pytest.raises(InvalidParameterError): adapter(object())
    backend,a,_=real_pairs
    explicit=adapter(object(),key_binding_validator=backend.inner_backend.validate_key_binding)
    assert explicit.load_master_secret(a["hmsk"].to_bytes()).to_bytes()==a["hmsk"].to_bytes()


@pytest.mark.parametrize("value",[False,None,0,1,"true"])
def test_validator_only_literal_True_authorizes_loading(real_pairs,value):
    _,a,_=real_pairs
    backend=adapter(key_binding_validator=lambda public,secret:value)
    with pytest.raises(SerializationError): backend.load_master_secret(a["hmsk"].to_bytes())


@pytest.mark.parametrize("error",[RuntimeError,ValueError,OSError])
def test_validator_exceptions_fail_closed_on_load_and_runtime(real_pairs,error):
    _,a,_=real_pairs
    def broken(public,secret): raise error("injected binding-check failure")
    backend=adapter(key_binding_validator=broken)
    with pytest.raises(SerializationError): backend.load_master_secret(a["hmsk"].to_bytes())
    with pytest.raises(InvalidParameterError): backend.extract(a["hmsk"],b"Receiver")


@pytest.mark.parametrize("kind",["hmsk","sk1","sk2"])
def test_public_syndrome_mismatch_is_rejected(real_pairs,kind):
    backend,a,_=real_pairs
    key=a[kind]
    values=key.inner.u.to_list()
    values[0]=(values[0]+1)%key.inner.u.q
    changed=replace(key,inner=replace(key.inner,u=ModVector(values,key.inner.u.q)))
    with pytest.raises(SerializationError):
        backend.component_decoders()[kind].from_bytes(changed.to_bytes())


@pytest.mark.parametrize("operation",["setup","extract","derive"])
def test_newly_produced_invalid_keys_are_rejected_before_export(real_pairs,operation):
    _,a,b=real_pairs
    class BrokenOutput(ABB10HIBE):
        def setup(self,*args,**kwargs): return a["hpk"].inner,b["hmsk"].inner
        def extract(self,*args,**kwargs): return b["sk1"].inner
        def derive(self,*args,**kwargs): return b["sk2"].inner
    backend=adapter(BrokenOutput())
    with pytest.raises(InvalidParameterError):
        if operation=="setup": backend.setup(RESEARCH_HIBE_PARAMS)
        elif operation=="extract": backend.extract(a["hmsk"],b"Receiver")
        else: backend.derive(a["sk1"],b"Sender")


def test_cli_rejects_misbound_master_despite_matching_outer_context(real_pairs,tmp_path):
    from ibme.cli import _load_msk,_write_state_meta
    from ibme.ibs.luo_module import LuoModuleIBSBackend
    from ibme.protocol.baseline import PublicKey,MasterSecret
    from ibme.protocol.luo_hybrid import RESEARCH_IBS_PARAMS
    _,a,b=real_pairs
    ipk,imsk=LuoModuleIBSBackend(rng=DeterministicRandom(b"binding-cli-IBS")).setup(RESEARCH_IBS_PARAMS)
    (tmp_path/"mpk.bin").write_bytes(PublicKey(a["hpk"],ipk).to_bytes())
    wrong=replace(a["hmsk"],inner=b["hmsk"].inner)
    (tmp_path/"msk.bin").write_bytes(MasterSecret(wrong,imsk).to_bytes())
    _write_state_meta(tmp_path,mock=False,preset="luo-module-research",
                      hibe_params=RESEARCH_HIBE_PARAMS,ibs_params=RESEARCH_IBS_PARAMS)
    with pytest.raises(SerializationError): _load_msk(tmp_path,False)


@pytest.mark.parametrize("kind,change_parent",[("sk1",True),("sk2",True),("sk2",False)])
def test_consistent_outer_inner_identity_substitution_still_fails_private_equation(real_pairs,kind,change_parent):
    backend,a,_=real_pairs
    key=a[kind]
    identity=b"Substituted"
    raw=encoded_identity(identity,key.public_key.limits,b"P" if change_parent else b"C")
    if kind=="sk1":
        changed=replace(key,inner=replace(key.inner,identity=raw),identities=(identity,))
    elif change_parent:
        changed=replace(key,inner=replace(key.inner,parent_identity=raw),identities=(identity,key.child_identity))
    else:
        changed=replace(key,inner=replace(key.inner,child_identity=raw),identities=(key.parent_identity,identity))
    with pytest.raises(SerializationError):
        backend.component_decoders()[kind].from_bytes(changed.to_bytes())
