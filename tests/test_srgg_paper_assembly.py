"""Real Table 4 arithmetic and public adapter checks; no HIBE stand-in.

Sparse fixtures below test parsing/bounds only. Actual randomized signature
and full LATTE combinations are exercised separately and never inferred here.
"""
from dataclasses import replace
import importlib.util
from math import isqrt

import pytest

pytest.importorskip('sage.all',reason='paper SRGG arithmetic needs prescribed WSL Sage')

from ibme.core.errors import SerializationError
from ibme.core.randomness import SecureRandom
from ibme.ibs.srgg import paper_registration as reg
from experiments.research.candidates.srgg import paper_backend, paper_compact
from experiments.research.candidates.srgg.paper_algebra import PaperRing, public_matrix
from experiments.research.candidates.srgg.paper_objects import PublicKey, MasterSecret, SigningKey, Signature


class NoRead:
    def read(self,_count):raise AssertionError('public parsing/verification consumed entropy')


def test_executable_adapter_is_present():
    assert importlib.util.find_spec('ibme.ibs.srgg.paper') is not None, 'paper boundary adapter is missing'
    backend=reg.factory(NoRead(),'compact')
    assert backend.security_claim=='none' and not backend.backend_admitted


@pytest.fixture(scope='module',params=['PARAM-I','PARAM-II','PARAM-III'])
def algebra(request):
    params=reg.PaperSuiteParams(request.param)
    p=params.paper_params();ring=PaperRing(p)
    a_hat=public_matrix(p,bytes(range(32)))
    witness=tuple(tuple(ring.constant(0) for _ in range(p.rank*p.digits)) for _ in range(2*p.rank))
    public=PublicKey(p,bytes(range(32)),a_hat,ring.build_public(a_hat,witness))
    key=SigningKey(public,b'algebra fixture',(ring.constant(0),)*((1+p.digits)*p.rank))
    master=MasterSecret(public,witness,{key.identity:('issued',key)})
    response=[ring.constant(0)]*(p.columns+1)
    response[0]=(-isqrt(p.signature_norm_cap),)+(0,)*(p.degree-1)
    signature=Signature(public.context,tuple(response),(0,)*p.degree)
    return params,public,master,key,signature


@pytest.mark.parametrize('fmt',['reference','compact'])
def test_strict_signature_loading_keeps_norm_and_wire_size_bound(algebra,fmt):
    params,public,master,key,signature=algebra
    backend=reg.factory(NoRead(),fmt)
    encoded=signature.to_bytes() if fmt=='reference' else paper_compact.dump_signature(public,signature)
    loaded=backend.load_signature(public,encoded)
    assert loaded.to_bytes()==encoded
    assert len(encoded)<=reg.signature_size(params,fmt)
    for malformed in (b'',encoded[:-1],encoded+b'\0'):
        with pytest.raises(SerializationError):backend.load_signature(public,malformed)
    wrong_format=paper_compact.dump_signature(public,signature) if fmt=='reference' else signature.to_bytes()
    with pytest.raises(SerializationError):backend.load_signature(public,wrong_format)
    bad_response=list(signature.response)
    bad_response[0]=(isqrt(public.params.signature_norm_cap)+1,)+(0,)*(public.params.degree-1)
    bad=replace(signature,response=tuple(bad_response))
    wire=bad.to_bytes() if fmt=='reference' else paper_compact.dump_signature(public,bad)
    with pytest.raises(SerializationError):backend.load_signature(public,wire)
    wrong_context=replace(signature,context=b'\xff'*32)
    with pytest.raises(SerializationError):
        if fmt=='reference':
            backend.load_signature(public,wrong_context.to_bytes())
        else:
            from ibme.ibs.srgg.paper import CompactSignature
            CompactSignature(public,wrong_context)
    assert backend.verify(public,key.identity,b'message',None) is False


def test_decoders_and_checks_bind_every_paper_profile_and_interpretation(algebra):
    params,public,master,key,signature=algebra
    spec=reg.backend_spec()
    for name,value in [('ipk',public),('imsk',master),('sk',key)]:
        restored=spec.decoders[name].from_bytes(value.to_bytes())
        assert restored.to_bytes()==value.to_bytes()
        spec.check_object(restored,params)
        with pytest.raises(SerializationError):
            spec.check_object(restored,replace(params,interpretation='literal-density-width'))
        other='PARAM-II' if params.profile_name=='PARAM-I' else 'PARAM-I'
        with pytest.raises(SerializationError):spec.check_object(restored,replace(params,profile_name=other))
    assert spec.master_public_key(master)==public


@pytest.mark.parametrize('fmt',['reference','compact'])
def test_actual_sampled_lifecycle_and_fixed_key_recovery(fmt):
    params=reg.PaperSuiteParams()
    backend=reg.factory(SecureRandom(),fmt)
    public,master=backend.setup(params)
    identity=b'A'*64;message=b'M'*32
    key=backend.key_extract(master,identity)
    before=master.to_bytes()
    assert backend.key_extract(master,identity).to_bytes()==key.to_bytes()
    assert master.to_bytes()==before
    signature=backend.sign(key,message)
    assert backend.verify(public,identity,message,signature)
    assert not backend.verify(public,b'wrong',message,signature)
    assert not backend.verify(public,identity,b'changed',signature)
    assert len(signature.to_bytes())<=reg.signature_size(params,fmt)
    spec=reg.backend_spec();restored=reg.factory(NoRead(),fmt)
    pk=spec.decoders['ipk'].from_bytes(public.to_bytes())
    msk=spec.decoders['imsk'].from_bytes(before)
    sk=spec.decoders['sk'].from_bytes(key.to_bytes())
    assert restored.key_extract(msk,identity).to_bytes()==sk.to_bytes()
    loaded=restored.load_signature(pk,signature.to_bytes())
    assert restored.verify(pk,identity,message,loaded)
    assert msk.to_bytes()==before
