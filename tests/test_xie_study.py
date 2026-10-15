"""Actual corrected NTRU/GPV/rejection chain, explicitly not original admission."""
from dataclasses import replace
from itertools import product
import json

import pytest

from ibme.core.errors import EncodingError,RandomnessError,SerializationError
from ibme.core.randomness import DeterministicRandom
from experiments.research.candidates.xie.params import StudyParams
from experiments.research.candidates.xie.ring import coefficients,mul,add,neg,inverse
from experiments.research.candidates.xie.hashing import unrank_challenge,challenge_count,challenge_hash,identity_hash
from experiments.research.candidates.xie.objects import Public,IdentitySecret,Signature,Master,PendingIdentity
from experiments.research.candidates.xie.verification import verify,load_signature
from experiments.research.candidates.xie.qualification import report


class NoEntropy:
    def read(self,n):raise AssertionError("unexpected entropy")


@pytest.fixture(scope="module",params=[16,32])
def instance(request):
    pytest.importorskip("sage.all",reason="prescribed WSL Sage")
    from experiments.research.candidates.xie import runtime
    rng=DeterministicRandom(b"Xie study TEST fixture "+bytes([request.param]))
    public,master=runtime.setup(StudyParams(n=request.param),rng=rng)
    alice=master.extract(b"alice",rng=rng);bob=master.extract(b"bob",rng=rng)
    return runtime,rng,public,master,alice,bob


@pytest.mark.parametrize("changes",[dict(n=8),dict(n=24),dict(q=225),dict(q=17),dict(n=True),
    dict(key_width=0),dict(extract_width=1.5),dict(signing_attempts=0),dict(entropy_limit=True),
    dict(security_claim="NIST-1"),dict(backend_admitted=0),dict(parameters_are_formal=True)])
def test_study_parameters_do_not_claim_paper_or_formal_admission(changes):
    with pytest.raises(ValueError):StudyParams(**changes)


def test_uniform_challenge_unranking_covers_the_whole_stated_space():
    expected={a for a in product((-1,0,1),repeat=4) if sum(abs(x) for x in a)<=2}
    actual=[unrank_challenge(4,2,i) for i in range(challenge_count(4,2))]
    assert len(actual)==len(set(actual))==len(expected) and set(actual)==expected
    assert (0,)*4 in actual
    for rank in (-1,len(expected),True):
        with pytest.raises(ValueError):unrank_challenge(4,2,rank)


def test_literal_paper_conflicts_are_executable_not_silently_erased():
    r=report()
    assert not r["literal_source_reproduction"] and not r["common_IBSBackend"]
    assert not r["equation"]["literal_basis_in_claimed_kernel"]
    assert r["equation"]["rotated_basis_in_claimed_kernel"]
    assert r["gaussian"]["printed_coordinate_width"]!=r["gaussian"]["gpv_coordinate_width"]
    assert r["table_not_reinterpreted_as_exponents"]


@pytest.mark.parametrize("n",[16,32])
def test_modular_inverse_and_negacyclic_signs(n):
    unit=(1,)+(0,)*(n-1);x=(0,1)+(0,)*(n-2)
    inv=inverse(x,12289)
    assert inv==(0,)*(n-1)+(12288,) and mul(x,inv,12289)==unit
    assert mul((0,)*(n-1)+(1,),x)==(-1,)+(0,)*(n-1)
    with pytest.raises(ValueError):inverse((0,)*n,12289)
    with pytest.raises(ValueError):coefficients([False]+[0]*(n-1),n)


def test_canonical_public_and_signature_parser_without_sage():
    p=StudyParams();public=Public(p,(2,)+(0,)*(p.n-1))
    assert Public.from_bytes(public.to_bytes())==public
    s=Signature(public.context,(0,)*p.n,(0,)*p.n,(0,)*p.n)
    assert load_signature(public,s.to_bytes())==s
    for raw in (s.to_bytes()[:-1],s.to_bytes()+b"!",s.to_bytes()+b" ",
                s.to_bytes().replace(b'"context":',b'"unknown":'),
                s.to_bytes().replace(b'"z1":',b'"z1":[],"z1":')):
        with pytest.raises(SerializationError):Signature.from_bytes(raw)
    with pytest.raises(SerializationError):load_signature(replace(public,params=replace(p,message_bytes=33)),s.to_bytes())


def test_genuine_root_preimages_and_signed_integer_equations(instance):
    runtime,rng,public,master,alice,bob=instance;p=public.params
    assert add(mul(master._f,master._G),neg(mul(master._g,master._F)))==(p.q,)+(0,)*(p.n-1)
    assert mul(master._g,inverse(master._f,p.q),p.q)==public.h
    assert master._sampler.dimension==2*p.n and master._sampler.basis.public.nrows==p.n
    assert master._sampler.tv_upper<1
    for key in (alice,bob):
        assert add(key.s1,mul(public.h,key.s2,p.q),p.q)==identity_hash(public,key.identity)
        assert any(x<0 for x in key.s1+key.s2)
        assert IdentitySecret.from_bytes(key.to_bytes())==key
        assert str(key.s1) not in repr(key)


def test_actual_signatures_multiple_messages_and_public_only_verification(instance):
    runtime,rng,public,master,alice,bob=instance
    for key in (alice,bob):
        for message in (b"",b"a\0b",b"m"*32):
            stats={};signature=runtime.sign(key,message,rng=rng,stats=stats)
            assert verify(public,key.identity,message,load_signature(public,signature.to_bytes()))
            assert 1<=stats["signing_attempts"]<=public.params.signing_attempts and stats["entropy_bytes"]>0
            assert not verify(public,key.identity,message,replace(signature,context=bytes(32)))
            assert not verify(public,key.identity,message,replace(signature,z1=(1<<25,)+(0,)*(public.params.n-1)))
    assert master.extract(alice.identity,rng=NoEntropy()) is alice


def test_restoration_is_exact_and_uses_no_new_sampling(instance,monkeypatch):
    runtime,rng,public,master,alice,bob=instance
    raw=master.to_bytes()
    def forbidden(*args,**kwargs):pytest.fail("restore sampled or generated")
    monkeypatch.setattr(runtime,"setup",forbidden);monkeypatch.setattr(runtime,"preimage_sampler",forbidden)
    restored=Master.from_bytes(raw)
    assert restored.to_bytes()==raw and restored.extract(b"alice",rng=NoEntropy())==alice
    assert restored.extract(b"bob",rng=NoEntropy())==bob
    assert "private" in repr(restored)


def test_key_and_cache_context_corruption_rejected(instance):
    runtime,rng,public,master,alice,bob=instance
    with pytest.raises(ValueError):replace(alice,identity=b"bob")
    with pytest.raises(ValueError):replace(alice,s1=add(alice.s1,(1,)+(0,)*(public.params.n-1)))
    values=json.loads(master.to_bytes());values["fields"]["F"][0]+=1
    from experiments.research.candidates.xie.codec import encode
    with pytest.raises(SerializationError):Master.from_bytes(encode(values["kind"],values["fields"]))
    values=json.loads(master.to_bytes());values["fields"]["cache"].append(values["fields"]["cache"][0])
    with pytest.raises(SerializationError):Master.from_bytes(encode(values["kind"],values["fields"]))


def test_entropy_failure_is_pending_across_snapshots(instance):
    runtime,rng,public,master,alice,bob=instance
    copy=Master.from_bytes(master.to_bytes())
    class Short:
        def read(self,n):return b""
    with pytest.raises(RandomnessError):copy.extract(b"failed",rng=Short())
    for state in (copy,Master.from_bytes(copy.to_bytes())):
        with pytest.raises(PendingIdentity):state.extract(b"failed",rng=NoEntropy())


def test_root_generation_and_signature_rejection_budgets(instance,monkeypatch):
    runtime,rng,public,master,alice,bob=instance
    from experiments.research.gaussian_reference import SamplingAbort
    with pytest.raises(SamplingAbort):runtime.setup(replace(public.params,entropy_limit=1),rng=rng)
    monkeypatch.setattr(runtime,"rejection_mass",lambda *args:0)
    # Same real key: exhaust its public limit without a fresh-seed fallback.
    p=replace(public.params,signing_attempts=1)
    alternate=Public(p,public.h)
    f,g,F,G=master._f,master._g,master._F,master._G
    other=Master(alternate,f,g,F,G);key=other.extract(b"alice",rng=rng)
    with pytest.raises(SamplingAbort,match="signature rejection budget"):runtime.sign(key,b"m",rng=rng)


def test_rejection_ratio_zero_shift_and_clipping():
    pytest.importorskip("sage.all",reason="prescribed WSL Sage")
    from experiments.research.candidates.xie.runtime import rejection_mass
    p=StudyParams();scale=1<<p.mass_bits
    assert abs(rejection_mass(p,(0,),(0,))-scale//p.rejection_m)<=1
    assert rejection_mass(p,(0,),(p.signing_width,))<scale//p.rejection_m
    assert rejection_mass(p,(p.signing_width,),(0,))>scale//p.rejection_m
    assert rejection_mass(p,(10*p.signing_width,),(0,))==scale
    assert rejection_mass(p,(0,),(100*p.signing_width,))==0


def test_actual_online_gaussian_diagnostic_at_signing_width():
    pytest.importorskip("sage.all",reason="prescribed WSL Sage")
    from experiments.research.candidates.xie.runtime import OnlineScalarGaussian,options
    p=StudyParams();scalar=OnlineScalarGaussian(p.signing_width**2,p.signing_width**2,options=options(p))
    rng=DeterministicRandom(b"Xie study Gaussian diagnostic TEST")
    samples=[scalar.sample(p.signing_width**2,rng=rng)/p.signing_width for _ in range(1024)]
    assert abs(sum(samples)/len(samples))<0.08
    assert 0.12<sum(x*x for x in samples)/len(samples)<0.20
    assert 0<float(scalar.tv_upper)<1e-12
