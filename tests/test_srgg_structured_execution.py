"""Independent equation parity, actual lifecycle, and failure boundaries."""
from dataclasses import replace
from fractions import Fraction
from hashlib import sha256
import json

import pytest

pytest.importorskip("sage.all",reason="specified WSL Sage required")

from ibme.core.randomness import DeterministicRandom
from experiments.research.gaussian_reference import SamplingAbort
from experiments.research.candidates.srgg import algebra
from experiments.research.candidates.srgg.formal_candidates import conditional_candidate
from experiments.research.candidates.srgg.structured_execution import (
    CountingEntropy, ExactRing, Execution, ExecutionParams, GadgetRecurrence,
    Key, Master, Public, Signature, _canonical, identity_target, message_challenge,
)


def _small():
    return ExecutionParams(2,1,5,3,2,64,2**20,2**20,1,100,1)


def _legacy_fixture():
    new,old = _small(),algebra.Params(2,1,5,3,2)
    r = ExactRing(new)
    a_hat = (((2,3),),)
    witness = (((1,-1),(0,1)),((1,0),(-1,0)))
    b = r.build_public(a_hat,witness)
    # Algebra-only lightweight public carries exactly the two public blocks.
    from types import SimpleNamespace
    public = SimpleNamespace(params=new,a_hat=a_hat,b=b)
    return r,public,old,algebra.build_public(old,a_hat,witness),witness


@pytest.mark.parametrize("degree",[2,4,8,64])
def test_ZZ_negative_cyclic_product_matches_independent_schoolbook(degree):
    params = replace(_small(),degree=degree,user_norm_cap=2+2*degree*16)
    ring = ExactRing(params)
    left = tuple((17*i+3)%11-5 for i in range(degree))
    right = tuple((7*i+2)%13-6 for i in range(degree))
    expected = [0]*degree
    for i,x in enumerate(left):
        for j,y in enumerate(right):
            expected[(i+j)%degree] += x*y*(1 if i+j<degree else -1)
    assert ring.multiply(left,right)==tuple(expected)
    assert ring.multiply(left,right,45)==tuple(x%45 for x in expected)


def test_public_trapdoor_HNF_and_approximate_extraction_match_legacy_equations():
    ring,new,old,legacy,witness = _legacy_fixture()
    assert new.b==legacy.b
    assert ring.public_a(new)==legacy.a
    assert ring.trapdoor_relation(new,witness)
    target = ((11,29),)
    perturbation = ((3,-4),(1,2),(-1,2),(4,-2))
    trace = algebra.extraction_from_values(legacy,witness,target,perturbation)
    residual = tuple(algebra.add(h,algebra.scale(a,-1),old.modulus)
        for h,a in zip(target,algebra.matvec(old,legacy.a,perturbation,old.modulus)))
    digits,error = algebra.gadget_digits(old,residual[0])
    actual = ring.raw_from_values(new,witness,target,perturbation,digits,(error,))
    assert actual==trace.raw_vector
    assert ring.reconstruct(new,target,actual[old.rank:])==algebra.reconstruct_vector(legacy,target,trace.tail)
    assert ring.matvec(ring.public_a(new),ring.reconstruct(new,target,trace.tail),old.modulus)==target


def test_zeta_2Q_signing_response_and_commitment_recovery_match_legacy():
    ring,new,old,legacy,witness = _legacy_fixture()
    target,tail = ((11,29),),((1,-2),(3,0),(-1,1))
    full = ring.reconstruct(new,target,tail)
    perturbation = ((1,-2),(2,3),(-1,4),(3,-4),(1,0))
    u,challenge = (2,-3),(1,0)
    assert ring.zeta()==algebra.zeta(old)
    assert ring.zeta(True)==algebra.zeta_star(old)
    assert ring.multiply(ring.zeta(),ring.zeta(True))==ring.constant(2)
    assert ring.signing_matrix(new,target)==algebra.signing_matrix(legacy,target)
    response = ring.response(full,perturbation,u,challenge)
    assert response==algebra.response_from_values(legacy,target,full,perturbation,u,challenge)
    assert ring.recover(new,target,response,challenge)==algebra.recover_commitment(legacy,target,response,challenge)
    assert ring.recover(new,target,response,challenge)==ring.matvec(ring.signing_matrix(new,target),perturbation,2*old.modulus)
    centers = tuple(Fraction(-x,2) for x in ring.multiply(ring.zeta(True),challenge))
    assert centers==(Fraction(-1,2),Fraction(1,2))


def test_gadget_recurrence_updates_state_and_maps_actual_Z_kernel_cosets():
    sampler = GadgetRecurrence(_small())
    seen = []
    class SpecifiedIntegerDraws:
        def sample(self,width,center,*,rng):
            seen.append((width,center))
            return (-2,3)[len(seen)-1]
    sampler.scalar = SpecifiedIntegerDraws()
    # target quotient is 8; first a=2 -> digit -4 -> next state 4,
    # second a=1 -> digit 10. 5*(-4+3*10)=130 ==40 mod45.
    digits,error = sampler.sample_scalar(40,None)
    assert (digits,error)==((-4,10),0)
    assert seen==[(64,Fraction(-2,3)),(64,Fraction(-1,3))]


def test_real_randomized_gadget_outputs_obey_every_coefficient_congruence():
    sampler = GadgetRecurrence(_small())
    target = ((0,44),)
    values,errors = sampler.sample(target,rng=DeterministicRandom(b"real-wide-gadget"))
    for i in range(2):
        assert (5*sum(3**j*values[j][i] for j in range(2))-target[0][i]+errors[0][i])%45==0
    cert = sampler.certificate()
    assert cert["digit_draws"]==4 and not cert["finite_kernel_equals_legacy_tables"]
    assert Fraction(cert["total_fiber_tv_upper_including_abort"])<Fraction(1,2**96)


@pytest.fixture(scope="module")
def lifecycle():
    params = ExecutionParams.from_candidate(conditional_candidate(degree=8,rank=1,digits=3))
    source = CountingEntropy(DeterministicRandom(b"structured-full-lifecycle-test-v1"))
    execution = Execution(params,rng=source)
    public,master = execution.setup()
    key = execution.key_extract(Master.restore(public,master.snapshot()),b"alice")
    restored = Key.restore(public,key.snapshot())
    signature = execution.sign(restored,b"a real 32 byte message for SRGG!!")
    return execution,public,master,key,restored,signature


def test_real_four_algorithm_lifecycle_signs_after_both_memory_restores(lifecycle):
    execution,public,master,key,restored,signature = lifecycle
    assert master.snapshot()==Master.restore(public,master.snapshot()).snapshot()
    assert key.snapshot()==restored.snapshot()
    assert execution.verify(public,b"alice",b"a real 32 byte message for SRGG!!",signature)
    assert execution.extract_calls==1 and 1<=execution.sign_attempts<=16
    assert execution.rng.used>0
    assert execution.last_master_certificate["security_claim"]=="none"
    assert execution.last_sign_certificate["noise_squared"]=="128"
    for value in (master,key,restored,signature):
        assert "redacted" in repr(value)


def test_identity_message_context_and_nonbinary_signature_rejections(lifecycle):
    execution,public,master,key,restored,signature = lifecycle
    msg = b"a real 32 byte message for SRGG!!"
    assert not execution.verify(public,b"bob",msg,signature)
    assert not execution.verify(public,b"alice",msg+b"!",signature)
    assert not execution.verify(public,b"alice",msg,replace(signature,context=bytes(32)))
    assert not execution.verify(public,b"alice",msg,replace(signature,challenge=(2,)+(0,)*7))
    assert not execution.verify(public,b"alice",msg,replace(signature,response=signature.response[:-1]))
    random_sig = Signature(public.context,((0,)*8,)*6,(1,0,1,0,0,1,1,0))
    assert not execution.verify(public,b"alice",msg,random_sig)


@pytest.mark.parametrize("kind",["master","key"])
def test_memory_snapshot_rejects_truncation_trailing_duplicate_and_corruption(lifecycle,kind):
    _,public,master,key,_,_ = lifecycle
    value,cls = (master,Master) if kind=="master" else (key,Key)
    payload = value.snapshot()
    record = json.loads(payload)
    record["checksum"]="0"*64
    for bad in (payload[:-1],payload+b" ",b'{"body":{},"body":{},"checksum":"x"}',_canonical(record)):
        with pytest.raises(ValueError):
            cls.restore(public,bad)


def test_memory_snapshot_rejects_wrong_public_key_and_changed_parameters(lifecycle):
    execution,public,master,key,_,_ = lifecycle
    other,_ = execution.setup()
    for cls,data in ((Master,master.snapshot()),(Key,key.snapshot())):
        with pytest.raises(ValueError,match="context"):
            cls.restore(other,data)
    changed = replace(public.params,sign_max_attempts=1)
    independent = Execution(changed,rng=DeterministicRandom(b"changed-params"))
    changed_public,_ = independent.setup()
    with pytest.raises(ValueError,match="context"):
        Key.restore(changed_public,key.snapshot())


def test_recomputed_checksum_does_not_bypass_master_relation_or_key_norm(lifecycle):
    _,public,master,key,_,_ = lifecycle
    changed_root = json.loads(master.snapshot())
    coefficients = changed_root["body"]["witness"][0][0]
    coefficients[0] = 1 if coefficients[0]!=1 else -1
    changed_root["checksum"] = sha256(_canonical(changed_root["body"])).hexdigest()
    with pytest.raises(ValueError,match="relation"):
        Master.restore(public,_canonical(changed_root))
    changed_key = json.loads(key.snapshot())
    changed_key["body"]["tail"][0][0] = 2**200
    changed_key["checksum"] = sha256(_canonical(changed_key["body"])).hexdigest()
    with pytest.raises(ValueError,match="norm"):
        Key.restore(public,_canonical(changed_key))


@pytest.mark.parametrize("change",[{"degree":True},{"degree":3},{"degree":1024},{"rank":5},
    {"base":4},{"p":9},{"digits":9},{"user_norm_cap":1},{"signature_norm_cap":2**96+1}])
def test_strict_execution_params_do_not_bypass_legacy_or_accept_bad_public_classes(change):
    with pytest.raises(ValueError):
        replace(_small(),**change)
    with pytest.raises(ValueError):
        algebra.Params(degree=512)


def test_bad_entropy_is_not_silently_replaced_or_retried():
    class Short:
        calls=0
        def read(self,size):
            self.calls+=1
            return bytes(max(0,size-1))
    params = ExecutionParams.from_candidate(conditional_candidate(degree=2,rank=1,digits=3))
    source = Short()
    execution = Execution(params,rng=source)
    with pytest.raises(ValueError,match="byte count"):
        execution.setup()
    assert source.calls==1


def test_extract_sampling_abort_is_propagated_once_without_reselecting(lifecycle,monkeypatch):
    execution,_,master,_,_,_ = lifecycle
    calls=[]
    class AbortPlan:
        def public_certificate(self): return {}
        def sample(self,*,rng):
            calls.append(1)
            raise SamplingAbort("injected finite sampler failure")
    monkeypatch.setattr(execution,"_master_plan",lambda witness:AbortPlan())
    previous = execution.extract_calls
    with pytest.raises(SamplingAbort):
        execution.key_extract(master,b"new-identity")
    assert calls==[1] and execution.extract_calls==previous+1


def test_sign_sampling_abort_is_not_converted_into_norm_retry(lifecycle,monkeypatch):
    execution,_,_,_,key,_ = lifecycle
    calls=[]
    class AbortPlan:
        def public_certificate(self): return {}
        def sample(self,*,rng):
            calls.append(1)
            raise SamplingAbort("injected finite sampler failure")
    monkeypatch.setattr(execution,"_sign_plan",lambda full:AbortPlan())
    previous = execution.sign_attempts
    with pytest.raises(SamplingAbort):
        execution.sign(key,b"message")
    assert calls==[1] and execution.sign_attempts==previous+1


@pytest.mark.parametrize("stage",["gadget","u"])
def test_gadget_and_u_abort_propagate_without_reselecting(lifecycle,monkeypatch,stage):
    execution,_,master,_,key,_ = lifecycle
    calls=[]
    def abort(*args,**kwargs):
        calls.append(1)
        raise SamplingAbort("injected digit/u abort")
    if stage=="gadget":
        monkeypatch.setattr(execution.gadget,"sample",abort)
        with pytest.raises(SamplingAbort): execution.key_extract(master,b"explicit-failed-issue")
    else:
        monkeypatch.setattr(execution.u_scalar,"sample",abort)
        previous = execution.sign_attempts
        with pytest.raises(SamplingAbort): execution.sign(key,b"explicit-failed-sign")
        assert execution.sign_attempts==previous+1
    assert calls==[1]


def test_only_norm_failures_repeat_up_to_explicit_signature_attempt_limit(lifecycle,monkeypatch):
    execution,_,_,_,key,_ = lifecycle
    params = execution.params
    class ZeroPlan:
        def public_certificate(self): return {}
        def sample(self,*,rng): return (0,)*((params.columns+1)*params.degree)
    monkeypatch.setattr(execution,"_sign_plan",lambda full:ZeroPlan())
    monkeypatch.setattr(execution.ring,"response",lambda *args:((2**128,)+(0,)*(params.degree-1),)+
        ((0,)*params.degree,)*params.columns)
    previous = execution.sign_attempts
    with pytest.raises(SamplingAbort,match="norm rejection"):
        execution.sign(key,b"norm-limit")
    assert execution.sign_attempts==previous+params.sign_max_attempts


def test_operational_audit_cap_fails_before_reading_source():
    source = DeterministicRandom(b"whole-audit-cap")
    bounded = CountingEntropy(source,maximum=2)
    with pytest.raises(SamplingAbort):
        bounded.read(3)
    assert bounded.used==0


def test_research_hashes_bind_public_parameters_and_canonical_commitment(lifecycle):
    _,public,_,_,_,_ = lifecycle
    assert identity_target(public,b"alice")!=identity_target(public,b"alice\x00")
    commitment = ((0,)*public.params.degree,)*public.params.rank
    first = message_challenge(public,commitment,b"m")
    assert len(first)==public.params.degree and set(first)<={0,1}
    with pytest.raises(ValueError):
        message_challenge(public,((public.params.modulus*2,)*8,),b"m")
