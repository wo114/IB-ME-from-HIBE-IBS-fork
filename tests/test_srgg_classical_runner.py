"""Real small public sampling, state attacks and two fresh-state fork runs.

Algebraic zero-block fixtures below deliberately have a public short kernel.
They test executable extraction, never a hardness or success-probability claim.
"""
from dataclasses import replace
from fractions import Fraction
import json

import pytest

pytest.importorskip("sage.all",reason="specified WSL Sage required")

from ibme.core.errors import EncodingError
from ibme.core.randomness import DeterministicRandom, SecureRandom
from experiments.research.gaussian_reference import SamplingAbort, draw_uniform_integer
from experiments.research.candidates.srgg import classical_runner as cr
from experiments.research.candidates.srgg import reduction_samplers as rs
from experiments.research.candidates.srgg import aggregate_budget
from experiments.research.candidates.srgg.formal_candidates import conditional_candidate
from experiments.research.candidates.srgg.structured_execution import (
    ExactRing, ExecutionParams, Signature,
)
from experiments.research.candidates.srgg.wide_scalar import WideScalarGaussian


class NoEntropy:
    def read(self,size):
        raise AssertionError("invalid input or certificate consumed entropy")


class FixedBytes:
    def __init__(self,value):
        self.value,self.calls= value,0

    def read(self,size):
        self.calls+=1
        return bytes([self.value])*size


def small_params():
    return ExecutionParams.from_candidate(conditional_candidate(degree=8,rank=1,digits=3))


def explicit_uniform_public(params,source):
    """Actual bounded public samples, no hidden root or target preimage."""
    def poly():
        return tuple(draw_uniform_integer(source,params.modulus,max_trials=256)
            for _ in range(params.degree))
    a=tuple(tuple(poly() for _ in range(params.rank)) for _ in range(params.rank))
    b=tuple(tuple(poly() for _ in range(params.rank*params.digits)) for _ in range(params.rank))
    return cr.ProofPublic(params,a,b)


def zero_block_public(params=None):
    """Algebraic fixture with a public short kernel; no honest distribution."""
    params=small_params() if params is None else params
    z=(0,)*params.degree
    return cr.ProofPublic(params,((z,)*params.rank,)*params.rank,
        ((z,)*(params.rank*params.digits),)*params.rank)


def new_runner(public=None,*,target_index=1,seed=b"runner-test",limits=None,free=None,coins=None,target=None):
    public=zero_block_public() if public is None else public
    target=((0,)*public.params.degree,)*public.params.rank if target is None else target
    coins=cr.ReplayBank(DeterministicRandom(seed)) if coins is None else coins
    free=cr.FreeReplies(rng=DeterministicRandom(seed+b"-free")) if free is None else free
    return cr.Runner(public,target,target_index,limits=limits,coins=coins,free=free)


@pytest.fixture(scope="module")
def real_lifecycle():
    p=small_params()
    public=explicit_uniform_public(p,DeterministicRandom(b"runner-public-uniform-fixture"))
    target=cr.sample_uniform_target(p,rng=DeterministicRandom(b"runner-external-target"))
    r=new_runner(public,target=target,seed=b"runner-real-lifecycle")
    # A raw 1 B first touch commits to the full target before any decoded H1.
    r.raw_h1(b"Alice",0,1)
    key=r.extract(b"Bob")
    known=r.sign(b"Bob",b"known 32 byte message for SRGG!!")
    simulated=r.sign(b"Alice",b"target 32 byte message for SRGG!")
    return r,key,known,simulated


def test_actual_explicit_public_lifecycle_has_no_target_key_or_master(real_lifecycle):
    r,key,known,simulated=real_lifecycle
    assert r.identities[b"Alice"].h==r.h_star
    assert r.identities[b"Alice"].key is None
    assert r.identities[b"Alice"].status=="target-unissued"
    assert r.ring.matvec(r.ring.public_a(r.public),key,r.p.modulus)==r.h1(b"Bob")
    assert sum(x*x for poly in key for x in poly)<=r.p.user_norm_cap
    assert r.verify(b"Bob",b"known 32 byte message for SRGG!!",known)
    assert r.verify(b"Alice",b"target 32 byte message for SRGG!",simulated)
    assert r.coins.used>0 and r.sign_attempts>=2
    assert "master" not in vars(r) and "trapdoor" not in vars(r)
    assert r.finish(b"Alice",b"target 32 byte message for SRGG!",simulated).won is False


def test_public_wire_and_context_are_explicit_and_have_no_seed(real_lifecycle):
    r,*_=real_lifecycle
    wire=json.loads(r.public.to_bytes())
    assert wire["kind"]=="explicit-proof-public" and "seed" not in wire
    assert cr.ProofPublic(r.p,list(r.public.a_hat),list(r.public.b)).to_bytes()==r.public.to_bytes()
    changed=replace(r.public,a_hat=(((1,)+(0,)*(r.p.degree-1),),))
    assert changed.context!=r.public.context


def test_raw_first_touch_offset_fixes_same_full_h1_and_suffix(real_lifecycle):
    r,*_=real_lifecycle
    state=r.identities[b"Alice"]
    used=r.coins.used
    whole=r.raw_h1(b"Alice",0,64)
    assert r.raw_h1(b"Alice",5,19)==whole[5:24]
    assert r.raw_h1(b"Alice",0,1)==whole[:1]
    assert state.point.first_touches==1 and state.h==r.h1(b"Alice")
    assert r.coins.used>=used
    # Decode independently from the raw words and the original rejection rule.
    q,n=r.p.modulus,r.p.degree*r.p.rank
    width=((q-1).bit_length()+7)//8
    limit=(2**(8*width)//q)*q
    values=[]
    raw=state.point.trajectory.raw_prefix
    for i in range(0,len(raw),width):
        value=int.from_bytes(raw[i:i+width],"big")
        if value<limit:
            values.append(value%q)
    assert tuple(values)==tuple(x for poly in r.h_star for x in poly) and len(values)==n


def test_secure_source_small_run_reaches_real_target_and_public_key_samples():
    p=small_params()
    public=explicit_uniform_public(p,SecureRandom())
    target=cr.sample_uniform_target(p,rng=SecureRandom())
    r=cr.Runner(public,target,1)
    assert r.h1(b"target")==target
    key=r.extract(b"other")
    assert r.ring.matvec(r.ring.public_a(public),key,p.modulus)==r.h1(b"other")
    assert r.coins.used>0


def test_h2_raw_offset_and_later_composite_reply_are_same_entry():
    r=new_runner()
    w=((0,)*r.p.degree,)
    assert r.raw_h2(w,b"m",99,0)==b"" and not r.h2_table
    suffix=r.raw_h2(w,b"m",7,13)
    c=r.h2(w,b"m")
    raw=r.raw_h2(w,b"m",0,20)
    assert raw[7:20]==suffix
    assert tuple((raw[i//8]>>(i%8))&1 for i in range(r.p.degree))==c
    assert len(r.free.values)==1 and r.h2_table[(w,b"m")].owner=="free"
    assert r.raw_h2(w,b"other",0,1)!=b"" and len(r.free.values)==2


def test_h2_owner_survives_cross_identity_alias_and_known_signature():
    # Derive an intentional h alias from a real non-target sample. It violates
    # the independent-target premise and tests only owner/state semantics.
    bank=cr.ReplayBank(DeterministicRandom(b"runner-alias"))
    pre=new_runner(target_index=2,coins=bank)
    alias=pre.h1(b"Bob")
    r=new_runner(target_index=2,coins=bank,target=alias)
    assert r.h1(b"Bob")==r.h1(b"Alice")==alias
    sig=r.sign(b"Alice",b"alias")
    w=r.ring.recover(r.public,alias,sig.response,sig.challenge)
    assert r.verify(b"Bob",b"alias",sig)
    assert r.h2_table[(w,b"alias")].owner=="sign"
    assert (b"Bob",b"alias",sig.to_bytes()) not in r.returned
    own=r.sign(b"Bob",b"known")
    own_w=r.ring.recover(r.public,alias,own.response,own.challenge)
    assert r.h2_table[(own_w,b"known")].owner=="free"
    assert r.h2_table[(w,b"alias")].owner=="sign"


def test_known_key_strong_log_is_exact_identity_message_and_canonical_bytes(real_lifecycle):
    r,_,known,_=real_lifecycle
    triple=(b"Bob",b"known 32 byte message for SRGG!!",known.to_bytes())
    assert triple in r.returned
    assert (b"Alice",triple[1],triple[2]) not in r.returned
    assert (triple[0],triple[1]+b"!",triple[2]) not in r.returned
    changed=replace(known,response=known.response[:-1]+((0,)*r.p.degree,))
    assert (triple[0],triple[1],changed.to_bytes()) not in r.returned


def test_fixed_failed_issue_retains_h_and_never_silently_resamples():
    p=replace(small_params(),raw_norm_cap=1)
    r=new_runner(zero_block_public(p),target_index=2)
    h=r.h1(b"failed")
    assert r.identities[b"failed"].status=="failed"
    used=r.coins.used
    for _ in range(2):
        with pytest.raises(cr.IssueBlocked,match="fixed"):
            r.extract(b"failed")
        with pytest.raises(cr.IssueBlocked,match="fixed"):
            r.sign(b"failed",b"m")
    assert r.h1(b"failed")==h and r.coins.used==used
    assert r.identities[b"failed"].key is None and not r.returned


def test_pending_identity_cannot_reenter():
    r=new_runner()
    r.identities[b"pending"]=cr.IdentityState(1,True)
    with pytest.raises(cr.RunAbort,match="pending"):
        r.h1(b"pending")
    assert r.failed is not None


def test_raw_h1_retains_256_reject_failure_instead_of_conditioning_it_away():
    source=FixedBytes(255)
    r=new_runner(coins=cr.ReplayBank(source))
    assert r.raw_h1(b"target",0,1)==b"\xff"
    point=r.identities[b"target"].point
    assert not point.trajectory.success and point.first_touches==1 and r.hashbad
    calls=source.calls
    assert r.raw_h1(b"target",0,4)==b"\xff"*4
    with pytest.raises(cr.RunAbort,match="retained H1"):
        r.h1(b"target")
    assert source.calls==calls and not r.returned


def test_explicit_target_extract_stops_without_creating_secret():
    r=new_runner()
    with pytest.raises(cr.RunAbort,match="target extraction"):
        r.extract(b"Alice")
    assert r.identities[b"Alice"].key is None and b"Alice" in r.extracted
    with pytest.raises(cr.RunAbort,match="already stopped"):
        r.sign(b"Alice",b"m")


@pytest.mark.parametrize("stage",["target-z","known-P","known-u"])
def test_sampling_abort_is_terminal_without_successful_log_or_norm_retry(monkeypatch,stage):
    r=new_runner()
    r.h1(b"target")
    if stage!="target-z":
        r.extract(b"known")
    calls=[]
    def abort(*args,**kwargs):
        calls.append(1)
        raise SamplingAbort("injected finite sampler abort")
    if stage=="target-z":
        monkeypatch.setattr(rs,"sample_simulator_z",abort)
        identity=b"target"
    elif stage=="known-P":
        monkeypatch.setattr(cr.StructuredSampleF,"sample",abort)
        identity=b"known"
    else:
        monkeypatch.setattr(cr,"sample_batch",abort)
        identity=b"known"
    with pytest.raises(SamplingAbort,match="injected"):
        r.sign(identity,b"m")
    assert calls==[1] and r.sign_attempts==1 and not r.returned and r.failed
    with pytest.raises(cr.RunAbort):
        r.sign(identity,b"m")
    assert calls==[1]


def test_target_simulation_norm_failure_never_programs_h2_or_logs(monkeypatch):
    r=new_runner()
    calls=[]
    def too_long(*args,**kwargs):
        calls.append(1)
        return (r.p.signature_norm_cap+1,)+(0,)*(r.rp.D-1)
    monkeypatch.setattr(rs,"sample_simulator_z",too_long)
    with pytest.raises(cr.RunAbort,match="norm failure"):
        r.sign(b"target",b"m")
    assert calls==[1] and r.sign_attempts==1 and not r.h2_table and not r.returned


def test_target_sign_collision_stops_and_preserves_original_owner():
    bank=cr.ReplayBank(DeterministicRandom(b"runner-collision"))
    pre=new_runner(coins=bank)
    sig=pre.sign(b"target",b"m")
    w=pre.ring.recover(pre.public,pre.h_star,sig.response,sig.challenge)
    r=new_runner(coins=bank)
    r.raw_h2(w,b"m",0,1)
    entry=r.h2_table[(w,b"m")]
    assert entry.owner=="free"
    with pytest.raises(cr.RunAbort,match="collided"):
        r.sign(b"target",b"m")
    assert r.h2_table[(w,b"m")] is entry and entry.owner=="free" and not r.returned


def test_only_known_key_norm_failure_retries_exact_public_attempt_cap(monkeypatch):
    r=new_runner()
    r.h1(b"target")
    r.extract(b"known")
    calls=[]
    actual_response=r.ring.response
    def too_long(*args):
        calls.append(1)
        value=actual_response(*args)
        return ((r.p.signature_norm_cap+1,)+(0,)*(r.p.degree-1),)+value[1:]
    monkeypatch.setattr(r.ring,"response",too_long)
    with pytest.raises(cr.RunAbort,match="retry cap"):
        r.sign(b"known",b"m")
    assert len(calls)==r.p.sign_max_attempts==r.sign_attempts and not r.returned


@pytest.mark.parametrize("kind",["identity","sign","h2"])
def test_query_caps_stop_without_continuing(kind):
    r=new_runner(limits=cr.Limits(identities=1,sign_queries=1,h2_entries=1))
    if kind=="identity":
        r.h1(b"target")
        operation=lambda:r.h1(b"other")
    elif kind=="sign":
        r.sign(b"target",b"first")
        operation=lambda:r.sign(b"target",b"second")
    else:
        r.h2(((0,)*r.p.degree,),b"first")
        operation=lambda:r.h2(((0,)*r.p.degree,),b"second")
    with pytest.raises(cr.RunAbort,match="cap exhausted"):
        operation()
    used=r.coins.used
    with pytest.raises(cr.RunAbort,match="already stopped"):
        r.raw_h1(b"target",0,0)
    assert r.coins.used==used


def test_oversized_or_noncanonical_oracle_input_is_rejected_before_entropy():
    r=new_runner(coins=cr.ReplayBank(NoEntropy()),free=cr.FreeReplies(rng=NoEntropy()))
    w=((0,)*r.p.degree,)
    for identity in (b"",b"x"*4097,"text"):
        with pytest.raises((ValueError,TypeError,EncodingError)):
            r.h1(identity)
    for offset,size in ((True,1),(-1,1),(0,2**30),(4096*r.p.degree,1)):
        with pytest.raises(ValueError):
            r.raw_h1(b"target",offset,size)
    with pytest.raises(ValueError):
        r.h2(((2*r.p.modulus,)*r.p.degree,),b"m")
    with pytest.raises(ValueError):
        r.h2(w,b"m"*65537)
    with pytest.raises(ValueError):
        r.raw_h2(w,b"m",r.limits.raw_query_bytes,1)
    assert not r.identities and not r.h2_table and r.coins.used==0
    assert r.raw_h1(b"target",999,0)==b"" and not r.identities


@pytest.mark.parametrize("payload",[b"",bytearray(1),"bad"])
def test_malformed_nonfree_source_blocks_once_and_cannot_reselect(payload):
    class Bad:
        calls=0
        def read(self,size):
            self.calls+=1
            return payload
    source=Bad()
    bank=cr.ReplayBank(source)
    r=new_runner(coins=bank)
    with pytest.raises(cr.RunAbort,match="invalid private"):
        r.raw_h1(b"target",0,1)
    assert source.calls==1 and bank.blocked and not r.returned and r.failed
    with pytest.raises(cr.RunAbort):
        bank.reader(("another",)).read(1)
    assert source.calls==1


def test_replay_reader_is_fixed_and_cap_failure_is_retained():
    source=FixedBytes(7)
    bank=cr.ReplayBank(source,cap=5)
    first=bank.reader(("label",))
    assert first.read(3)==b"\x07"*3
    assert bank.reader(("label",)).read(3)==b"\x07"*3 and bank.used==3 and source.calls==1
    with pytest.raises(cr.RunAbort,match="cap exhausted"):
        bank.reader(("other",)).read(3)
    assert bank.used==3 and source.calls==1
    with pytest.raises(cr.RunAbort,match="blocked"):
        first.read(1)


def test_free_source_failure_blocks_h2_run_without_reselection():
    source=FixedBytes(1)
    r=new_runner(free=cr.FreeReplies(rng=source),coins=cr.ReplayBank(NoEntropy()))
    with pytest.raises(AssertionError,match="consumed entropy"):
        r.h2(((0,)*r.p.degree,),b"m")
    assert r.failed and len(r.free.values)==1 and not r.h2_table
    with pytest.raises(cr.RunAbort):
        r.h2(((0,)*r.p.degree,),b"m")
    assert source.calls==1


def test_verify_rejects_malformed_signature_before_h1_entropy():
    r=new_runner(coins=cr.ReplayBank(NoEntropy()))
    good=Signature(r.public.context,((0,)*r.p.degree,)*(r.p.columns+1),(0,)*r.p.degree)
    bad=(None,replace(good,context=bytearray(r.public.context)),replace(good,challenge=(2,)*8),
        replace(good,response=good.response[:-1]),replace(good,response=((True,)*8,)*6))
    for signature in bad:
        assert r.verify(b"id",b"m",signature) is False
    assert r.verify(b"",b"m",good) is False
    assert not r.identities and r.coins.used==0


def _algebraic_fork_adversary(observations):
    def attacker(r):
        # The zero public blocks intentionally give a known short kernel.
        observations.append({"empty":not r.identities and not r.h2_table,
            "coins":r.attacker_rng.read(11)})
        r.h1(b"target")
        observations[-1]["key"]=r.extract(b"known")  # actual U/E, twice
        zero=(0,)*r.p.degree
        w=(zero,)
        r.raw_h2(w,b"decoy",0,1)  # fork must preserve this earlier free reply
        c=r.h2(w,b"forgery")
        response=(zero,)*r.p.columns+(c,)
        return b"target",b"forgery",Signature(r.public.context,response,c)
    return attacker


def test_real_second_run_replays_nonfree_coins_and_extracts_checked_kernel():
    public=zero_block_public()
    zero=(0,)*public.params.degree
    first=cr.FreeReplies(prefix=((1,)*8,zero),rng=NoEntropy())
    observations=[]
    result=cr.fork_extract(_algebraic_fork_adversary(observations),public,(zero,),1,
        coins=cr.ReplayBank(DeterministicRandom(b"actual-two-run-fork")),
        first_free=first,second_free_rng=FixedBytes(1))
    assert result["status"]=="fork-extracted" and result["runs"]==2
    assert len(observations)==2 and all(x["empty"] for x in observations)
    assert observations[0]["coins"]==observations[1]["coins"]
    assert observations[0]["key"]==observations[1]["key"]
    assert result["first_free_index"]==1
    assert result["first_replies"][0]==result["second_replies"][0]
    assert result["first_replies"][1]!=result["second_replies"][1]
    delta=result["delta"]
    ring=ExactRing(public.params)
    matrix=tuple(row+(zero,) for row in ring.public_a(public))
    assert any(x for poly in delta for x in poly)
    assert ring.matvec(matrix,delta,public.params.modulus)==(zero,)
    assert sum(x*x for poly in delta for x in poly)<=4*public.params.signature_norm_cap


def test_effective_challenge_collision_with_same_response_does_not_extract():
    public=zero_block_public()
    zero=(0,)*8
    # c=0 and c=1+X^(n/2) differ but have identical eta. Same all-zero z
    # recovers the same W because zeta* times their difference vanishes mod2.
    def attacker(r):
        r.h1(b"target")
        c=r.h2((zero,),b"m")
        return b"target",b"m",Signature(r.public.context,(zero,)*6,c)
    result=cr.fork_extract(attacker,public,(zero,),1,
        first_free=cr.FreeReplies(prefix=(zero,),rng=NoEntropy()),
        second_free_rng=FixedBytes(17))
    assert result["runs"]==2 and result["first_replies"]!=result["second_replies"]
    assert result["status"]=="fork-failed" and result["delta"] is None


def test_changed_free_index_is_rejected_as_a_fork():
    # Deliberately non-replayable external callback state. The extractor must
    # reject the apparent algebraic success if it no longer forks reply I.
    public=zero_block_public()
    zero=(0,)*8
    calls=[]
    def attacker(r):
        calls.append(1)
        r.h1(b"target")
        if len(calls)==2:
            r.h2((zero,),b"extra-decoy")
        c=r.h2((zero,),b"m")
        return b"target",b"m",Signature(r.public.context,(zero,)*5+(c,),c)
    result=cr.fork_extract(attacker,public,(zero,),1,
        first_free=cr.FreeReplies(prefix=(zero,),rng=NoEntropy()),
        second_free_rng=FixedBytes(1))
    assert calls==[1,1] and result["runs"]==2
    assert result["status"]=="fork-failed" and result["delta"] is None


def test_changed_free_owner_to_sign_is_rejected_as_a_fork():
    public=zero_block_public()
    zero=(0,)*8
    bank=cr.ReplayBank(DeterministicRandom(b"runner-owner-swap"))
    pre=new_runner(public,coins=bank)
    simulated=pre.sign(b"target",b"m")
    w=pre.ring.recover(public,(zero,),simulated.response,simulated.challenge)
    first_c=(1-simulated.challenge[0],)+simulated.challenge[1:]
    calls=[]
    def attacker(r):
        # Intentional external state violates the replayability premise, to
        # verify that matching W/message alone cannot label this a valid fork.
        calls.append(1)
        if len(calls)==1:
            r.h1(b"target")
            c=r.h2(w,b"m")
            response=list(simulated.response)
            response[-1]=tuple(a+b-c0 for a,b,c0 in
                zip(response[-1],c,simulated.challenge))
            signature=Signature(public.context,tuple(response),c)
        else:
            signature=r.sign(b"target",b"m")
        response=list(signature.response)
        response[1]=(response[1][0]+1,)+response[1][1:]
        return b"target",b"m",replace(signature,response=tuple(response))
    result=cr.fork_extract(attacker,public,(zero,),1,coins=bank,
        first_free=cr.FreeReplies(prefix=(first_c,),rng=NoEntropy()),
        second_free_rng=NoEntropy())
    assert calls==[1,1] and result["runs"]==2
    assert result["status"]=="fork-failed" and result["delta"] is None


def test_sign_owner_strong_fresh_response_extracts_without_second_run():
    public=zero_block_public()
    zero=(0,)*8
    calls=[]
    def attacker(r):
        calls.append(1)
        sig=r.sign(b"target",b"m")
        response=list(sig.response)
        response[1]=(response[1][0]+1,)+response[1][1:]
        forged=replace(sig,response=tuple(response))
        assert r.verify(b"target",b"m",forged)
        assert forged.to_bytes()!=sig.to_bytes()
        return b"target",b"m",forged
    result=cr.fork_extract(attacker,public,(zero,),1,
        coins=cr.ReplayBank(DeterministicRandom(b"runner-direct-owner")))
    assert result["status"]=="direct-owner-extracted" and result["runs"]==1 and calls==[1]
    assert result["delta"][1]==(1,)+(0,)*7


def test_finish_classifies_unseen_point_before_verifier_queries_it():
    r=new_runner(free=cr.FreeReplies(prefix=((0,)*8,),rng=NoEntropy()))
    sig=Signature(r.public.context,((0,)*8,)*6,(0,)*8)
    finish=r.finish(b"target",b"unseen",sig)
    assert finish.won and finish.owner=="unseen" and finish.free_index is None
    assert len(r.h2_table)==1 and next(iter(r.h2_table.values())).owner=="free"


def test_fork_stops_after_target_extract_and_does_not_rerun():
    calls=[]
    def attacker(r):
        calls.append(1)
        r.extract(b"target")
        raise AssertionError("target extract should have stopped")
    public=zero_block_public()
    result=cr.fork_extract(attacker,public,((0,)*8,),1)
    assert result=={"status":"first-run-aborted","delta":None,"runs":1} and calls==[1]


def test_n512_report_is_zero_entropy_and_separates_uncovered_global_cap(monkeypatch):
    def forbidden(*args,**kwargs):
        raise AssertionError("zero-entropy report created a source or drew")
    monkeypatch.setattr(cr,"SecureRandom",forbidden)
    monkeypatch.setattr(rs,"SecureRandom",forbidden)
    monkeypatch.setattr(aggregate_budget,"SecureRandom",forbidden)
    monkeypatch.setattr(WideScalarGaussian,"sample",forbidden)
    report=cr.build_report()
    assert report["parameters"]["degree"]==512
    assert report["actual_entropy_bytes"]==0 and not report["draw_performed"]
    assert report["two_run_sampler_raw_upper_bytes"]==2*report["one_run_sampler_raw_upper_bytes"]
    assert report["two_run_nonfree_sampler_raw_upper_bytes"]>report["physical_replay_bank_cap_bytes"]
    assert report["two_run_nonfree_upper_covered_by_bank_cap"] is False
    assert report["global_entropy_cap_abort_upper"] is None
    assert report["attacker_own_time_and_coin_budget_included"] is False
    assert report["external_uniform_target_sampling_in_run_cost"] is False
    assert Fraction(report["public_u"]["finite_to_ideal_tv_upper_including_abort_exact"])<Fraction(1,2**176)
    assert report["security_claim"]=="none" and not report["backend_admitted"]
    assert report["parameters_are_formal"] is False and report["nist_security_category"] is None
    assert report["proof_public_has_production_seed_embedding"] is False
    assert report["whole_adaptive_security_reduction_proved"] is False
    assert report["actual_adversary_executed_by_report"] is False
    assert len(report["source_sha256"])==8


@pytest.mark.parametrize("kwargs",[{"identities":True},{"sign_queries":0},
    {"h2_entries":1.5},{"raw_query_bytes":2**29},{"entropy_bytes":-1}])
def test_limits_are_strict_public_inputs(kwargs):
    with pytest.raises(ValueError):
        cr.Limits(**kwargs)


def test_unvalidated_public_target_and_limits_are_rejected():
    public=zero_block_public()
    for target in (((public.params.modulus,)*8,),((False,)*8,),((0,)*7,)):
        with pytest.raises(ValueError):
            cr.Runner(public,target,1)
    for index in (True,0,9):
        with pytest.raises(ValueError):
            cr.Runner(public,((0,)*8,),index)
    with pytest.raises(TypeError):
        cr.Runner(public,((0,)*8,),1,limits={})
    with pytest.raises(TypeError):
        cr.resource_certificate(public.params,limits={})
    with pytest.raises(TypeError):
        cr.sample_uniform_target(object(),rng=NoEntropy())


def test_report_cli_refuses_existing_receipt(tmp_path,monkeypatch):
    target=tmp_path/"existing.json"
    target.write_bytes(b"frozen\n")
    monkeypatch.setattr(cr,"build_report",lambda path:{"actual_entropy_bytes":0})
    monkeypatch.setattr("sys.argv",["classical_runner","--output",str(target)])
    with pytest.raises(FileExistsError):
        cr.main()
    assert target.read_bytes()==b"frozen\n"
