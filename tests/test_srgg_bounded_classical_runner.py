"""New bounded Run: real small draws, two-run replay and all-source accounting."""
from dataclasses import replace
import json

import pytest

pytest.importorskip("sage.all",reason="specified WSL Sage required")

from ibme.core.randomness import DeterministicRandom
from experiments.research.gaussian_reference import SamplingAbort, draw_uniform_integer
from experiments.research.candidates.srgg import bounded_classical_runner as br
from experiments.research.candidates.srgg import classical_runner as v1
from experiments.research.candidates.srgg import aggregate_budget
from experiments.research.candidates.srgg.formal_candidates import conditional_candidate
from experiments.research.candidates.srgg.structured_execution import ExecutionParams, ExactRing, Signature
from experiments.research.candidates.srgg.wide_scalar import WideScalarGaussian


class NoEntropy:
    def read(self,size):
        raise AssertionError("preflight or zero-entropy report consumed entropy")


class FixedBytes:
    def __init__(self,value):
        self.value,self.calls,self.bytes=value,0,0
    def read(self,size):
        self.calls+=1
        self.bytes+=size
        return bytes([self.value])*size


def params():
    return ExecutionParams.from_candidate(conditional_candidate(degree=8,rank=1,digits=3))


def zero_fixture(p=None):
    """Known-public-kernel algebra fixture, never an honest/hard distribution."""
    p=params() if p is None else p
    z=(0,)*p.degree
    return br.ProofPublic(p,((z,),),((z,)*p.digits,))


def bank_for(public,limits=None,source=None):
    limits=br.Limits() if limits is None else limits
    cert=br.resource_certificate(public.params,limits=limits)
    return br.ReplayBank(DeterministicRandom(b"bounded-bank") if source is None else source,
        cap=cert["nonfree_bank_physical_cap_bytes"])


def runner(public=None,limits=None,source=None,free=None):
    public=zero_fixture() if public is None else public
    limits=br.Limits() if limits is None else limits
    return br.Runner(public,((0,)*public.params.degree,),1,limits=limits,
        coins=bank_for(public,limits,source),free=free)


def test_n512_default_two_complete_runs_and_every_coin_class_are_covered_without_entropy(monkeypatch):
    def forbidden(*args,**kwargs):
        raise AssertionError("zero-entropy report created RNG or drew")
    monkeypatch.setattr(br,"SecureRandom",forbidden)
    monkeypatch.setattr(v1,"SecureRandom",forbidden)
    monkeypatch.setattr(v1.rs,"SecureRandom",forbidden)
    monkeypatch.setattr(aggregate_budget,"SecureRandom",forbidden)
    monkeypatch.setattr(WideScalarGaussian,"sample",forbidden)
    report=br.build_report()
    assert report["limits"]=={"identities":8,"sign_queries":8,"h2_entries":128,
        "raw_query_bytes":65536,"entropy_bytes":4*1024**3,"attacker_coin_bytes":1024*1024}
    assert report["two_run_nonfree_sampler_raw_upper_bytes"]==3255750784
    assert report["two_run_attacker_coin_upper_bytes"]==2097152
    assert report["two_run_free_h2_source_upper_bytes"]==16384
    assert report["two_run_all_source_upper_bytes"]==3257864320
    assert report["nonfree_bank_physical_cap_bytes"]==4*1024**3-16384
    assert report["two_run_nonfree_bank_upper_bytes"]<=report["nonfree_bank_physical_cap_bytes"]
    assert report["admitted"] and report["global_entropy_cap_abort_upper_exact"]=="0"
    assert report["global_entropy_cap_abort_upper"]==0
    assert not report["draw_performed"] and report["actual_entropy_bytes"]==0
    assert report["security_claim"]=="none" and report["backend_admitted"] is False
    assert report["parameters_are_formal"] is False and report["nist_security_category"] is None
    assert report["whole_adaptive_security_reduction_proved"] is False
    assert report["proof_public_has_production_seed_embedding"] is False
    assert report["finite_sampler_and_hash_abort_terms_removed"] is False
    assert report["bound_is_source_bytes_not_python_heap_size"] is True
    assert len(report["source_sha256"])==9


def test_insufficient_two_run_budget_rejects_runner_and_fork_before_entropy(monkeypatch):
    public=zero_fixture()
    need=br.resource_certificate(public.params)["two_run_all_source_upper_bytes"]
    low=br.Limits(entropy_bytes=need-1)
    report=br.resource_certificate(public.params,limits=low)
    assert not report["admitted"] and report["global_entropy_cap_abort_upper"] is None
    def forbidden(*args,**kwargs):
        raise AssertionError("rejected profile constructed a random source")
    monkeypatch.setattr(br,"SecureRandom",forbidden)
    with pytest.raises(ValueError,match="not admitted before entropy"):
        br.Runner(public,((0,)*8,),1,limits=low)
    with pytest.raises(ValueError,match="not admitted before entropy"):
        br.fork_extract(lambda r:None,public,((0,)*8,),1,limits=low)
    exact=br.Limits(entropy_bytes=need)
    assert br.resource_certificate(public.params,limits=exact)["admitted"]


def test_large_cap_is_lazy_and_single_request_cannot_exceed_frozen_256mib():
    bank=br.ReplayBank(NoEntropy(),cap=4*1024**3)
    assert bank.used==0 and bank.tapes=={} and bank.runs==0
    read=bank.reader(("lazy",))
    with pytest.raises(ValueError,match="single entropy request"):
        read.read(br.MAX_REQUEST_BYTES+1)
    assert bank.used==0 and bank.tapes=={} and not bank.blocked


def test_replay_bank_fixed_prefix_distinct_tapes_and_blocked_cap():
    source=FixedBytes(9)
    bank=br.ReplayBank(source,cap=10)
    a=bank.reader(("a",))
    assert a.read(4)==bytes([9])*4
    assert bank.reader(("a",)).read(4)==bytes([9])*4 and source.bytes==4
    assert a.read(2)==bytes([9])*2 and source.bytes==6
    assert bank.reader(("b",)).read(3)==bytes([9])*3 and source.bytes==9
    with pytest.raises(br.RunAbort,match="cap exhausted"):
        bank.reader(("new",)).read(2)
    assert bank.used==9 and source.bytes==9 and bank.blocked
    with pytest.raises(br.RunAbort,match="blocked"):
        bank.reader(("a",)).read(1)


@pytest.mark.parametrize("payload",[b"",bytearray(4),"bad"])
def test_malformed_nonfree_source_is_retained_and_never_replaced(payload):
    class Bad:
        calls=0
        def read(self,size):
            self.calls+=1
            return payload
    source=Bad()
    r=runner(source=source)
    with pytest.raises(br.RunAbort,match="invalid private"):
        r.raw_h1(b"target",0,1)
    assert source.calls==1 and r.failed and r.coins.blocked and not r.returned
    with pytest.raises(br.RunAbort):
        r.coins.reader(("another",)).read(1)
    assert source.calls==1


def test_bank_allows_only_two_registered_fresh_runs_and_prechecks_headroom():
    public=zero_fixture()
    bank=bank_for(public)
    free=lambda:br.FreeReplies(8,128,rng=NoEntropy())
    a=br.Runner(public,((0,)*8,),1,coins=bank,free=free())
    b=br.Runner(public,((0,)*8,),1,coins=bank,free=free())
    assert a.coins is b.coins and bank.runs==2 and bank.used==0
    with pytest.raises(ValueError,match="fresh bounded run"):
        br.Runner(public,((0,)*8,),1,coins=bank,free=free())
    small=br.ReplayBank(NoEntropy(),cap=4)
    with pytest.raises(ValueError,match="headroom before entropy"):
        small.register_run(5)
    assert small.used==0 and small.runs==0


def test_attacker_tape_exact_limit_replays_and_overrun_is_terminal_without_more_entropy():
    public=zero_fixture()
    limits=br.Limits(attacker_coin_bytes=7)
    source=FixedBytes(3)
    bank=bank_for(public,limits,source)
    r=br.Runner(public,((0,)*8,),1,limits=limits,coins=bank)
    assert r.attacker_rng.read(3)+r.attacker_rng.read(4)==bytes([3])*7
    assert source.bytes==7 and r.attacker_rng.used==7
    replay=br.Runner(public,((0,)*8,),1,limits=limits,coins=bank)
    assert replay.attacker_rng.read(7)==bytes([3])*7 and source.bytes==7
    with pytest.raises(br.RunAbort,match="forward entropy cap"):
        r.attacker_rng.read(1)
    assert source.bytes==7 and r.failed and r.attacker_rng.blocked
    with pytest.raises(br.RunAbort,match="already stopped"):
        r.h1(b"target")


def test_bad_attacker_source_marks_both_tape_and_runner_failed():
    class Bad:
        def read(self,size): return b""
    r=runner(source=Bad())
    with pytest.raises(br.RunAbort,match="invalid private"):
        r.attacker_rng.read(1)
    assert r.failed and r.attacker_rng.blocked and r.coins.blocked


def test_free_h2_cap_charges_only_fresh_replies_and_preserves_fork_prefix():
    source=FixedBytes(1)
    free=br.FreeReplies(8,3,prefix=((0,)*8,),rng=source)
    assert free.next(8)==((0,)*8,0) and source.bytes==0
    assert free.next(8)==((1,)+(0,)*7,1)
    assert free.next(8)==((1,)+(0,)*7,2) and source.bytes==2
    with pytest.raises(br.RunAbort,match="reply cap exhausted"):
        free.next(8)
    assert source.bytes==2 and free.source.used==2


def test_free_source_fault_blocks_entire_run_and_retains_no_h2_entry():
    class Bad:
        calls=0
        def read(self,size):
            self.calls+=1
            return b""
    source=Bad()
    r=runner(free=br.FreeReplies(8,128,rng=source))
    with pytest.raises(br.RunAbort,match="invalid forward"):
        r.h2(((0,)*8,),b"m")
    assert source.calls==1 and r.failed and r.free.source.blocked and not r.h2_table
    with pytest.raises(br.RunAbort):
        r.h2(((0,)*8,),b"m")
    assert source.calls==1


def test_actual_public_sampling_known_sign_and_target_sim_with_inherited_methods():
    p=params()
    source=DeterministicRandom(b"bounded-uniform-explicit-public")
    def poly(): return tuple(draw_uniform_integer(source,p.modulus,max_trials=256) for _ in range(8))
    public=br.ProofPublic(p,((poly(),),),((poly(),poly(),poly()),))
    target=v1.sample_uniform_target(p,rng=DeterministicRandom(b"bounded-external-target"))
    r=br.Runner(public,target,1,coins=bank_for(public))
    assert br.Runner.sign is v1.Runner.sign and br.Runner.raw_h1 is v1.Runner.raw_h1
    assert r.raw_h1(b"Alice",0,1)
    key=r.extract(b"Bob")
    msg=b"0123456789abcdef0123456789abcdef"
    signed=r.sign(b"Bob",msg)
    simulated=r.sign(b"Alice",msg)
    assert r.ring.matvec(r.ring.public_a(public),key,p.modulus)==r.h1(b"Bob")
    assert r.verify(b"Bob",msg,signed) and r.verify(b"Alice",msg,simulated)
    assert r.identities[b"Alice"].key is None
    assert r.identities[b"Alice"].point.first_touches==1
    assert not r.finish(b"Alice",msg,simulated).won
    w=r.ring.recover(public,target,simulated.response,simulated.challenge)
    assert r.h2_table[(w,msg)].owner=="sign"
    assert r.coins.used>0 and r.free.source.used>0


def _fork_attacker(observations,*,changed_index=False):
    def attacker(r):
        observations.append({"empty":not r.h2_table and not r.identities,
            "coins":r.attacker_rng.read(17)})
        r.raw_h1(b"target",0,1)
        observations[-1]["key"]=r.extract(b"known")
        zero=(0,)*8
        r.raw_h2((zero,),b"decoy",7,2)
        if changed_index and len(observations)==2:
            r.h2((zero,),b"extra")
        c=r.h2((zero,),b"forge")
        return b"target",b"forge",Signature(r.public.context,(zero,)*5+(c,),c)
    return attacker


def test_actual_two_runs_replay_attacker_sampler_and_raw_tapes_with_bounded_free_sources():
    public=zero_fixture()
    observations=[]
    first,second=FixedBytes(0),FixedBytes(1)
    result=br.fork_extract(_fork_attacker(observations),public,((0,)*8,),1,
        coins=bank_for(public),first_free_rng=first,second_free_rng=second)
    assert result["status"]=="fork-extracted" and result["runs"]==2
    assert len(observations)==2 and all(x["empty"] for x in observations)
    assert observations[0]["coins"]==observations[1]["coins"]
    assert observations[0]["key"]==observations[1]["key"]
    assert result["attacker_read_bytes_first"]==result["attacker_read_bytes_second"]==17
    assert result["first_free_index"]==1
    assert result["first_replies"][0]==result["second_replies"][0]
    assert result["first_replies"][1]!=result["second_replies"][1]
    assert result["free_h2_source_bytes"]==first.bytes+second.bytes==3
    assert result["all_source_bytes"]==result["nonfree_physical_source_bytes"]+3
    assert result["all_source_bytes"]<=4*1024**3
    assert result["global_entropy_cap_abort_upper_exact"]=="0"
    ring=ExactRing(public.params)
    matrix=tuple(row+((0,)*8,) for row in ring.public_a(public))
    delta=result["delta"]
    assert any(x for poly in delta for x in poly)
    assert ring.matvec(matrix,delta,public.params.modulus)==((0,)*8,)
    assert sum(x*x for poly in delta for x in poly)<=4*public.params.signature_norm_cap


def test_changed_second_free_index_cannot_be_mislabeled_as_successful_fork():
    public=zero_fixture()
    observations=[]
    result=br.fork_extract(_fork_attacker(observations,changed_index=True),public,((0,)*8,),1,
        coins=bank_for(public),first_free_rng=FixedBytes(0),second_free_rng=FixedBytes(1))
    assert len(observations)==2 and result["runs"]==2
    assert result["status"]=="fork-failed" and result["delta"] is None


def test_changed_second_free_owner_to_sign_is_rejected():
    # Intentionally violates callback replayability using external state, to
    # check that the wrapper refuses this misleading matching-W path.
    public=zero_fixture()
    zero=(0,)*8
    pre=runner(public)
    simulated=pre.sign(b"target",b"m")
    w=pre.ring.recover(public,(zero,),simulated.response,simulated.challenge)
    first_c=(1-simulated.challenge[0],)+simulated.challenge[1:]
    bits=sum(value<<i for i,value in enumerate(first_c))
    calls=[]
    def attacker(r):
        calls.append(1)
        if len(calls)==1:
            r.h1(b"target")
            c=r.h2(w,b"m")
            response=list(simulated.response)
            response[-1]=tuple(a+b-c0 for a,b,c0 in zip(response[-1],c,simulated.challenge))
            sig=Signature(public.context,tuple(response),c)
        else:
            sig=r.sign(b"target",b"m")
        response=list(sig.response)
        response[1]=(response[1][0]+1,)+response[1][1:]
        return b"target",b"m",replace(sig,response=tuple(response))
    result=br.fork_extract(attacker,public,(zero,),1,coins=bank_for(public),
        first_free_rng=FixedBytes(bits),second_free_rng=NoEntropy())
    assert calls==[1,1] and result["runs"]==2
    assert result["status"]=="fork-failed" and result["delta"] is None


def test_equal_effective_challenges_with_equal_response_are_not_nonzero_extraction():
    public=zero_fixture()
    zero=(0,)*8
    def attacker(r):
        r.h1(b"target")
        c=r.h2((zero,),b"m")
        return b"target",b"m",Signature(public.context,(zero,)*6,c)
    result=br.fork_extract(attacker,public,(zero,),1,coins=bank_for(public),
        first_free_rng=FixedBytes(0),second_free_rng=FixedBytes(17))
    assert result["runs"]==2 and result["status"]=="fork-failed" and result["delta"] is None


def test_direct_sign_owner_extraction_uses_actual_target_sim_and_one_run():
    public=zero_fixture()
    def attacker(r):
        sig=r.sign(b"target",b"m")
        response=list(sig.response)
        response[1]=(response[1][0]+1,)+response[1][1:]
        return b"target",b"m",replace(sig,response=tuple(response))
    result=br.fork_extract(attacker,public,((0,)*8,),1,coins=bank_for(public))
    assert result["status"]=="direct-owner-extracted" and result["runs"]==1
    assert result["free_h2_source_bytes"]==0 and result["delta"][1]==(1,)+(0,)*7


def test_failed_target_extract_and_attacker_budget_have_no_success_log():
    public=zero_fixture()
    def extract(r):
        r.extract(b"target")
    result=br.fork_extract(extract,public,((0,)*8,),1,coins=bank_for(public))
    assert result["status"]=="first-run-aborted" and result["runs"]==1 and result["delta"] is None
    limits=br.Limits(attacker_coin_bytes=1)
    def excess(r):
        r.attacker_rng.read(2)
    result=br.fork_extract(excess,public,((0,)*8,),1,limits=limits,coins=bank_for(public,limits))
    assert result["status"]=="first-run-aborted" and result["all_source_bytes"]==0


def test_frozen_v1_limits_and_exact_type_guards_are_not_modified_or_bypassed():
    public=zero_fixture()
    with pytest.raises(ValueError):
        v1.Limits(entropy_bytes=4*1024**3)
    with pytest.raises(TypeError):
        v1.Runner(public,((0,)*8,),1,limits=br.Limits())
    with pytest.raises(ValueError):
        v1.Runner(public,((0,)*8,),1,coins=bank_for(public))
    with pytest.raises(TypeError):
        br.Runner(public,((0,)*8,),1,limits=v1.Limits())


@pytest.mark.parametrize("kwargs",[{"entropy_bytes":True},{"entropy_bytes":8*1024**3+1},
    {"attacker_coin_bytes":0},{"attacker_coin_bytes":br.MAX_REQUEST_BYTES+1},
    {"h2_entries":0},{"raw_query_bytes":1.5}])
def test_new_public_limits_are_strict(kwargs):
    with pytest.raises(ValueError):
        br.Limits(**kwargs)


def test_wrong_used_or_prescribed_free_objects_are_rejected_before_sources():
    public=zero_fixture()
    free=br.FreeReplies(8,128,prefix=((0,)*8,),rng=NoEntropy())
    with pytest.raises(ValueError,match="fresh unprescribed"):
        br.fork_extract(lambda r:None,public,((0,)*8,),1,coins=bank_for(public),first_free=free)
    wrong=br.FreeReplies(8,1,rng=NoEntropy())
    with pytest.raises(ValueError,match="fresh bounded FreeReplies"):
        runner(public,free=wrong)
    bank=bank_for(public)
    bank.reader(("extra",)).read(1)
    with pytest.raises(ValueError,match="empty fresh"):
        br.fork_extract(lambda r:None,public,((0,)*8,),1,coins=bank)


def test_exclusive_json_output_preserves_existing_evidence(tmp_path,monkeypatch):
    output=tmp_path/"already.json"
    output.write_bytes(b"frozen\n")
    monkeypatch.setattr(br,"build_report",lambda path:{"actual_entropy_bytes":0})
    monkeypatch.setattr("sys.argv",["bounded_classical_runner","--output",str(output)])
    with pytest.raises(FileExistsError):
        br.main()
    assert output.read_bytes()==b"frozen\n"
