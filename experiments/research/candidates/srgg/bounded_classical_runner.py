"""New bounded explicit-public classical Run/fork; frozen v1 stays untouched.

Admitted profiles cover both complete runs, bounded attacker coins and free H2
with a lazy global byte cap. This closes only that extra resource-abort term;
source errors, finite-sampler aborts and the full reduction remain separate.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from pathlib import Path
import platform

from ibme.core.randomness import SecureRandom
from experiments.research.gaussian_reference import SamplingAbort
from . import classical_runner as v1
from .seeded_xof import DEFAULT_INPUT


SCHEMA = "IBME/SRGG-BOUNDED-CLASSICAL-RUNNER/1"
MAX_REQUEST_BYTES = 256*1024*1024
MAX_TOTAL_BYTES = 8*1024**3
ProofPublic, RunAbort, IssueBlocked = v1.ProofPublic, v1.RunAbort, v1.IssueBlocked


def _int(value,name,low=0,high=MAX_TOTAL_BYTES):
    if type(value) is not int or not low<=value<=high:
        raise ValueError("bounded exact integer required: "+name)
    return value


@dataclass(frozen=True)
class Limits:
    identities: int = 8
    sign_queries: int = 8
    h2_entries: int = 128
    raw_query_bytes: int = 65536
    entropy_bytes: int = 4*1024**3
    attacker_coin_bytes: int = 1024*1024

    def __post_init__(self):
        for name in ("identities","sign_queries","h2_entries","raw_query_bytes"):
            _int(getattr(self,name),name,1,MAX_REQUEST_BYTES)
        _int(self.entropy_bytes,"global entropy budget",1,MAX_TOTAL_BYTES)
        _int(self.attacker_coin_bytes,"attacker tape budget",1,MAX_REQUEST_BYTES)


def resource_certificate(params,*,limits=None):
    """No draw. Exact conservative envelope for at most two full fresh runs."""
    if type(params) is not v1.ExecutionParams:
        raise TypeError("explicit ExecutionParams required")
    limits=Limits() if limits is None else limits
    if type(limits) is not Limits:
        raise TypeError("bounded runner Limits required")
    # The v1 resource function's entropy field is descriptive only; its sampler
    # upper bounds depend on the unchanged query caps and the frozen parameters.
    old_limits=v1.Limits(identities=limits.identities,sign_queries=limits.sign_queries,
        h2_entries=limits.h2_entries,raw_query_bytes=limits.raw_query_bytes,
        entropy_bytes=MAX_REQUEST_BYTES)
    old=v1.resource_certificate(params,limits=old_limits)
    c_bytes=old["target_c"]["random_bytes"]
    free_per_run=limits.h2_entries*c_bytes
    free_two=2*free_per_run
    nonfree_per_run=old["one_run_nonfree_sampler_raw_upper_bytes"]
    attacker_two=2*limits.attacker_coin_bytes
    bank_upper=2*nonfree_per_run+attacker_two
    total_upper=bank_upper+free_two
    bank_cap=max(0,limits.entropy_bytes-free_two)
    admitted=total_upper<=limits.entropy_bytes
    samplers={name:old[name] for name in
        ("public_u","public_e","target_z","target_c","h1_point","known_P_class","known_u_batch")}
    return {"schema":SCHEMA,"parameters":asdict(params),"limits":asdict(limits),
        "sampler_certificates":samplers,
        "one_run_sampler_raw_upper_bytes":old["one_run_sampler_raw_upper_bytes"],
        "two_run_sampler_raw_upper_bytes":old["two_run_sampler_raw_upper_bytes"],
        "one_run_nonfree_sampler_raw_upper_bytes":nonfree_per_run,
        "two_run_nonfree_sampler_raw_upper_bytes":2*nonfree_per_run,
        "one_run_attacker_coin_upper_bytes":limits.attacker_coin_bytes,
        "two_run_attacker_coin_upper_bytes":attacker_two,
        "one_run_free_h2_source_upper_bytes":free_per_run,
        "two_run_free_h2_source_upper_bytes":free_two,
        "two_run_nonfree_bank_upper_bytes":bank_upper,
        "two_run_all_source_upper_bytes":total_upper,
        "nonfree_bank_physical_cap_bytes":bank_cap,
        "all_source_global_cap_bytes":limits.entropy_bytes,
        "single_request_cap_bytes":MAX_REQUEST_BYTES,
        "admitted":admitted,"global_entropy_cap_abort_upper":0 if admitted else None,
        "global_entropy_cap_abort_upper_exact":"0" if admitted else None,
        "bank_allocated_lazily":True,"runs_covered":2,
        "attacker_coin_budget_included":True,"free_h2_source_budget_included":True,
        "attacker_own_computation_time_included":False,
        "bound_is_source_bytes_not_python_heap_size":True,
        "finite_sampler_and_hash_abort_terms_removed":False,
        "malformed_source_failure_probability_claimed":False,
        "requires_callback_use_only_public_oracles_and_attacker_rng":True,
        "actual_entropy_bytes":0,"draw_performed":False,
        "proof_public_has_production_seed_embedding":False,
        "whole_adaptive_security_reduction_proved":False,
        "security_claim":"none","backend_admitted":False,
        "parameters_are_formal":False,"nist_security_category":None}


class ReplayBank:
    """At most two registered runs; byte tapes grow on demand, never preallocate.

    Non-free sampler and attacker readers share fixed labeled tapes. Independent
    iid source bytes imply independent tapes. Bounds count bytes, not Python's
    object/tuple/list overhead or peak RAM.
    """
    def __init__(self,rng=None,*,cap=4*1024**3):
        self.cap=_int(cap,"nonfree bank cap",1,MAX_TOTAL_BYTES)
        self.rng=SecureRandom() if rng is None else rng
        if not callable(getattr(self.rng,"read",None)):
            raise TypeError("bank byte source required")
        self.tapes,self.used,self.blocked,self.runs={},0,False,0

    def register_run(self,upper_bytes):
        _int(upper_bytes,"one-run bank upper",1)
        if self.blocked:
            raise ValueError("blocked bank cannot start a run")
        if self.runs>=2:
            raise ValueError("bank already registered two runs")
        if self.used+upper_bytes>self.cap:
            raise ValueError("insufficient bank headroom before entropy")
        self.runs+=1

    def reader(self,label):
        hash(label)
        bank=self
        class Reader:
            position=0
            def read(self,size):
                _int(size,"single entropy request",0,MAX_REQUEST_BYTES)
                if bank.blocked:
                    raise RunAbort("nonfree replay bank is blocked")
                buffer=bank.tapes.setdefault(label,bytearray())
                end=self.position+size
                missing=max(0,end-len(buffer))
                if bank.used+missing>bank.cap:
                    bank.blocked=True
                    raise RunAbort("nonfree replay entropy cap exhausted")
                if missing:
                    try:
                        data=bank.rng.read(missing)
                        if type(data) is not bytes or len(data)!=missing:
                            raise RunAbort("invalid private replay entropy source")
                    except BaseException:
                        bank.blocked=True
                        raise
                    buffer.extend(data)
                    bank.used+=missing
                result=bytes(buffer[self.position:end])
                self.position=end
                return result
        return Reader()


class _CappedSource:
    """Forward byte source, with no retries or fallback after a source error."""
    def __init__(self,rng,cap,*,failure=None):
        self.cap=_int(cap,"forward source cap",0,MAX_TOTAL_BYTES)
        if not callable(getattr(rng,"read",None)):
            raise TypeError("forward byte source required")
        self.rng,self.used,self.blocked,self.failure=rng,0,False,failure

    def _failed(self,reason):
        self.blocked=True
        if self.failure is not None:
            self.failure(reason)

    def read(self,size):
        _int(size,"single forward request",0,MAX_REQUEST_BYTES)
        if self.blocked:
            raise RunAbort("forward entropy source is blocked")
        if self.used+size>self.cap:
            self._failed("bounded forward entropy cap exhausted")
            raise RunAbort("bounded forward entropy cap exhausted")
        if size==0:
            return b""
        try:
            data=self.rng.read(size)
            if type(data) is not bytes or len(data)!=size:
                raise RunAbort("invalid forward entropy source")
        except BaseException:
            self._failed("bounded forward entropy source failed")
            raise
        self.used+=size
        return data


class FreeReplies:
    """Fresh iid H2 c except the prescribed fork prefix; all source bytes capped."""
    def __init__(self,degree,max_entries,*,prefix=(),rng=None):
        _int(degree,"free H2 degree",2,512)
        _int(max_entries,"free H2 entry cap",1,MAX_REQUEST_BYTES)
        if type(prefix) not in (tuple,list) or len(prefix)>max_entries:
            raise ValueError("fork prefix exceeds free H2 entry cap")
        prefix=tuple(prefix)
        for value in prefix:
            if (type(value) is not tuple or len(value)!=degree
                    or any(type(x) is not int or x not in (0,1) for x in value)):
                raise ValueError("canonical full binary fork replies required")
        self.degree,self.max_entries,self.prefix,self.values=degree,max_entries,prefix,[]
        self.source=_CappedSource(SecureRandom() if rng is None else rng,
            max_entries*((degree+7)//8))

    def next(self,degree):
        if type(degree) is not int or degree!=self.degree:
            raise ValueError("free H2 degree differs")
        index=len(self.values)
        if index>=self.max_entries:
            raise RunAbort("free H2 reply cap exhausted")
        value=(self.prefix[index] if index<len(self.prefix) else
            v1.rs.sample_binary_challenge(degree,rng=self.source))
        self.values.append(value)
        return value,index


class Runner(v1.Runner):
    """Frozen algebra/oracle methods, with an explicit new bounded constructor.

    Does not call v1.__init__, replace frozen globals or pass subclasses through
    v1's exact-type validation. Each version validates its own resource objects.
    """
    def __init__(self,public,h_star,target_index,*,limits=None,coins=None,free=None):
        if type(public) is not ProofPublic:
            raise TypeError("frozen explicit ProofPublic required")
        limits=Limits() if limits is None else limits
        if type(limits) is not Limits:
            raise TypeError("bounded runner Limits required")
        target_index=_int(target_index,"target identity index",1,limits.identities)
        ring=v1.ExactRing(public.params)
        h_star=ring.vector(h_star,public.params.rank,public.params.modulus)
        certificate=resource_certificate(public.params,limits=limits)
        if not certificate["admitted"]:
            raise ValueError("two-run global entropy profile not admitted before entropy")
        bank_cap=certificate["nonfree_bank_physical_cap_bytes"]
        one_run_upper=(certificate["one_run_nonfree_sampler_raw_upper_bytes"]
            +limits.attacker_coin_bytes)
        if coins is not None:
            if type(coins) is not ReplayBank or coins.cap!=bank_cap:
                raise ValueError("new ReplayBank with exact admitted nonfree cap required")
            if coins.blocked or coins.runs>=2 or coins.used+one_run_upper>coins.cap:
                raise ValueError("nonfree bank lacks a fresh bounded run before entropy")
        if free is not None:
            if (type(free) is not FreeReplies or free.degree!=public.params.degree
                    or free.max_entries!=limits.h2_entries or free.values or free.source.used
                    or free.source.blocked):
                raise ValueError("fresh bounded FreeReplies for this profile required")
        self.public,self.p,self.ring=public,public.params,ring
        self.limits,self.target_index,self.h_star=limits,target_index,h_star
        self.resource_certificate=certificate
        self.coins=ReplayBank(cap=bank_cap) if coins is None else coins
        self.free=FreeReplies(self.p.degree,limits.h2_entries) if free is None else free
        self.coins.register_run(one_run_upper)
        self.identities,self.h2_table,self.extracted,self.returned={},{},set(),set()
        self.sign_calls,self.sign_attempts,self.failed,self.hashbad=0,0,None,False
        self.attacker_rng=_CappedSource(self.coins.reader(("attacker",)),
            limits.attacker_coin_bytes,failure=self._attacker_failed)
        self.rp=v1.rs.ReductionParameters(self.p.degree,self.p.rank,self.p.digits,self.p.p,
            self.p.master_squared,self.p.signature_squared)
        self.series,self.scalar=v1.sampler_profile("query-bounded-deep")

    def _attacker_failed(self,reason):
        self.failed=reason


def fork_extract(adversary,public,h_star,target_index,*,limits=None,coins=None,
                 first_free=None,first_free_rng=None,second_free_rng=None):
    """At most two real runs; no empirical probability claim is made."""
    if not callable(adversary):
        raise TypeError("deterministic bounded adversary callback required")
    limits=Limits() if limits is None else limits
    if type(limits) is not Limits or type(public) is not ProofPublic:
        raise TypeError("bounded Limits and explicit ProofPublic required")
    certificate=resource_certificate(public.params,limits=limits)
    if not certificate["admitted"]:
        raise ValueError("two-run global entropy profile not admitted before entropy")
    if first_free is not None and first_free_rng is not None:
        raise ValueError("choose a reply source or a fresh reply object")
    if first_free is not None and (type(first_free) is not FreeReplies or first_free.prefix):
        raise ValueError("first run must have fresh unprescribed free H2 replies")
    if coins is not None and (type(coins) is not ReplayBank or coins.used or coins.runs or coins.blocked):
        raise ValueError("fork requires an empty fresh nonfree ReplayBank")
    bank=(ReplayBank(cap=certificate["nonfree_bank_physical_cap_bytes"])
        if coins is None else coins)
    replies=(FreeReplies(public.params.degree,limits.h2_entries,rng=first_free_rng)
        if first_free is None else first_free)
    first=Runner(public,h_star,target_index,limits=limits,coins=bank,free=replies)

    def result(status,delta=None,runs=1,second=None,**fields):
        free_used=first.free.source.used+(0 if second is None else second.free.source.used)
        return {"status":status,"delta":delta,"runs":runs,
            "nonfree_physical_source_bytes":bank.used,
            "free_h2_source_bytes":free_used,
            "all_source_bytes":bank.used+free_used,
            "global_entropy_cap_abort_upper_exact":"0",**fields}

    try:
        outcome=first.finish(*adversary(first))
    except SamplingAbort:
        return result("first-run-aborted")
    if not outcome.won:
        return result("first-run-not-target-strong-success")
    if outcome.owner=="sign":
        logged=first.h2_table[(outcome.commitment,outcome.message)].returned
        delta=v1._difference(public,h_star,outcome.signature,logged[2]) if logged is not None else None
        return result("direct-owner-extracted" if delta is not None else "direct-owner-failed",delta)
    if outcome.owner!="free":
        return result("unseen-final-point")
    second_replies=FreeReplies(public.params.degree,limits.h2_entries,
        prefix=first.free.values[:outcome.free_index],rng=second_free_rng)
    second=Runner(public,h_star,target_index,limits=limits,coins=bank,free=second_replies)
    try:
        second_outcome=second.finish(*adversary(second))
    except SamplingAbort:
        return result("second-run-aborted",runs=2,second=second)
    same=(second_outcome.won and second_outcome.owner=="free"
        and second_outcome.free_index==outcome.free_index
        and second_outcome.commitment==outcome.commitment
        and second_outcome.message==outcome.message
        and second_outcome.signature.challenge!=outcome.signature.challenge)
    delta=v1._difference(public,h_star,outcome.signature,second_outcome.signature) if same else None
    return result("fork-extracted" if delta is not None else "fork-failed",delta,2,second,
        first_free_index=outcome.free_index,
        first_replies=tuple(first.free.values),second_replies=tuple(second.free.values),
        attacker_read_bytes_first=first.attacker_rng.used,
        attacker_read_bytes_second=second.attacker_rng.used)


def build_report(input_path=DEFAULT_INPUT,*,limits=None):
    """Frozen n512 parameters; source/input hashes and zero-entropy accounting."""
    from sage.version import version as sage_version
    path=Path(input_path)
    payload=path.read_bytes()
    record=json.loads(payload)
    if record.get("schema")!="IBME/SRGG-INTEGRATED-BRIDGE/1":
        raise ValueError("known integrated bridge input required")
    profiles=[p for p in record["profiles"] if p["profile"]=="query-bounded-deep"]
    if len(profiles)!=1:
        raise ValueError("exactly one query-bounded-deep profile required")
    report=resource_certificate(v1.ExecutionParams(**profiles[0]["parameters"]),limits=limits)
    project=Path(__file__).resolve().parents[4]
    names=("experiments/research/candidates/srgg/bounded_classical_runner.py",
        "experiments/research/candidates/srgg/classical_runner.py",
        "experiments/research/candidates/srgg/conditional_xof.py",
        "experiments/research/candidates/srgg/reduction_samplers.py",
        "experiments/research/candidates/srgg/structured_execution.py",
        "experiments/research/candidates/srgg/structured_samplef.py",
        "experiments/research/candidates/srgg/structured_geometry.py",
        "experiments/research/candidates/srgg/aggregate_budget.py",
        "experiments/research/candidates/srgg/wide_scalar.py")
    report.update({"input_path":path.as_posix(),"input_sha256":sha256(payload).hexdigest(),
        "source_sha256":{name:sha256((project/name).read_bytes()).hexdigest() for name in names},
        "environment":{"python":platform.python_version(),"sage":sage_version,
            "platform":platform.platform(),"machine":platform.machine()},
        "scope":"new bounded explicit-proof-public Run/fork; zero-entropy n512 report only",
        "external_uniform_target_sampling_in_run_cost":False,
        "production_backend_modified":False,"production_hash_or_QRO_programmed":False,
        "actual_adversary_executed_by_report":False,"all_path_time_bound_proved":False})
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input",type=Path,default=DEFAULT_INPUT)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    report=build_report(args.input)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open("x",encoding="utf-8",newline="\n") as handle:
        json.dump(report,handle,ensure_ascii=False,indent=2)
        handle.write("\n")


if __name__=="__main__":
    main()
