"""Executable root-free classical SRGG experiment and two-run fork prototype.

Uses actual bounded samplers, explicit proof public matrices and local ideal
H1/H2 tables. No production hash is patched. No persistent service, production
seed embedding, complete reduction theorem or quantum oracle is implemented.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path
import platform

from ibme.core.randomness import SecureRandom
from ibme.core.errors import EncodingError
from ibme.core.types import validate_bytes, validate_identity
from experiments.research.gaussian_reference import SamplingAbort
from . import reduction_samplers as rs
from .conditional_xof import ConditionalPoint, conditional_certificate
from .structured_execution import ExactRing, ExecutionParams, Signature, sampler_profile
from .structured_geometry import signature_operator
from .structured_samplef import StructuredSampleF
from .wide_scalar import WideScalarGaussian
from .aggregate_budget import batch_certificate, sample_batch
from .seeded_xof import DEFAULT_INPUT


SCHEMA = "IBME/SRGG-CLASSICAL-RUNNER/1"


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _int(value, name, low=0, high=2**48):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("bounded exact integer required: "+name)
    return value


def _norm(vector):
    return sum(x*x for poly in vector for x in poly)


def _reshape(values, n):
    return tuple(tuple(values[i:i+n]) for i in range(0,len(values),n))


def _pack(challenge, unused):
    result = bytearray(unused)
    for j, value in enumerate(challenge):
        result[j//8] = (result[j//8] & ~(1 << (j % 8))) | (value << (j % 8))
    return bytes(result)


@dataclass(frozen=True)
class Limits:
    identities: int = 8
    sign_queries: int = 8
    h2_entries: int = 128
    raw_query_bytes: int = 65536
    entropy_bytes: int = 256*1024*1024

    def __post_init__(self):
        for name in ("identities", "sign_queries", "h2_entries", "raw_query_bytes", "entropy_bytes"):
            _int(getattr(self,name), name, 1, 256*1024*1024)


@dataclass(frozen=True)
class ProofPublic:
    params: ExecutionParams
    a_hat: tuple
    b: tuple

    def __post_init__(self):
        if type(self.params) is not ExecutionParams:
            raise TypeError("explicit ExecutionParams required")
        p, r = self.params, ExactRing(self.params)
        object.__setattr__(self,"a_hat",r.matrix(self.a_hat,p.rank,p.rank,p.modulus))
        object.__setattr__(self,"b",r.matrix(self.b,p.rank,p.rank*p.digits,p.modulus))

    def to_bytes(self):
        return _canonical({"schema":SCHEMA,"kind":"explicit-proof-public", "params":asdict(self.params),
            "a_hat":self.a_hat,"b":self.b})

    @property
    def context(self):
        return sha256(self.to_bytes()).digest()


class RunAbort(SamplingAbort):
    """The explicit local experiment has stopped, without reselection."""


class IssueBlocked(SamplingAbort):
    """This identity has a fixed failed/pending issuance state."""


class ReplayBank:
    """Private lazily fixed byte tapes. Fresh readers replay from position zero.

    With an iid source, separate labels have independent tapes. The global
    physical cap is enforced but no probability bound for its abort is claimed.
    """
    def __init__(self, rng=None, *, cap=256*1024*1024):
        self.cap = _int(cap,"replay bank cap",1,256*1024*1024)
        self.rng = SecureRandom() if rng is None else rng
        if not callable(getattr(self.rng,"read",None)):
            raise TypeError("byte source required")
        self.tapes, self.used, self.blocked = {}, 0, False

    def reader(self, label):
        bank = self
        class Reader:
            position = 0
            def read(self, size):
                _int(size,"coin request",0,bank.cap)
                if bank.blocked:
                    raise RunAbort("replay entropy bank is blocked")
                buffer = bank.tapes.setdefault(label,bytearray())
                end = self.position+size
                missing = max(0,end-len(buffer))
                if bank.used+missing > bank.cap:
                    bank.blocked = True
                    raise RunAbort("global replay entropy cap exhausted")
                if missing:
                    try:
                        data = bank.rng.read(missing)
                        if type(data) is not bytes or len(data) != missing:
                            raise RunAbort("invalid private replay entropy source")
                    except BaseException:
                        bank.blocked = True
                        raise
                    buffer.extend(data)
                    bank.used += missing
                result = bytes(buffer[self.position:end])
                self.position = end
                return result
        return Reader()


class FreeReplies:
    """Only free H2 challenge replies are refreshed by a fork."""
    def __init__(self, *, prefix=(), rng=None):
        self.prefix, self.values = tuple(prefix), []
        self.rng = SecureRandom() if rng is None else rng
        if not callable(getattr(self.rng,"read",None)):
            raise TypeError("free challenge byte source required")

    def next(self, degree):
        index = len(self.values)
        value = self.prefix[index] if index < len(self.prefix) else rs.sample_binary_challenge(degree,rng=self.rng)
        if type(value) is not tuple or len(value) != degree or any(type(x) is not int or x not in (0,1) for x in value):
            raise RunAbort("invalid free H2 reply")
        self.values.append(value)
        return value, index


@dataclass
class IdentityState:
    index: int
    target: bool
    status: str = "pending"
    h: tuple | None = None
    key: tuple | None = field(default=None,repr=False)
    point: ConditionalPoint | None = field(default=None,repr=False)


@dataclass
class H2State:
    challenge: tuple
    owner: str
    free_index: int | None
    buffer: bytearray = field(repr=False)
    suffix: object = field(repr=False)
    returned: tuple | None = field(default=None,repr=False)


@dataclass(frozen=True)
class Finish:
    won: bool
    identity: bytes
    message: bytes
    signature: Signature
    commitment: tuple | None
    owner: str
    free_index: int | None = None


class Runner:
    """Local Run(A,h_star,J), with actual public samples and no target key."""
    def __init__(self, public, h_star, target_index, *, limits=None, coins=None, free=None):
        if type(public) is not ProofPublic:
            raise TypeError("ProofPublic required")
        self.public, self.p, self.ring = public, public.params, ExactRing(public.params)
        self.limits = Limits() if limits is None else limits
        if type(self.limits) is not Limits:
            raise TypeError("validated Limits required")
        self.target_index = _int(target_index,"target identity index",1,self.limits.identities)
        self.h_star = self.ring.vector(h_star,self.p.rank,self.p.modulus)
        self.coins = ReplayBank(cap=self.limits.entropy_bytes) if coins is None else coins
        self.free = FreeReplies() if free is None else free
        if type(self.coins) is not ReplayBank or self.coins.cap>self.limits.entropy_bytes:
            raise ValueError("validated replay bank within physical cap required")
        if type(self.free) is not FreeReplies:
            raise TypeError("FreeReplies required")
        self.attacker_rng = self.coins.reader(("attacker",))
        self.identities, self.h2_table, self.extracted, self.returned = {}, {}, set(), set()
        self.sign_calls, self.sign_attempts, self.failed, self.hashbad = 0, 0, None, False
        self.rp = rs.ReductionParameters(self.p.degree,self.p.rank,self.p.digits,self.p.p,
            self.p.master_squared,self.p.signature_squared)
        self.series, self.scalar = sampler_profile("query-bounded-deep")

    def _active(self):
        if self.failed is not None:
            raise RunAbort("experiment already stopped: "+self.failed)

    def _stop(self, reason):
        self.failed = reason
        raise RunAbort(reason)

    def _message(self, value):
        value = validate_bytes(value,name="message")
        if len(value)>65536:
            raise ValueError("message exceeds 65536 bytes")
        return value

    def _touch(self, identity):
        self._active()
        identity = validate_identity(identity,max_bytes=4096)
        if identity in self.identities:
            state = self.identities[identity]
            if state.status == "pending":
                self._stop("pending identity cannot be reentered")
            return identity,state
        if len(self.identities)>=self.limits.identities:
            self._stop("identity query cap exhausted")
        index = len(self.identities)+1
        state = IdentityState(index,index==self.target_index)
        self.identities[identity] = state
        try:
            if state.target:
                state.h, state.status = self.h_star,"target-unissued"
            else:
                u = _reshape(rs.sample_public_u(self.rp,rng=self.coins.reader(("id-u",index))),self.p.degree)
                e = _reshape(rs.sample_uniform_e(self.rp,rng=self.coins.reader(("id-e",index))),self.p.degree)
                q = self.p.modulus
                head = tuple(tuple((a+b+q//2)%q-q//2 for a,b in zip(x,y))
                    for x,y in zip(u[:self.p.rank],e))
                y = head+u[self.p.rank:]
                state.h = self.ring.matvec(self.ring.public_a(self.public),y,q)
                state.key = y if _norm(u)<=self.p.raw_norm_cap and _norm(y)<=self.p.user_norm_cap else None
                state.status = "issued" if state.key is not None else "failed"
            state.point = ConditionalPoint(self.p.modulus,
                tuple(x for poly in state.h for x in poly),
                rng=self.coins.reader(("h1-raw",index)))
            return identity,state
        except BaseException:
            state.status = "failed"
            self.failed = "identity generation failed"
            raise

    def raw_h1(self, identity, offset, size):
        # Reject malformed reads before first-touch sampling.
        self._active()
        _int(offset,"H1 offset",0,self.p.rank*self.p.degree*4096)
        _int(size,"H1 read",0,self.p.rank*self.p.degree*4096)
        if offset+size>self.p.rank*self.p.degree*4096:
            raise ValueError("H1 raw byte cap exceeded")
        identity = validate_identity(identity,max_bytes=4096)
        if size == 0:
            return b""
        _,state = self._touch(identity)
        try:
            result = state.point.read_at(offset,size)
            if not state.point.trajectory.success:
                self.hashbad = True
            return result
        except BaseException:
            self.failed = "H1 raw source failure"
            raise

    def h1(self, identity):
        identity,state = self._touch(identity)
        self.raw_h1(identity,0,1)
        if not state.point.trajectory.success:
            self._stop("retained H1 trial-limit failure")
        return state.h

    def extract(self, identity):
        identity = validate_identity(identity,max_bytes=4096)
        self.h1(identity)
        self.extracted.add(identity)
        state = self.identities[identity]
        if state.target:
            self._stop("explicit target extraction")
        if state.status != "issued":
            raise IssueBlocked("fixed identity issuance failed; no reselection")
        return state.key

    def _h2_key(self, commitment, message):
        commitment = self.ring.vector(commitment,self.p.rank,2*self.p.modulus)
        return commitment,self._message(message)

    def _entry(self, commitment, message, *, programmed=None):
        self._active()
        key = self._h2_key(commitment,message)
        if key in self.h2_table:
            if programmed is not None:
                self._stop("target signing collided with existing H2 owner")
            return key,self.h2_table[key]
        if len(self.h2_table)>=self.limits.h2_entries:
            self._stop("H2 entry cap exhausted")
        ordinal = len(self.h2_table)
        try:
            if programmed is None:
                challenge,free_index = self.free.next(self.p.degree)
                owner = "free"
            else:
                challenge,free_index,owner = programmed,None,"sign"
            source = self.coins.reader(("h2-raw",ordinal))
            prefix = _pack(challenge,source.read((self.p.degree+7)//8))
            entry = H2State(challenge,owner,free_index,bytearray(prefix),source)
            self.h2_table[key] = entry
            return key,entry
        except BaseException:
            self.failed = "H2 entry construction failed"
            raise

    def h2(self, commitment, message):
        return self._entry(commitment,message)[1].challenge

    def raw_h2(self, commitment, message, offset, size):
        self._active()
        _int(offset,"H2 offset",0,self.limits.raw_query_bytes)
        _int(size,"H2 read",0,self.limits.raw_query_bytes)
        if offset+size>self.limits.raw_query_bytes:
            raise ValueError("H2 raw byte cap exceeded")
        key = self._h2_key(commitment,message)
        if size == 0:
            return b""
        _,entry = self._entry(*key)
        try:
            end = offset+size
            if end>len(entry.buffer):
                entry.buffer.extend(entry.suffix.read(end-len(entry.buffer)))
            return bytes(entry.buffer[offset:end])
        except BaseException:
            self.failed = "H2 raw source failure"
            raise

    def _known_sign(self, state, message, serial):
        p = self.p
        plan = StructuredSampleF(signature_operator(degree=p.degree,rank=p.rank,digits=p.digits,
            user_vector=state.key,first_squared=p.signature_squared,second_squared=p.signature_squared,
            r_squared=p.r_squared,noise_factor=2),bound_kind="public-norm-cap",
            witness_norm_squared_cap=p.user_norm_cap,options=self.series,scalar_options=self.scalar)
        scalar = WideScalarGaussian(p.r_squared,p.r_squared,options=self.scalar)
        for attempt in range(p.sign_max_attempts):
            self.sign_attempts += 1
            perturbation = _reshape(plan.sample(rng=self.coins.reader(("sign-p",serial,attempt))),p.degree)
            w = self.ring.matvec(self.ring.signing_matrix(self.public,state.h),perturbation,2*p.modulus)
            c = self.h2(w,message)
            centers = tuple(Fraction(-x,2) for x in self.ring.multiply(self.ring.zeta(True),c))
            u = sample_batch(scalar,p.r_squared,centers,
                rng=self.coins.reader(("sign-u",serial,attempt)),error_bits=self.series.aggregate_abort_bits)
            z = self.ring.response(state.key,perturbation,u,c)
            if _norm(z)<=p.signature_norm_cap:
                return Signature(self.public.context,z,c)
        self._stop("known-key signature norm retry cap exhausted")

    def sign(self, identity, message):
        self._active()
        message = self._message(message)
        if self.sign_calls>=self.limits.sign_queries:
            self._stop("Sign query cap exhausted")
        identity = validate_identity(identity,max_bytes=4096)
        self.h1(identity)
        state = self.identities[identity]
        self.sign_calls += 1
        serial = self.sign_calls
        if not state.target and state.status != "issued":
            raise IssueBlocked("fixed identity issuance failed; no reselection")
        try:
            if state.target:
                self.sign_attempts += 1
                c = rs.sample_binary_challenge(self.p.degree,rng=self.coins.reader(("sim-c",serial)))
                z = _reshape(rs.sample_simulator_z(self.rp,rng=self.coins.reader(("sim-z",serial))),self.p.degree)
                if _norm(z)>self.p.signature_norm_cap:
                    self._stop("target simulation norm failure")
                w = self.ring.recover(self.public,state.h,z,c)
                _,entry = self._entry(w,message,programmed=c)
                signature = Signature(self.public.context,z,c)
                entry.returned = (identity,message,signature)
            else:
                signature = self._known_sign(state,message,serial)
            self.returned.add((identity,message,signature.to_bytes()))
            return signature
        except BaseException:
            if self.failed is None:
                self.failed = "Sign sampling/infrastructure failure"
            raise

    def _valid_signature(self, signature):
        if (type(signature) is not Signature or type(signature.context) is not bytes
                or signature.context != self.public.context):
            return False
        try:
            self.ring.vector(signature.response,self.p.columns+1)
            self.ring.poly(signature.challenge)
            return (all(type(x) is int and x in (0,1) for x in signature.challenge)
                and _norm(signature.response)<=self.p.signature_norm_cap)
        except (ValueError,TypeError,AttributeError,OverflowError):
            return False

    def verify(self, identity, message, signature):
        self._active()
        if not self._valid_signature(signature):
            return False
        try:
            identity = validate_identity(identity,max_bytes=4096)
            message = self._message(message)
        except (ValueError,TypeError,EncodingError):
            return False
        h = self.h1(identity)
        w = self.ring.recover(self.public,h,signature.response,signature.challenge)
        return self.h2(w,message) == signature.challenge

    def finish(self, identity, message, signature):
        self._active()
        identity = validate_identity(identity,max_bytes=4096)
        message = self._message(message)
        self.h1(identity)
        if not self._valid_signature(signature):
            return Finish(False,identity,message,signature,None,"invalid")
        h = self.identities[identity].h
        w = self.ring.recover(self.public,h,signature.response,signature.challenge)
        entry = self.h2_table.get((w,message))
        owner,index = ("unseen",None) if entry is None else (entry.owner,entry.free_index)
        won = (self.verify(identity,message,signature) and self.identities[identity].target
            and identity not in self.extracted
            and (identity,message,signature.to_bytes()) not in self.returned and not self.hashbad)
        return Finish(won,identity,message,signature,w,owner,index)


def _difference(public, target, first, second):
    r,p = ExactRing(public.params),public.params
    delta = tuple(r.add(x,r.scale(y,-1)) for x,y in zip(first.response,second.response))
    if not any(x for poly in delta for x in poly) or _norm(delta)>4*p.signature_norm_cap:
        return None
    matrix = tuple(row+(r.scale(h,-1,p.modulus),) for row,h in zip(r.public_a(public),target))
    if any(x for poly in r.matvec(matrix,delta,p.modulus) for x in poly):
        return None
    return delta


def fork_extract(adversary, public, h_star, target_index, *, limits=None, coins=None,
                 first_free=None, second_free_rng=None):
    """Actually execute fresh-state runs; no theorem or success rate is inferred.

    adversary(runner) returns (identity,message,signature) and must be
    deterministic given runner interfaces plus runner.attacker_rng.
    """
    if not callable(adversary):
        raise TypeError("deterministic adversary callback required")
    limits = Limits() if limits is None else limits
    if type(limits) is not Limits:
        raise TypeError("validated Limits required")
    coins = ReplayBank(cap=limits.entropy_bytes) if coins is None else coins
    first = Runner(public,h_star,target_index,limits=limits,coins=coins,free=first_free)
    try:
        forgery = adversary(first)
        outcome = first.finish(*forgery)
    except SamplingAbort:
        return {"status":"first-run-aborted","delta":None,"runs":1}
    if not outcome.won:
        return {"status":"first-run-not-target-strong-success","delta":None,"runs":1}
    if outcome.owner == "sign":
        logged = first.h2_table[(outcome.commitment,outcome.message)].returned
        delta = _difference(public,h_star,outcome.signature,logged[2]) if logged is not None else None
        return {"status":"direct-owner-extracted" if delta is not None else "direct-owner-failed",
            "delta":delta,"runs":1}
    if outcome.owner != "free":
        return {"status":"unseen-final-point","delta":None,"runs":1}
    replies = FreeReplies(prefix=first.free.values[:outcome.free_index],rng=second_free_rng)
    second = Runner(public,h_star,target_index,limits=limits,coins=coins,free=replies)
    try:
        second_outcome = second.finish(*adversary(second))
    except SamplingAbort:
        return {"status":"second-run-aborted","delta":None,"runs":2}
    same = (second_outcome.won and second_outcome.owner == "free"
        and second_outcome.free_index == outcome.free_index
        and second_outcome.commitment == outcome.commitment
        and second_outcome.message == outcome.message
        and outcome.signature.challenge != second_outcome.signature.challenge)
    delta = _difference(public,h_star,outcome.signature,second_outcome.signature) if same else None
    return {"status":"fork-extracted" if delta is not None else "fork-failed",
        "delta":delta,"runs":2,"first_free_index":outcome.free_index,
        "first_replies":tuple(first.free.values),"second_replies":tuple(second.free.values)}


def resource_certificate(params, *, limits=None):
    """Zero-entropy arithmetic only; does not admit the full reduction budget."""
    if type(params) is not ExecutionParams:
        raise TypeError("ExecutionParams required")
    limits = Limits() if limits is None else limits
    if type(limits) is not Limits:
        raise TypeError("validated Limits required")
    rp = rs.ReductionParameters(params.degree,params.rank,params.digits,params.p,
        params.master_squared,params.signature_squared)
    u = rs.gaussian_product_certificate(rp.master_squared,rp.N)
    e = rs.uniform_vector_certificate(rp.p,rp.H)
    z = rs.gaussian_product_certificate(rp.signature_squared,rp.D)
    c = rs.binary_vector_certificate(params.degree)
    h1 = conditional_certificate(q=params.modulus,count=rp.H)
    series,scalar_options = sampler_profile("query-bounded-deep")
    zero = ((0,)*params.degree,)*params.columns
    known = StructuredSampleF(signature_operator(degree=params.degree,rank=params.rank,digits=params.digits,
        user_vector=zero,first_squared=params.signature_squared,second_squared=params.signature_squared,
        r_squared=params.r_squared,noise_factor=2),bound_kind="public-norm-cap",
        witness_norm_squared_cap=params.user_norm_cap,options=series,scalar_options=scalar_options).public_certificate()
    scalar = WideScalarGaussian(params.r_squared,params.r_squared,options=scalar_options)
    ubatch = batch_certificate(scalar,params.degree,error_bits=series.aggregate_abort_bits)
    per_identity = u["batch"]["selected_cap_bytes"]+e["all_path_byte_cap"]+h1["point_random_bytes_all_paths"]
    per_sign = max(z["batch"]["selected_cap_bytes"]+c["random_bytes"],
        params.sign_max_attempts*(known["whole_entropy_cap_bytes"]+ubatch["selected_cap_bytes"]))
    h2_cap = max(limits.raw_query_bytes,c["random_bytes"])+c["random_bytes"]
    per_run = limits.identities*per_identity+limits.sign_queries*per_sign+limits.h2_entries*h2_cap
    per_run_nonfree = per_run-limits.h2_entries*c["random_bytes"]
    return {"schema":SCHEMA,"parameters":asdict(params),"limits":asdict(limits),
        "public_u":u,"public_e":e,"target_z":z,"target_c":c,"h1_point":h1,
        "known_P_class":known,"known_u_batch":ubatch,
        "one_run_sampler_raw_upper_bytes":per_run,
        "two_run_sampler_raw_upper_bytes":2*per_run,
        "one_run_nonfree_sampler_raw_upper_bytes":per_run_nonfree,
        "two_run_nonfree_sampler_raw_upper_bytes":2*per_run_nonfree,
        "two_run_nonfree_upper_covered_by_bank_cap":2*per_run_nonfree<=limits.entropy_bytes,
        "physical_replay_bank_cap_bytes":limits.entropy_bytes,
        "global_entropy_cap_abort_upper":None,
        "attacker_own_time_and_coin_budget_included":False,
        "actual_entropy_bytes":0,"draw_performed":False,
        "proof_public_has_production_seed_embedding":False,
        "whole_adaptive_security_reduction_proved":False,
        "security_claim":"none","backend_admitted":False,
        "parameters_are_formal":False,"nist_security_category":None}


def sample_uniform_target(params, *, rng=None):
    """External uniform h input, conditional on this bounded sampler succeeding.

    Uses an independent source chosen by the caller; abort is retained and no
    target key, master key, public-image sampling or whole-vector retry exists.
    This helper is outside Run/fork's fixed-input resource accounting.
    """
    if type(params) is not ExecutionParams:
        raise TypeError("ExecutionParams required")
    rp = rs.ReductionParameters(params.degree,params.rank,params.digits,params.modulus,
        params.master_squared,params.signature_squared)
    return _reshape(rs.sample_uniform_e(rp,rng=rng,max_trials=128),params.degree)


def build_report(input_path=DEFAULT_INPUT, *, limits=None):
    """Read the frozen n512 input and certify costs without creating any RNG."""
    from sage.version import version as sage_version
    path = Path(input_path)
    payload = path.read_bytes()
    record = json.loads(payload)
    if record.get("schema") != "IBME/SRGG-INTEGRATED-BRIDGE/1":
        raise ValueError("known integrated bridge schema required")
    matches = [item for item in record["profiles"] if item["profile"] == "query-bounded-deep"]
    if len(matches) != 1:
        raise ValueError("exactly one frozen query-bounded-deep profile required")
    params = ExecutionParams(**matches[0]["parameters"])
    result = resource_certificate(params,limits=limits)
    project = Path(__file__).resolve().parents[4]
    names = ("experiments/research/candidates/srgg/classical_runner.py",
        "experiments/research/candidates/srgg/conditional_xof.py",
        "experiments/research/candidates/srgg/reduction_samplers.py",
        "experiments/research/candidates/srgg/structured_execution.py",
        "experiments/research/candidates/srgg/structured_samplef.py",
        "experiments/research/candidates/srgg/structured_geometry.py",
        "experiments/research/candidates/srgg/aggregate_budget.py",
        "experiments/research/candidates/srgg/wide_scalar.py")
    result.update({"input_path":path.as_posix(),"input_sha256":sha256(payload).hexdigest(),
        "source_sha256":{name:sha256((project/name).read_bytes()).hexdigest() for name in names},
        "environment":{"python":platform.python_version(),"sage":sage_version,
            "platform":platform.platform(),"machine":platform.machine(),"processor":platform.processor()},
        "scope":"bounded local explicit-public classical Run/fork executable; this report draws nothing",
        "external_uniform_target":rs.uniform_vector_certificate(params.modulus,
            params.rank*params.degree,max_trials=128),
        "external_uniform_target_sampling_in_run_cost":False,
        "private_trapdoor_input":False,"production_backend_modified":False,
        "production_hash_or_QRO_programmed":False,
        "actual_adversary_executed_by_report":False,
        "all_path_time_bound_proved":False})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input",type=Path,default=DEFAULT_INPUT)
    parser.add_argument("--output",type=Path,required=True)
    args = parser.parse_args()
    report = build_report(args.input)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open("x",encoding="utf-8",newline="\n") as handle:
        json.dump(report,handle,ensure_ascii=False,indent=2)
        handle.write("\n")


if __name__ == "__main__":
    main()
