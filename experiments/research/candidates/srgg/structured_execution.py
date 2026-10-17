"""Independent bounded SRGG four-algorithm research execution, using Sage.

No legacy Params/Config admission is bypassed or changed. This separate
execution namespace uses joint StructuredSampleF, exact ZZ ring arithmetic,
and the genuine randomized gadget recurrence. Private snapshots stay in
memory in audit(); its JSON report contains no keys, samples or signatures.
This is not a public backend, a persistent issuer, or formal parameters.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
from fractions import Fraction
from hashlib import sha256, shake_256
import json
from math import gcd
from pathlib import Path
import platform
from time import perf_counter

from sage.all import PolynomialRing, ZZ
from sage.version import version as sage_version

from ibme.core.encoding import encode_bytes
from ibme.core.randomness import SecureRandom
from experiments.research.gaussian_reference import SamplingAbort
from .aggregate_budget import AggregateByteSource, MAX_BYTES, batch_certificate
from .fiber_normalizers import normalizer_certificate
from .formal_candidates import Candidate, conditional_candidate
from .structured_geometry import master_operator, signature_operator
from .structured_samplef import SeriesOptions, StructuredSampleF
from .wide_scalar import WideScalarGaussian, WideScalarOptions
from ..wang_pw.hashing import XOFStream, uniform_values


SCHEMA = "IBME/SRGG-STRUCTURED-EXECUTION/1"
DOMAIN = b"IBME-SRGG-independent-structured-execution-v1"
MAX_SNAPSHOT = 16*1024*1024


def _bound(value, name, low=1, high=2**96):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("bounded exact integer required: "+name)
    return value


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _frame(*parts):
    return b"".join(encode_bytes(value) for value in parts)


def _bytes(value, name, minimum=0, maximum=4096):
    if type(value) is not bytes or not minimum <= len(value) <= maximum:
        raise ValueError("bounded bytes required: "+name)
    return value


def _parse(data, fields):
    _bytes(data, "snapshot", 2, MAX_SNAPSHOT)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate snapshot field")
            result[key] = value
        return result
    try:
        result = json.loads(data, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("malformed snapshot") from exc
    if type(result) is not dict or set(result) != set(fields) or _canonical(result) != data:
        raise ValueError("noncanonical snapshot fields")
    return result


@dataclass(frozen=True)
class ExecutionParams:
    """Strict public study input; separate from legacy Params and Config."""
    degree: int
    rank: int
    p: int
    base: int
    digits: int
    r_squared: int
    master_squared: int
    signature_squared: int
    raw_norm_cap: int
    user_norm_cap: int
    signature_norm_cap: int
    sign_max_attempts: int = 16

    def __post_init__(self):
        _bound(self.degree, "degree", 2, 512)
        if self.degree & (self.degree-1):
            raise ValueError("power-of-two degree required")
        for name, high in (("rank",4),("p",2**16-1),("base",63),("digits",8),
                           ("r_squared",4096),("sign_max_attempts",16)):
            _bound(getattr(self,name), name, high=high)
        if self.p < 3 or self.base < 3 or self.p%2 == 0 or self.base%2 == 0 or gcd(self.p,self.base) != 1:
            raise ValueError("odd coprime p/base at least three required")
        for name in ("master_squared","signature_squared","raw_norm_cap","user_norm_cap","signature_norm_cap"):
            _bound(getattr(self,name), name)
        if self.columns*self.degree > 32768 or self.modulus.bit_length() > 128:
            raise ValueError("execution shape/modulus resource cap exceeded")
        correction = 2*self.raw_norm_cap+2*self.rank*self.degree*(self.p-1)**2
        if self.user_norm_cap < correction:
            raise ValueError("user cap must cover raw cap and HNF correction")
        if self.modulus**2 <= 4*self.signature_norm_cap:
            raise ValueError("conditional Q>2gamma gate does not pass")

    @property
    def columns(self): return (2+self.digits)*self.rank

    @property
    def modulus(self): return self.p*self.base**self.digits

    @classmethod
    def from_candidate(cls, value):
        if not isinstance(value,Candidate) or value.master_first_squared != value.master_second_squared or value.signature_first_squared != value.signature_second_squared:
            raise ValueError("isotropic explicit Candidate required")
        return cls(value.degree,value.rank,value.p,value.base,value.digits,value.r_squared,
                   value.master_first_squared,value.signature_first_squared,value.raw_norm_squared_cap,
                   value.user_norm_squared_cap,value.signature_norm_squared_cap,value.sign_max_attempts)


class ExactRing:
    """Canonical fixed-degree tuples; Sage ZZ multiplication, no float FFT."""
    def __init__(self,params):
        if not isinstance(params,ExecutionParams):
            raise ValueError("ExecutionParams required")
        self.params,self.n = params,params.degree
        self.ring = PolynomialRing(ZZ,"x")
        self.modulus = self.ring.gen()**self.n+1
        self.products = 0

    def poly(self,value,modulus=None):
        if not isinstance(value,(tuple,list)) or len(value) != self.n:
            raise ValueError("fixed-degree polynomial required")
        if any(type(x) is not int or abs(x).bit_length() > 256 for x in value):
            raise ValueError("bounded integer coefficient required")
        if modulus is not None and any(not 0 <= x < modulus for x in value):
            raise ValueError("canonical public coefficient required")
        return tuple(value)

    def vector(self,value,count,modulus=None):
        if not isinstance(value,(tuple,list)) or len(value) != count:
            raise ValueError("module vector dimension mismatch")
        return tuple(self.poly(x,modulus) for x in value)

    def matrix(self,value,rows,columns,modulus=None):
        if not isinstance(value,(tuple,list)) or len(value) != rows:
            raise ValueError("module matrix dimension mismatch")
        return tuple(self.vector(row,columns,modulus) for row in value)

    def constant(self,value): return (value,)+(0,)*(self.n-1)

    def add(self,x,y,modulus=None):
        x,y = self.poly(x),self.poly(y)
        result = tuple(a+b for a,b in zip(x,y))
        return result if modulus is None else tuple(z%modulus for z in result)

    def scale(self,x,value,modulus=None):
        _bound(value,"scale",-2**128,2**128)
        result = tuple(value*y for y in self.poly(x))
        return result if modulus is None else tuple(z%modulus for z in result)

    def multiply(self,x,y,modulus=None):
        x,y = self.poly(x),self.poly(y)
        result = (self.ring(x)*self.ring(y))%self.modulus
        self.products += 1
        values = tuple(int(result[i]) for i in range(self.n))
        return values if modulus is None else tuple(z%modulus for z in values)

    def identity(self,size):
        return tuple(tuple(self.constant(int(i==j)) for j in range(size)) for i in range(size))

    def matvec(self,matrix,values,modulus=None):
        if not matrix or not values:
            raise ValueError("nonempty module product required")
        values = self.vector(values,len(values))
        matrix = self.matrix(matrix,len(matrix),len(values))
        out = []
        for row in matrix:
            total = self.constant(0)
            for entry,value in zip(row,values):
                total = self.add(total,self.multiply(entry,value,modulus),modulus)
            out.append(total)
        return tuple(out)

    def gadget(self):
        p = self.params
        return tuple(tuple(self.constant(p.p*p.base**(j%p.digits) if j//p.digits==i else 0)
                           for j in range(p.rank*p.digits)) for i in range(p.rank))

    def build_public(self,a_hat,witness):
        p,q = self.params,self.params.modulus
        a_hat = self.matrix(a_hat,p.rank,p.rank,q)
        witness = self.matrix(witness,2*p.rank,p.rank*p.digits)
        if any(x not in (-1,0,1) for row in witness for poly in row for x in poly):
            raise ValueError("CBD1 witness required")
        left = tuple(x+y for x,y in zip(self.identity(p.rank),a_hat))
        columns = tuple(self.matvec(left,tuple(row[j] for row in witness),q) for j in range(p.rank*p.digits))
        b = tuple(tuple(self.add(g,self.scale(columns[j][i],-1),q)
                         for j,g in enumerate(row)) for i,row in enumerate(self.gadget()))
        return b

    def public_a(self,public):
        return tuple(x+y+z for x,y,z in zip(self.identity(self.params.rank),public.a_hat,public.b))

    def trapdoor_relation(self,public,witness):
        p = self.params
        stacked = witness+self.identity(p.rank*p.digits)
        a = self.public_a(public)
        return all(self.matvec(a,tuple(row[j] for row in stacked),p.modulus)==tuple(row[j] for row in self.gadget())
                   for j in range(p.rank*p.digits))

    def raw_from_values(self,public,witness,target,perturbation,digits,error):
        p,q = self.params,self.params.modulus
        target = self.vector(target,p.rank,q)
        perturbation = self.vector(perturbation,p.columns)
        digits = self.vector(digits,p.rank*p.digits)
        error = self.vector(error,p.rank)
        raw = tuple(self.add(x,y) for x,y in zip(perturbation,self.matvec(witness+self.identity(p.rank*p.digits),digits)))
        expected = tuple(self.add(x,self.scale(y,-1),q) for x,y in zip(target,error))
        if self.matvec(self.public_a(public),raw,q) != expected:
            raise RuntimeError("approximate extraction relation failed")
        return raw

    def reconstruct(self,public,target,tail):
        p,q = self.params,self.params.modulus
        target,tail = self.vector(target,p.rank,q),self.vector(tail,(1+p.digits)*p.rank)
        remainder = self.matvec(tuple(x+y for x,y in zip(public.a_hat,public.b)),tail,q)
        first = tuple(tuple((a-b+q//2)%q-q//2 for a,b in zip(x,y)) for x,y in zip(target,remainder))
        full = first+tail
        if self.matvec(self.public_a(public),full,q) != target:
            raise RuntimeError("HNF reconstruction relation failed")
        return full

    def zeta(self,adjoint=False):
        return tuple(1 if i==0 else (-1 if adjoint else 1) if i==self.n//2 else 0 for i in range(self.n))

    def signing_matrix(self,public,target):
        p,q = self.params,self.params.modulus
        target = self.vector(target,p.rank,q)
        j = (self.zeta(True),)+(self.constant(0),)*(p.rank-1)
        last = tuple(self.add(self.scale(x,q),self.scale(y,-2),2*q) for x,y in zip(j,target))
        return tuple(tuple(self.scale(x,2,2*q) for x in row)+(z,) for row,z in zip(self.public_a(public),last))

    def response(self,full,perturbation,u,challenge):
        p = self.params
        full = self.vector(full,p.columns)
        perturbation = self.vector(perturbation,p.columns+1)
        u,challenge = self.poly(u),self.poly(challenge)
        if any(x not in (0,1) for x in challenge):
            raise ValueError("binary challenge required")
        shift = self.add(self.multiply(self.zeta(),u),challenge)
        return tuple(self.add(a,self.multiply(b,shift)) for a,b in zip(perturbation,full+(self.constant(1),)))

    def recover(self,public,target,response,challenge):
        p,q = self.params,self.params.modulus
        response,challenge = self.vector(response,p.columns+1),self.poly(challenge)
        if any(x not in (0,1) for x in challenge):
            raise ValueError("binary challenge required")
        product = self.matvec(self.signing_matrix(public,target),response,2*q)
        qjc = self.scale(self.multiply(self.zeta(True),challenge),q,2*q)
        return (self.add(product[0],self.scale(qjc,-1),2*q),)+product[1:]


@dataclass(frozen=True)
class Public:
    params: ExecutionParams
    seed: bytes
    a_hat: tuple
    b: tuple

    def __post_init__(self):
        ring = ExactRing(self.params)
        _bytes(self.seed,"public seed",32,32)
        p = self.params
        object.__setattr__(self,"a_hat",ring.matrix(self.a_hat,p.rank,p.rank,p.modulus))
        object.__setattr__(self,"b",ring.matrix(self.b,p.rank,p.rank*p.digits,p.modulus))
        if self.a_hat != public_matrix(p,self.seed):
            raise ValueError("seed/public matrix mismatch")

    def to_bytes(self):
        return _canonical({"schema":SCHEMA,"params":asdict(self.params),"seed":self.seed.hex(),"b":self.b})

    @property
    def context(self): return sha256(self.to_bytes()).digest()


@dataclass(frozen=True,repr=False)
class Master:
    public: Public
    witness: tuple = field(repr=False)

    def __post_init__(self):
        p,ring = self.public.params,ExactRing(self.public.params)
        witness = ring.matrix(self.witness,2*p.rank,p.rank*p.digits)
        if any(x not in (-1,0,1) for row in witness for poly in row for x in poly) or not ring.trapdoor_relation(self.public,witness):
            raise ValueError("master trapdoor/public relation mismatch")
        object.__setattr__(self,"witness",witness)

    def __repr__(self): return "StructuredResearchMaster(private=<redacted>)"

    def snapshot(self):
        body = {"schema":SCHEMA,"kind":"private-master-memory-only","context":self.public.context.hex(),"witness":self.witness}
        return _canonical({"body":body,"checksum":sha256(_canonical(body)).hexdigest()})

    @classmethod
    def restore(cls,public,data):
        body = _snapshot_body(public,data,"private-master-memory-only",{"witness"})
        return cls(public,body["witness"])


@dataclass(frozen=True,repr=False)
class Key:
    public: Public
    identity: bytes
    tail: tuple = field(repr=False)
    full: tuple = field(init=False,repr=False)

    def __post_init__(self):
        _bytes(self.identity,"identity",1)
        p,ring = self.public.params,ExactRing(self.public.params)
        tail = ring.vector(self.tail,(1+p.digits)*p.rank)
        full = ring.reconstruct(self.public,identity_target(self.public,self.identity),tail)
        if _norm(full)>p.user_norm_cap:
            raise ValueError("key outside public norm class")
        object.__setattr__(self,"tail",tail)
        object.__setattr__(self,"full",full)

    def __repr__(self): return "StructuredResearchKey(private=<redacted>)"

    def snapshot(self):
        body = {"schema":SCHEMA,"kind":"private-key-memory-only","context":self.public.context.hex(),"identity":self.identity.hex(),"tail":self.tail}
        return _canonical({"body":body,"checksum":sha256(_canonical(body)).hexdigest()})

    @classmethod
    def restore(cls,public,data):
        body = _snapshot_body(public,data,"private-key-memory-only",{"identity","tail"})
        if type(body["identity"]) is not str or len(body["identity"])>8192:
            raise ValueError("invalid snapshot identity")
        try: identity = bytes.fromhex(body["identity"])
        except ValueError as exc: raise ValueError("invalid snapshot identity") from exc
        if identity.hex()!=body["identity"]:
            raise ValueError("noncanonical snapshot identity")
        return cls(public,identity,body["tail"])


def _snapshot_body(public,data,kind,extra):
    outer = _parse(data,{"body","checksum"})
    body = outer["body"]
    if type(body) is not dict or set(body)!={"schema","kind","context"}|extra or body["schema"]!=SCHEMA or body["kind"]!=kind or body["context"]!=public.context.hex():
        raise ValueError("snapshot context/parameter/kind mismatch")
    if outer["checksum"]!=sha256(_canonical(body)).hexdigest():
        raise ValueError("snapshot checksum mismatch")
    return body


@dataclass(frozen=True,repr=False)
class Signature:
    context: bytes
    response: tuple
    challenge: tuple

    def __repr__(self): return "StructuredResearchSignature(values=<redacted>)"

    def to_bytes(self):
        return _canonical({"schema":SCHEMA,"context":self.context.hex(),"response":self.response,"challenge":self.challenge})


def public_matrix(params,seed):
    count = params.rank**2*params.degree
    stream = XOFStream(_frame(DOMAIN,b"matrix",_canonical(asdict(params)),seed),count*4096)
    values = uniform_values(stream,params.modulus,count)
    n,d = params.degree,params.rank
    return tuple(tuple(tuple(values[(i*d+j)*n:(i*d+j+1)*n]) for j in range(d)) for i in range(d))


def identity_target(public,identity):
    _bytes(identity,"identity",1)
    p = public.params
    count = p.rank*p.degree
    stream = XOFStream(_frame(DOMAIN,b"identity",public.to_bytes(),identity),count*4096)
    values = uniform_values(stream,p.modulus,count)
    return tuple(tuple(values[i*p.degree:(i+1)*p.degree]) for i in range(p.rank))


def message_challenge(public,commitment,message):
    _bytes(message,"message",maximum=65536)
    p = public.params
    commitment = ExactRing(p).vector(commitment,p.rank,2*p.modulus)
    bits = shake_256(_frame(DOMAIN,b"message",public.to_bytes(),_canonical(commitment),message)).digest((p.degree+7)//8)
    return tuple((bits[i//8]>>(i%8))&1 for i in range(p.degree))


def _norm(value): return sum(x*x for poly in value for x in poly)


class GadgetRecurrence:
    """Real Gaussian coset recurrence; finite Z kernel differs from old tables."""
    def __init__(self,params,*,scalar_options=None,aggregate_abort_bits=128):
        self.params = params
        self.scalar = WideScalarGaussian(params.r_squared,params.r_squared,options=scalar_options)
        self.draws = params.rank*params.degree*params.digits
        self.batch = batch_certificate(self.scalar,self.draws,error_bits=aggregate_abort_bits,max_bytes=MAX_BYTES)
        if not self.batch["admitted"]:
            raise ValueError("whole gadget batch entropy cap not admitted")
        self.normalizer = normalizer_certificate(degree=params.degree,rank=params.rank,
            base=params.base,digits=params.digits,r_squared=params.r_squared)
        for residue in range(params.base):
            self.scalar.checked_inputs(params.r_squared,Fraction(-residue,params.base))

    def sample_scalar(self,target,source):
        p = self.params
        _bound(target,"canonical gadget target",0,p.modulus-1)
        error,state = target%p.p,target//p.p
        result = []
        for _ in range(p.digits):
            residue = state%p.base
            value = residue+p.base*self.scalar.sample(p.r_squared,Fraction(-residue,p.base),rng=source)
            if (state-value)%p.base:
                raise RuntimeError("gadget digit congruence failed")
            result.append(value)
            state = (state-value)//p.base
        if (p.p*sum(p.base**i*x for i,x in enumerate(result))-target+error)%p.modulus:
            raise RuntimeError("gadget recurrence relation failed")
        return tuple(result),error

    def sample(self,target,*,rng):
        p = self.params
        target = ExactRing(p).vector(target,p.rank,p.modulus)
        source = AggregateByteSource(rng,self.batch["selected_cap_bytes"])
        result,errors = [],[]
        for poly in target:
            values = [self.sample_scalar(value,source) for value in poly]
            result.extend(tuple(x[0][j] for x in values) for j in range(p.digits))
            errors.append(tuple(x[1] for x in values))
        return tuple(result),tuple(errors)

    def certificate(self):
        finite = Fraction(self.batch["scalar_kernel_tv_including_aggregate_exact"])
        bias = Fraction(self.normalizer["raw_denominator_removal_tv_upper_exact"])
        return {"digit_draws":self.draws,"width_squared":self.params.base**2*self.params.r_squared,
            "finite_Z_kernel_tv_including_batch_abort":str(finite),
            "ideal_recurrence_to_spherical_fiber_tv_upper":str(bias),
            "total_fiber_tv_upper_including_abort":str(min(Fraction(1),finite+bias)),
            "proof":"coset z=a+b*k, k~D_Z,r²,-a/b; product normalizers tilt recurrence to spherical fiber",
            "finite_kernel_equals_legacy_tables":False,"batch":self.batch,
            "scope":"uniform in canonical residual; fiber only, not final HNF key law"}


class Execution:
    """Independent algorithms; each extraction is explicit, no issuer cache."""
    def __init__(self,params,*,rng=None,series_options=None,scalar_options=None):
        if not isinstance(params,ExecutionParams):
            raise ValueError("ExecutionParams required")
        self.params,self.ring = params,ExactRing(params)
        self.rng = SecureRandom() if rng is None else rng
        self.series_options = SeriesOptions() if series_options is None else series_options
        self.scalar_options = WideScalarOptions() if scalar_options is None else scalar_options
        if not isinstance(self.series_options,SeriesOptions) or not isinstance(self.scalar_options,WideScalarOptions):
            raise ValueError("explicit bounded sampler option classes required")
        self.gadget = GadgetRecurrence(params,scalar_options=self.scalar_options,
            aggregate_abort_bits=self.series_options.aggregate_abort_bits)
        self.u_scalar = WideScalarGaussian(params.r_squared,params.r_squared,options=self.scalar_options)
        self.u_batch = batch_certificate(self.u_scalar,params.degree,error_bits=self.series_options.aggregate_abort_bits,max_bytes=MAX_BYTES)
        if not self.u_batch["admitted"]:
            raise ValueError("whole u batch entropy cap not admitted")
        # Admit both entire witness classes before consuming secret entropy.
        p = params
        zero = tuple(tuple((0,)*p.degree for _ in range(p.rank*p.digits)) for _ in range(2*p.rank))
        self.class_master_certificate = self._master_plan(zero).public_certificate()
        self.class_sign_certificate = self._sign_plan(((0,)*p.degree,)*p.columns).public_certificate()
        self.last_master_certificate = self.last_sign_certificate = None
        self.sign_attempts = self.extract_calls = 0

    def _master_plan(self,witness):
        p = self.params
        return StructuredSampleF(master_operator(degree=p.degree,rank=p.rank,digits=p.digits,base=p.base,
            witness=witness,first_squared=p.master_squared,second_squared=p.master_squared,r_squared=p.r_squared),bound_kind="cbd1",
            options=self.series_options,scalar_options=self.scalar_options)

    def _sign_plan(self,full):
        p = self.params
        return StructuredSampleF(signature_operator(degree=p.degree,rank=p.rank,digits=p.digits,user_vector=full,
            first_squared=p.signature_squared,second_squared=p.signature_squared,r_squared=p.r_squared,
            noise_factor=2),bound_kind="public-norm-cap",witness_norm_squared_cap=p.user_norm_cap,
            options=self.series_options,scalar_options=self.scalar_options)

    def _read(self,count):
        data = self.rng.read(count)
        if type(data) is not bytes or len(data)!=count:
            raise ValueError("random source returned wrong byte count/type")
        return data

    def setup(self):
        p,r = self.params,self.ring
        seed = self._read(32)
        data = self._read(2*p.rank*p.rank*p.digits*p.degree)
        values = tuple((x&1)-((x>>1)&1) for x in data)
        witness = tuple(tuple(tuple(values[(i*p.rank*p.digits+j)*p.degree:(i*p.rank*p.digits+j+1)*p.degree])
            for j in range(p.rank*p.digits)) for i in range(2*p.rank))
        a_hat = public_matrix(p,seed)
        public = Public(p,seed,a_hat,r.build_public(a_hat,witness))
        return public,Master(public,witness)

    def key_extract(self,master,identity):
        if not isinstance(master,Master) or master.public.params!=self.params:
            raise ValueError("matching independent master required")
        _bytes(identity,"identity",1)
        self.extract_calls += 1
        p,r = self.params,self.ring
        public = master.public
        target = identity_target(public,identity)
        plan = self._master_plan(master.witness)
        self.last_master_certificate = plan.public_certificate()
        flat = plan.sample(rng=self.rng)
        perturbation = tuple(tuple(flat[i:i+p.degree]) for i in range(0,len(flat),p.degree))
        residual = tuple(r.add(h,r.scale(a,-1),p.modulus) for h,a in zip(target,r.matvec(r.public_a(public),perturbation,p.modulus)))
        digits,error = self.gadget.sample(residual,rng=self.rng)
        raw = r.raw_from_values(public,master.witness,target,perturbation,digits,error)
        if _norm(raw)>p.raw_norm_cap:
            raise SamplingAbort("raw extracted norm cap exceeded; no reselection")
        return Key(public,identity,raw[p.rank:])

    def sign(self,key,message):
        if not isinstance(key,Key) or key.public.params!=self.params:
            raise ValueError("matching independent key required")
        _bytes(message,"message",maximum=65536)
        p,r,public = self.params,self.ring,key.public
        target = identity_target(public,key.identity)
        plan = self._sign_plan(key.full)
        self.last_sign_certificate = plan.public_certificate()
        for _ in range(p.sign_max_attempts):
            self.sign_attempts += 1
            flat = plan.sample(rng=self.rng)
            perturbation = tuple(tuple(flat[i:i+p.degree]) for i in range(0,len(flat),p.degree))
            commitment = r.matvec(r.signing_matrix(public,target),perturbation,2*p.modulus)
            challenge = message_challenge(public,commitment,message)
            centers = tuple(Fraction(-x,2) for x in r.multiply(r.zeta(True),challenge))
            source = AggregateByteSource(self.rng,self.u_batch["selected_cap_bytes"])
            u = tuple(self.u_scalar.sample(p.r_squared,center,rng=source) for center in centers)
            response = r.response(key.full,perturbation,u,challenge)
            if _norm(response)>p.signature_norm_cap:
                continue  # Algorithm 7's only retry; all numerical/entropy aborts propagate.
            signature = Signature(public.context,response,challenge)
            if not self.verify(public,key.identity,message,signature):
                raise RuntimeError("honest signature commitment invariant failed")
            return signature
        raise SamplingAbort("signature norm rejection limit exhausted")

    def verify(self,public,identity,message,signature):
        try:
            if not isinstance(public,Public) or public.params!=self.params or not isinstance(signature,Signature) or signature.context!=public.context:
                return False
            _bytes(identity,"identity",1)
            _bytes(message,"message",maximum=65536)
            self.ring.vector(signature.response,self.params.columns+1)
            self.ring.poly(signature.challenge)
            if _norm(signature.response)>self.params.signature_norm_cap:
                return False
            commitment = self.ring.recover(public,identity_target(public,identity),signature.response,signature.challenge)
            return message_challenge(public,commitment,message)==signature.challenge
        except (ValueError,TypeError,AttributeError,OverflowError):
            return False


class CountingEntropy:
    """Operational audit limit; its extra abort probability is not certified."""
    def __init__(self,source,maximum=MAX_BYTES):
        _bound(maximum,"audit entropy limit",1,MAX_BYTES)
        self.source,self.maximum,self.used = source,maximum,0

    def read(self,size):
        _bound(size,"entropy request",0,MAX_BYTES)
        if self.used+size>self.maximum:
            raise SamplingAbort("whole research audit entropy cap exhausted")
        data = self.source.read(size)
        if type(data) is not bytes or len(data)!=size:
            raise ValueError("invalid audit entropy response")
        self.used += size
        return data


def sampler_profile(name):
    """Explicit numerical profiles; none is an admitted cryptographic preset."""
    if name=="default":
        return SeriesOptions(),WideScalarOptions()
    if name not in ("query-bounded","query-bounded-deep"):
        raise ValueError("unknown independent numerical profile")
    return (SeriesOptions(precision_bits=1024,ticket_bits=768,vector_dyadic_bits=384,
        series_error_bits=256 if name=="query-bounded" else 384,aggregate_abort_bits=192),
        WideScalarOptions(tail_bits=192,mass_bits=256,precision_bits=384,gaussian_abort_bits=192,
            max_uniform_trials=256,target_tv_bits=160))


def sampling_query_certificate(execution,*,new_identities=2**40,signatures=2**40):
    """Only finite-sampler hybrids, conditional on consistent reachable calls.

    This does not certify the independent audit's operational global cap,
    norm acceptance, final HNF law, PSF premise, or any IBS security game.
    """
    _bound(new_identities,"new identity query count",0,2**64)
    _bound(signatures,"signature query count",0,2**64)
    master = Fraction(execution.class_master_certificate["full_target_integer_tv_upper_including_abort"])
    sign = Fraction(execution.class_sign_certificate["full_target_integer_tv_upper_including_abort"])
    gadget = Fraction(execution.gadget.batch["scalar_kernel_tv_including_aggregate_exact"])
    u = Fraction(execution.u_batch["scalar_kernel_tv_including_aggregate_exact"])
    bound = min(Fraction(1),new_identities*(master+gadget)+signatures*execution.params.sign_max_attempts*(sign+u))
    return {"new_identity_queries":new_identities,"sign_queries":signatures,
        "max_norm_attempts_per_sign":execution.params.sign_max_attempts,
        "fresh_issuance_finite_sampling_hybrid_tv_upper":str(min(Fraction(1),master+gadget)),
        "sign_attempt_finite_sampling_hybrid_tv_upper":str(min(Fraction(1),sign+u)),
        "finite_sampling_transcript_hybrid_tv_upper":str(bound),
        "passes_2_minus_128_finite_sampling_only":bound<=Fraction(1,2**128),
        "scope":"finite samplers to ideal joint perturbation+ideal recurrence+ideal u; not an IBS security bound",
        "requires":"uniform reachable-history class bounds, fresh entropy, consistent fixed identity ledger for reuse",
        "excluded":["gadget recurrence bias to spherical fiber","convolution/HNF/PSF mapping","norm rejection probability",
            "independent audit operational cap","persistent issuer","underlying cryptographic reduction"]}


def certificate_profiles(*,degree=512,rank=2,digits=8):
    """Zero-entropy preflight of fixed public numerical profiles."""
    params = ExecutionParams.from_candidate(conditional_candidate(degree=degree,rank=rank,digits=digits))
    class NoEntropy:
        def read(self,size): raise RuntimeError("certificate preflight must not consume entropy")
    rows = []
    for name in ("default","query-bounded","query-bounded-deep"):
        series,scalar = sampler_profile(name)
        row = {"profile":name,"series_options":asdict(series),"scalar_options":asdict(scalar)}
        try:
            execution = Execution(params,rng=NoEntropy(),series_options=series,scalar_options=scalar)
            row.update({"admitted":True,"master":execution.class_master_certificate,
                "sign":execution.class_sign_certificate,"gadget":execution.gadget.certificate(),
                "u_batch":execution.u_batch,"finite_sampling_queries":sampling_query_certificate(execution)})
        except (ValueError,RuntimeError) as exc:
            row.update({"admitted":False,"failure_type":type(exc).__name__})
        rows.append(row)
    return {"schema":SCHEMA,"scope":"zero-entropy numerical/resource preflight only",
        "parameters":asdict(params),"profiles":rows,"actual_entropy_bytes":0,
        "security_claim":"none","backend_admitted":False,"parameters_are_formal":False}


def audit(*,degree=512,rank=2,digits=8,profile="query-bounded-deep"):
    """One root, one issuance, one signature; no success-selected roots/keys."""
    candidate = conditional_candidate(degree=degree,rank=rank,digits=digits)
    params = ExecutionParams.from_candidate(candidate)
    series_options,scalar_options = sampler_profile(profile)
    source = CountingEntropy(SecureRandom())
    result = {"schema":SCHEMA,"parameters":asdict(params),"Q":params.modulus,
        "environment":{"platform":platform.platform(),"python":platform.python_version(),"sage":sage_version},
        "identities":1,"identity_bytes":len(b"SRGG-structured-research-one-identity"),
        "message_bytes":32,"roots_requested":1,"key_issuances_requested":1,"signatures_requested":1,
        "production_randomness":True,"root_reselection":False,"key_reselection":False,
        "numerical_profile":profile,"series_options":asdict(series_options),"scalar_options":asdict(scalar_options),
        "sampler":"joint isotropic matrix sqrt series; not bit-identical to legacy sequential Schur",
        "hash_domains":"independent research namespace; canonical length-prefixed binding",
        "snapshots":"in-memory roundtrip only; private payloads and signature are not exported",
        "audit_entropy_cap_bytes":MAX_BYTES,"audit_extra_abort_probability_certified":False,
        "public_backend":False,"fixed_persistent_service":False,
        "security_claim":"none","backend_admitted":False,"parameters_are_formal":False,
        "source_sha256":{name:sha256((Path(__file__).parents[4]/name).read_bytes()).hexdigest() for name in (
            "experiments/research/candidates/srgg/"+name for name in
            ("structured_execution.py","structured_samplef.py","wide_scalar.py","structured_geometry.py",
             "aggregate_budget.py","fiber_normalizers.py","spectral_bounds.py","formal_candidates.py"))},
        "timings_seconds":{},"completed":False}
    started = perf_counter()
    execution = None
    stage = "prepare"
    try:
        execution = Execution(params,rng=source,series_options=series_options,scalar_options=scalar_options)
        result["timings_seconds"][stage] = perf_counter()-started
        result["finite_sampling_query_certificate"] = sampling_query_certificate(execution)
        stage,clock = "setup",perf_counter()
        public,master = execution.setup()
        result["timings_seconds"][stage] = perf_counter()-clock
        stage,clock = "master-memory-snapshot",perf_counter()
        master_snapshot = master.snapshot()
        restored_master = Master.restore(public,master_snapshot)
        result["timings_seconds"][stage] = perf_counter()-clock
        stage,clock = "key-extract",perf_counter()
        identity,message = b"SRGG-structured-research-one-identity",bytes(range(32))
        key = execution.key_extract(restored_master,identity)
        result["timings_seconds"][stage] = perf_counter()-clock
        stage,clock = "key-memory-snapshot",perf_counter()
        key_snapshot = key.snapshot()
        restored_key = Key.restore(public,key_snapshot)
        result["timings_seconds"][stage] = perf_counter()-clock
        stage,clock = "sign-after-restore",perf_counter()
        signature = execution.sign(restored_key,message)
        result["timings_seconds"][stage] = perf_counter()-clock
        stage,clock = "verify-and-negative-checks",perf_counter()
        random_bytes = source.read((params.columns+2)*params.degree)
        random_response = tuple(tuple((x&1)-((x>>1)&1) for x in
            random_bytes[i*params.degree:(i+1)*params.degree]) for i in range(params.columns+1))
        random_signature = Signature(public.context,random_response,
            tuple(x&1 for x in random_bytes[-params.degree:]))
        checks = {"honest":execution.verify(public,identity,message,signature),
            "wrong_identity_rejected":not execution.verify(public,identity+b"!",message,signature),
            "wrong_message_rejected":not execution.verify(public,identity,message+b"!",signature),
            "random_signature_rejected":not execution.verify(public,identity,message,random_signature),
            "root_snapshot_equal":restored_master.snapshot()==master_snapshot,
            "key_snapshot_equal":restored_key.snapshot()==key_snapshot}
        result["timings_seconds"][stage] = perf_counter()-clock
        result.update({"checks":checks,"completed":all(checks.values()),
            "public_key_bytes":len(public.to_bytes()),"public_key_sha256":sha256(public.to_bytes()).hexdigest(),
            "master_snapshot_bytes":len(master_snapshot),"key_snapshot_bytes":len(key_snapshot),
            "signature_bytes":len(signature.to_bytes()),
            "master_samplef":execution.last_master_certificate,"sign_samplef":execution.last_sign_certificate,
            "gadget":execution.gadget.certificate(),"u_batch":execution.u_batch,
            "actual_gadget_digit_draws":execution.gadget.draws})
    except (SamplingAbort,ValueError,RuntimeError) as exc:
        # Diagnostic classes/stage only: arbitrary exception text can contain private data.
        result.update({"failed_stage":stage,"failure_type":type(exc).__name__})
    result["total_seconds"] = perf_counter()-started
    result["actual_entropy_bytes"] = source.used
    if execution is not None:
        result["actual_extract_calls"],result["actual_sign_attempts"] = execution.extract_calls,execution.sign_attempts
        result["exact_ZZ_ring_products_excluding_SampleF"] = execution.ring.products
    try:
        import resource
        result["peak_rss_KiB"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except ImportError:
        result["peak_rss_KiB"] = None
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--degree",type=int,default=512)
    parser.add_argument("--rank",type=int,default=2)
    parser.add_argument("--digits",type=int,default=8)
    parser.add_argument("--profile",choices=("default","query-bounded","query-bounded-deep"),default="query-bounded-deep")
    parser.add_argument("--certificate-profiles",action="store_true")
    parser.add_argument("--output",type=Path)
    args = parser.parse_args()
    report = (certificate_profiles(degree=args.degree,rank=args.rank,digits=args.digits) if args.certificate_profiles else
        audit(degree=args.degree,rank=args.rank,digits=args.digits,profile=args.profile))
    payload = json.dumps(report,indent=2,ensure_ascii=True)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(payload,encoding="utf-8",newline="\n")
    else:
        print(payload,end="")
    if not args.certificate_profiles and not report["completed"]:
        raise SystemExit(1)


if __name__ == "__main__": main()
