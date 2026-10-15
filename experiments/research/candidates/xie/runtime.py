"""Corrected Xie-equation research kernel: genuine NTRU/GPV/rejection.

This is NOT a literal reproduction or an admitted/common IBSBackend. Unit
membership, basis coordinates and GPV use are explicit repairs; see the map.
No Falcon key generator, fixed keys, uniform-as-Gaussian or hidden native RNG.
Sage/PARI fresh work is supported on the main thread only.
"""
from .execution import require_main_thread
require_main_thread("loading the Sage study runtime")

from sage.all import QQ,ZZ,RealIntervalField,matrix,vector,identity_matrix

from ibme.core.randomness import SecureRandom
from ibme.core.errors import RandomnessError
from experiments.research.online_gaussian_reference import OnlineOptions,OnlineScalarGaussian
from experiments.research.gaussian_reference import SamplingAbort,interval_bounds
from experiments.research.chkp_basis import KernelBasis,ModMatrixReference
from experiments.research.chkp_gpv import CHKPGPVSampler
from .params import StudyParams
from .ring import add,neg,mul,inverse,rotations
from .objects import Public,Master,IdentitySecret,Signature
from .hashing import identity_hash,challenge_hash,message_bytes


class BudgetRandom:
    def __init__(self,params,rng=None):
        self.source=SecureRandom() if rng is None else rng;self.used=0;self.limit=params.entropy_limit
        if not callable(getattr(self.source,"read",None)):raise RandomnessError("study requires read(n)")
    def read(self,n):
        if type(n) is not int or n<0 or n>self.limit-self.used:raise SamplingAbort("operation entropy budget")
        self.used+=n;raw=self.source.read(n)
        if type(raw) is not bytes or len(raw)!=n:raise RandomnessError("study random source type/length")
        return raw


def options(params):
    return OnlineOptions(tail_bits=params.tail_bits,mass_bits=params.mass_bits,precision_bits=params.precision_bits,
        gaussian_abort_bits=params.tail_bits,max_uniform_trials=128,rational_bits=8192)


def babai_reduce(F,G,f,g):
    """Subtract k(f,g) using exact rational nearest-plane on n rotations."""
    require_main_thread("NTRU nearest-plane reduction")
    rows=[vector(ZZ,a+b) for a,b in zip(rotations(f),rotations(g))]
    orth=[];norms=[]
    for row in rows:
        v=vector(QQ,row)
        for b,norm in zip(orth,norms):v-=(v.dot_product(b)/norm)*b
        norm=v.dot_product(v)
        if norm<=0:raise ValueError("dependent NTRU rotation basis")
        if any(max(abs(int(x.numerator())).bit_length(),int(x.denominator()).bit_length())>8192 for x in v):
            raise ValueError("NTRU rational bit budget")
        orth.append(v);norms.append(norm)
    current=vector(ZZ,tuple(F)+tuple(G))
    for i in reversed(range(len(rows))):
        quotient=current.dot_product(orth[i])/norms[i]
        k=int((quotient+QQ(1)/2).floor());current-=k*rows[i]
    n=len(f)
    return tuple(int(x) for x in current[:n]),tuple(int(x) for x in current[n:])


def bezout_one(f,g):
    """Exact Z[x]/(x^n+1) ideal membership, not resultant-gcd heuristics."""
    require_main_thread("NTRU ideal membership")
    n=len(f);rows=matrix(ZZ,rotations(f)+rotations(g))
    H,U=rows.hermite_form(transformation=True)
    if H.nrows()<n or H.matrix_from_rows(list(range(n)))!=identity_matrix(ZZ,n):return None
    if any(x for row in H.rows()[n:] for x in row):return None
    if U*rows!=H:raise AssertionError("integer ideal certificate")
    a=tuple(int(x) for x in U.row(0)[:n]);b=tuple(int(x) for x in U.row(0)[n:])
    if add(mul(f,a),mul(g,b))!=(1,)+(0,)*(n-1):raise AssertionError("ring Bezout identity")
    return neg(b),a  # f*G1-g*F1=1


def setup(params=None,*,rng=None,stats=None):
    require_main_thread("NTRU root generation")
    params=StudyParams() if params is None else params
    if type(params) is not StudyParams:raise ValueError("need explicit StudyParams")
    scalar=OnlineScalarGaussian(params.key_width**2,params.key_width**2,options=options(params))
    source=BudgetRandom(params,rng);n=params.n
    for attempt in range(1,params.keygen_attempts+1):
        f=tuple(scalar.sample(params.key_width**2,rng=source) for _ in range(n))
        g=tuple(scalar.sample(params.key_width**2,rng=source) for _ in range(n))
        if any(sum(x*x for x in a)>n*params.key_width**2 for a in (f,g)):continue
        try:finv=inverse(f,params.q);inverse(g,params.q)
        except ValueError:continue
        bezout=bezout_one(f,g)
        if bezout is None:continue
        F1,G1=bezout
        F,G=babai_reduce(tuple(params.q*x for x in F1),tuple(params.q*x for x in G1),f,g)
        if sum(x*x for a in (F,G) for x in a)>n*n*params.key_width**2:continue
        public=Public(params,mul(g,finv,params.q));master=Master(public,f,g,F,G)
        if stats is not None:stats.update(keygen_attempts=attempt,entropy_bytes=source.used)
        return public,master
    raise SamplingAbort("NTRU key generation budget; no outer retry")


def preimage_sampler(master):
    """Rotate each (f,g) row to (-g,f), LLL precondition, then actual GPV."""
    require_main_thread("identity Gaussian sampler construction")
    p=master.public.params;n=p.n
    root_rows=[neg(a)+b for a,b in zip(rotations(master._g),rotations(master._f))]
    root_rows += [neg(a)+b for a,b in zip(rotations(master._G),rotations(master._F))]
    rows=matrix(ZZ,root_rows).LLL()
    h_columns=matrix(ZZ,rotations(master.public.h)).transpose()
    public=identity_matrix(ZZ,n).augment(h_columns).apply_map(lambda x:int(x)%p.q)
    basis=KernelBasis(ModMatrixReference(tuple(tuple(int(x) for x in row) for row in public.rows()),p.q),
                      tuple(tuple(int(x) for x in row) for row in rows.transpose().rows()))
    return CHKPGPVSampler(basis,p.extract_width**2,epsilon_bits=64,options=options(p))


def rejection_mass(params,y,z):
    """Lower-rounded min(1,rho_s(z)/(M rho_s(z-v))) with y=z-v."""
    require_main_thread("signature rejection calculation")
    difference=sum(x*x for x in z)-sum(x*x for x in y)
    field=RealIntervalField(params.precision_bits);scale=1<<params.mass_bits
    exponent=-field.pi()*field(QQ(difference)/params.signing_width**2)-field(params.rejection_m).log()
    low,high=interval_bounds(exponent)
    if low>=0:return scale
    # exp(-b) < 2^-mass_bits for b>mass_bits, a conservative quantization.
    if high<=-params.mass_bits:return 0
    probability=exponent.exp();lower,upper=interval_bounds(probability)
    if upper-lower>QQ(1)/2**params.mass_bits:raise SamplingAbort("rejection interval precision")
    return max(0,min(scale,int((lower*scale).floor())))


def sign(key,message,*,rng=None,stats=None):
    require_main_thread("fresh signature generation")
    if type(key) is not IdentitySecret:raise TypeError("study signing key")
    public=key.public;p=public.params;message=message_bytes(public,message)
    scalar=OnlineScalarGaussian(p.signing_width**2,p.signing_width**2,options=options(p))
    source=BudgetRandom(p,rng);size=(p.mass_bits+7)//8
    for attempt in range(1,p.signing_attempts+1):
        y1=tuple(scalar.sample(p.signing_width**2,rng=source) for _ in range(p.n))
        y2=tuple(scalar.sample(p.signing_width**2,rng=source) for _ in range(p.n))
        u=challenge_hash(public,add(y1,mul(public.h,y2,p.q),p.q),message)
        z1=add(y1,mul(key.s1,u));z2=add(y2,mul(key.s2,u))
        mass=rejection_mass(p,y1+y2,z1+z2)
        ticket=int.from_bytes(source.read(size),"big")&((1<<p.mass_bits)-1)
        if ticket<mass:
            signature=Signature(public.context,z1,z2,u)
            if stats is not None:stats.update(signing_attempts=attempt,entropy_bytes=source.used)
            return signature
    raise SamplingAbort("signature rejection budget; no outer retry")
