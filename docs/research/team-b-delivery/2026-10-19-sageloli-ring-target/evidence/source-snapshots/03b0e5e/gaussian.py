"""Vectorized genuine discrete Gaussian rounding and ternary coset CDTs.

The continuous Fourier stage has a separate, explicitly uncertified numerical
error. This module never substitutes uniform noise for a Gaussian draw.
"""
from bisect import bisect_right
from functools import lru_cache
import math
import numpy as np


class SamplingAbort(RuntimeError): pass


class ByteSource:
    def __init__(self,rng,limit=256<<30):
        if not callable(getattr(rng,"read",None)): raise TypeError("read(n) byte source required")
        self.rng=rng;self.limit=limit;self.used=0

    def read(self,n):
        if type(n) is not int or n<0 or self.used+n>self.limit:
            raise SamplingAbort("phase entropy budget exhausted")
        raw=self.rng.read(n)
        if not isinstance(raw,(bytes,bytearray,memoryview)) or len(raw)!=n:
            raise SamplingAbort("entropy source returned invalid bytes")
        self.used+=n
        return bytes(raw)


def normal(shape,source):
    """Box-Muller on an exactly representable 52-bit midpoint grid."""
    count=math.prod(shape);pairs=(count+1)//2
    words=np.frombuffer(source.read(pairs*16),dtype="<u8").reshape(pairs,2)
    u=((words>>12).astype(np.float64)+0.5)*2.0**-52
    radius=np.sqrt(-2*np.log(u[:,0]));angle=2*np.pi*u[:,1]
    out=np.empty(2*pairs);out[0::2]=radius*np.cos(angle);out[1::2]=radius*np.sin(angle)
    return out[:count].reshape(shape)


def _uniform_small(count,bound,source,max_trials=320):
    if not 1<=bound<=256: raise ValueError("small uniform bound")
    out=np.empty(count,dtype=np.int64);pending=np.arange(count)
    limit=256-256%bound
    for _ in range(max_trials):
        if not len(pending): return out
        x=np.frombuffer(source.read(len(pending)),dtype=np.uint8).astype(np.int64)
        keep=x<limit;out[pending[keep]]=x[keep]%bound;pending=pending[~keep]
    raise SamplingAbort("uniform candidate trial cap")


def _exp_approx(t):
    """Degree-12 Taylor at t/4096, then 12 squarings; t in [0,512].

    A 2^-24 absolute guard covers the Taylor remainder, argument rounding,
    and <40 IEEE-754 binary64 operations amplified by at most 4096. Near a
    random comparison boundary the directed MPFI calculation is authoritative.
    """
    if np.any(t<0) or np.any(t>512) or not np.all(np.isfinite(t)):
        raise ValueError("Gaussian exponent outside admitted numerical range")
    x=-t/4096
    value=np.full_like(x,1/math.factorial(12))
    for j in range(11,-1,-1): value=value*x+1/math.factorial(j)
    for _ in range(12): value=value*value
    return value


def _mpfi_accept(offset,fraction,width,ticket,mass_bits):
    from sage.all import QQ, RealIntervalField
    frac=QQ(float(fraction).as_integer_ratio()[0])/float(fraction).as_integer_ratio()[1]
    closest=0 if frac<=QQ(1)/2 else 1
    argument=((int(offset)-frac)**2-(closest-frac)**2)/width
    for precision in (mass_bits+64,mass_bits+192,mass_bits+512):
        f=RealIntervalField(precision);w=(-f.pi()*f(argument)).exp()*f(2)**mass_bits
        lo=int(w.lower().floor());hi=int(w.upper().floor())
        if lo==hi: return ticket<lo
    raise SamplingAbort("Gaussian probability interval unresolved")


def round_gaussian(centers,width_squared,source,*,tail_bits=256,mass_bits=320,max_trials=8192):
    """D_Z,s,c by bounded uniform-box rejection, independently per coordinate.

    Centers are exact dyadic values of the supplied binary64 numbers. Scalar
    acceptance uses 320-bit tickets; far comparisons take a guarded vector
    path and ambiguous comparisons use directed MPFI, never a rounded center.
    """
    c=np.asarray(centers,dtype=np.float64)
    if not np.all(np.isfinite(c)) or np.any(np.abs(c)>=2**51):
        raise SamplingAbort("continuous center exceeds exact dyadic rounding domain")
    if type(width_squared) is not int or not 16<=width_squared<=64:
        raise ValueError("fixed Gaussian width domain")
    if mass_bits%8 or not 256<=mass_bits<=512: raise ValueError("Gaussian mass bits")
    radius=math.ceil(math.sqrt(width_squared*((tail_bits+16)*math.log(2))/math.pi))+2
    bound=2*radius+2
    if bound>256: raise ValueError("rounding proposal support too large")
    flat=c.ravel();shift=np.floor(flat).astype(np.int64);frac=flat-shift
    closest=np.where(frac<=0.5,0.,1.);out=np.empty(len(flat),dtype=np.int64)
    pending=np.arange(len(flat));width=mass_bits//8
    for _ in range(max_trials):
        if not len(pending): return out.reshape(c.shape)
        x=_uniform_small(len(pending),bound,source)-radius
        f=frac[pending];distance=(x-f)**2-(closest[pending]-f)**2
        t=np.pi*distance/width_squared
        weight=_exp_approx(t)
        raw=source.read(len(pending)*width)
        tickets=np.frombuffer(raw,dtype=np.uint8).reshape(-1,width)
        prefix=np.frombuffer(tickets[:,:8].copy().tobytes(),dtype=">u8")
        u=((prefix>>12).astype(np.float64)+0.5)*2.0**-52
        accept=u<weight-2.0**-24
        uncertain=np.flatnonzero(np.abs(u-weight)<=2.0**-24)
        for i in uncertain:
            ticket=int.from_bytes(tickets[i].tobytes(),"big")
            accept[i]=_mpfi_accept(x[i],f[i],width_squared,ticket,mass_bits)
        out[pending[accept]]=shift[pending[accept]]+x[accept]
        pending=pending[~accept]
    raise SamplingAbort("integer Gaussian rejection cap exhausted")


@lru_cache(maxsize=8)
def ternary_tables(r_squared,tail_bits,mass_bits):
    from ibme.lattice.chkp.gaussian import build_gaussian_table_squared
    return tuple(build_gaussian_table_squared(9*r_squared,step=3,residue=a,
        tail_bits=tail_bits,mass_bits=mass_bits,precision_bits=mass_bits+96,
        max_trials=320,max_radius=256) for a in range(3))


def _cdf(table,count,source):
    """Exact integer CDT law, with rejection against its non-power-of-two mass."""
    bits=table.total_mass.bit_length();width=(bits+7)//8
    shift=8*(width-8);limit=table.total_mass
    thresholds=np.array([v>>shift for v in table.cumulative],dtype=np.uint64)
    out=np.empty(count,dtype=np.int64);pending=np.arange(count)
    for _ in range(320):
        if not len(pending): return out
        raw=np.frombuffer(source.read(len(pending)*width),dtype=np.uint8).copy().reshape(-1,width)
        raw[:,0]&=(1<<(bits-8*(width-1)))-1
        prefix=np.frombuffer(raw[:,:8].copy().tobytes(),dtype=">u8")
        keep=prefix<(limit>>shift)
        equal=np.flatnonzero(prefix==(limit>>shift))
        for i in equal: keep[i]=int.from_bytes(raw[i].tobytes(),"big")<limit
        index=np.searchsorted(thresholds,prefix,side="right")
        ambiguous=np.flatnonzero(keep & (index>0) & (prefix==thresholds[np.maximum(index-1,0)]))
        for i in ambiguous: index[i]=bisect_right(table.cumulative,int.from_bytes(raw[i].tobytes(),"big"))
        accepted=np.flatnonzero(keep)
        if len(accepted):out[pending[accepted]]=np.array(table.support,dtype=np.int64)[index[accepted]]
        pending=pending[~keep]
    raise SamplingAbort("ternary Gaussian CDT rejection cap")


def ternary(target,k,r_squared,source,*,tail_bits=256,mass_bits=320):
    state=np.asarray(target,dtype=object).copy()
    q=3**k
    if state.ndim!=1 or any(type(x) is not int or not 0<=x<q for x in state):
        raise ValueError("canonical ternary syndrome required")
    tables=ternary_tables(r_squared,tail_bits,mass_bits)
    out=np.empty((k,len(state)),dtype=np.int64)
    for digit in range(k):
        residues=np.array([int(x%3) for x in state],dtype=np.int8)
        for residue,table in enumerate(tables):
            where=np.flatnonzero(residues==residue)
            out[digit,where]=_cdf(table,len(where),source)
        state=(state-out[digit])//3
    return out
