"""O(d*r*k + d*k^2) ring perturbation, never a (d*r)^2 covariance.

For J=[-T;I], square-root aI-cJJ* with the stable low-rank identity
sqrt(a)I - J U diag(c/(sqrt(a)+sqrt(a-c*lambda))) U* J*.
The scalar Gaussian rounding has width r; a=s^2-r^2 and c=9r^2.
Continuous-grid and eigensolver approximation errors remain uncertified.
"""
import math
import numpy as np
from .gaussian import normal,round_gaussian,SamplingAbort


def twiddles(d):
    """Directed MPFI verifies every rounded twist within 2^-51 per component."""
    from sage.all import QQ,RealIntervalField
    f=RealIntervalField(192);out=np.empty(d,dtype=np.complex128);error=f(QQ(1)/2**51)
    for j in range(d):
        angle=-f.pi()*j/d;re=angle.cos();im=angle.sin()
        x=float(re.center());y=float(im.center())
        if not (re-f(x)).abs().upper()<error.lower() or not (im-f(y)).abs().upper()<error.lower():
            raise ValueError("twiddle enclosure failed")
        out[j]=complex(x,y)
    return out


def enclosed_transform(values,twist):
    """Fixed radix-2 butterfly plus an absolute component-error envelope.

    Exact integer input is restricted below 2^53. For each butterfly the
    envelope 3E+2^-46*(B+1) covers two input balls, twiddle uncertainty and
    binary64 multiplication/addition rounding. E is rounded upward each step.
    No error bound for an opaque FFT library is assumed for PSD admission.
    """
    a=np.asarray(values)
    if a.dtype.kind not in "iu" or a.ndim!=3 or np.any(a>=2**53) or np.any(a<=-2**53):
        raise ValueError("exact integer spectral input required")
    d=a.shape[-1]
    if d<4 or d&(d-1) or len(twist)!=d: raise ValueError("power-of-two transform")
    b=float(np.max(np.abs(a)))
    error=np.nextafter(2.0**-48*(b+1),np.inf)
    z=a.astype(np.complex128)*twist
    # Explicit bit reversal; all subsequent butterflies are componentwise.
    order=np.arange(d,dtype=np.uint32);reverse=np.zeros(d,dtype=np.uint32)
    for _ in range(d.bit_length()-1):reverse=(reverse<<1)|(order&1);order>>=1
    z=z[...,reverse].copy()
    for size in (2**i for i in range(1,d.bit_length())):
        b=float(np.max(np.maximum(np.abs(z.real),np.abs(z.imag))))
        blocks=z.reshape(*z.shape[:-1],d//size,size)
        left=blocks[...,:size//2].copy()
        right=blocks[...,size//2:].copy()*twist[np.arange(size//2)*(2*d//size)]
        blocks[...,:size//2]=left+right;blocks[...,size//2:]=left-right
        error=np.nextafter(3*error+2.0**-46*(b+1),np.inf)
    return z,error


class FourierPlan:
    def __init__(self,trapdoor,width_squared,r_squared,*,progress=None):
        t=np.asarray(trapdoor)
        if t.ndim!=3 or t.dtype.kind not in "iu": raise ValueError("integer ring trapdoor tensor")
        self.top,self.k,self.d=t.shape;self.rows=self.top+self.k
        self.width_squared=width_squared;self.r_squared=r_squared
        if type(width_squared) is not int or type(r_squared) is not int or width_squared<=r_squared:
            raise ValueError("positive exact covariance parameters")
        self.twist=twiddles(self.d)
        full,error=enclosed_transform(t,self.twist)
        self.t=np.ascontiguousarray(full[...,:self.d//2].transpose(2,0,1));del full
        mags=np.abs(self.t)
        mags=np.nextafter(mags*(1+2.0**-40)+2*error,np.inf)
        row=np.max(np.sum(mags,axis=2),axis=1)*(1+2.0**-40)
        col=np.max(np.sum(mags,axis=1),axis=1)*(1+2.0**-40)
        norm_bound=1+math.ceil(float(np.max(row*col))*(1+2.0**-40))
        del mags,row,col
        if width_squared<11*r_squared*norm_bound:
            raise ValueError("raw ring PSD sufficient bound fails before entropy")
        self.norm_bound=norm_bound;self.transform_error=error
        self.alpha=math.sqrt(width_squared-r_squared)
        c=9*r_squared
        self.b=np.empty((self.d//2,self.k,self.k),dtype=np.complex128)
        for start in range(0,self.d//2,16):
            stop=min(self.d//2,start+16);v=self.t[start:stop]
            gram=v.conj().transpose(0,2,1)@v+np.eye(self.k)
            eigen,u=np.linalg.eigh(gram)
            residual=(width_squared-r_squared)-c*eigen
            if np.any(eigen<=0) or np.any(residual<=0):
                raise ValueError("numerical spectral factor failed positivity")
            scale=c/(self.alpha+np.sqrt(residual))
            self.b[start:stop]=(u*scale[:,None,:])@u.conj().transpose(0,2,1)
            if progress and stop%128==0:progress("factor",stop,self.d//2)

    def certificate(self):
        return dict(method="ring Fourier low-rank SampleF with discrete Gaussian rounding",
            coefficient_dimension=self.rows*self.d,frequency_count=self.d//2,
            largest_factor_dimension=self.k,raw_norm_squared_upper=self.norm_bound,
            raw_psd_sufficient_condition=True,transform_component_error_upper=self.transform_error,
            stored_complex_coefficients=int(self.t.size+self.b.size),
            dense_covariance_allocated=False,continuous_ticket_bits=52,
            total_TV_certified=False,security_claim="none",backend_admitted=False)

    def sample(self,source,*,tail_bits=256,mass_bits=320):
        g=normal((self.rows,self.d),source)
        gh=np.fft.fft(g*self.twist,axis=-1)[:,:self.d//2].T
        out=np.empty_like(gh)
        for start in range(0,self.d//2,32):
            stop=min(self.d//2,start+32);t=self.t[start:stop];v=gh[start:stop]
            inner=-np.einsum("frk,fr->fk",t.conj(),v[:,:self.top])+v[:,self.top:]
            correction=np.einsum("fij,fj->fi",self.b[start:stop],inner)
            out[start:stop,:self.top]=self.alpha*v[:,:self.top]+np.einsum("frk,fk->fr",t,correction)
            out[start:stop,self.top:]=self.alpha*v[:,self.top:]-correction
        full=np.concatenate((out.T,out.T[:,::-1].conj()),axis=1)
        values=(np.fft.ifft(full,axis=1)*self.twist.conj()).real/math.sqrt(2*np.pi)
        if not np.all(np.isfinite(values)): raise SamplingAbort("continuous arithmetic failure")
        return round_gaussian(values,self.r_squared,source,tail_bits=tail_bits,mass_bits=mass_bits)
