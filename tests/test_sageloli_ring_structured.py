"""Small, independently computable checks for the structured target engine."""
import math
import numpy as np
import pytest
from ibme.core.randomness import DeterministicRandom
from experiments.research.candidates.sageloli.ring import codec
from experiments.research.candidates.sageloli.ring.params import published,small,RingParams
from experiments.research.candidates.sageloli.ring.gaussian import ByteSource,round_gaussian,ternary,_exp_approx
from experiments.research.candidates.sageloli.ring.spectral import FourierPlan,enclosed_transform,twiddles


@pytest.mark.parametrize("k",[65,153])
def test_wide_modulus_coefficients_roundtrip_and_spare_bits_rejected(k):
    q=3**k;bits=q.bit_length();a=np.array([[0,1,q-1,2**80]],dtype=object)
    wire=codec.tensor(a,a.shape,bits)
    assert np.array_equal(codec.tensor_from(wire,a.shape,bits,modulus=q),a)
    with pytest.raises(ValueError):codec.tensor_from(wire+b"x",a.shape,bits,modulus=q)
    bad=bytearray(wire);bad[4+4*a.ndim]=255
    with pytest.raises(ValueError):codec.tensor_from(bytes(bad),a.shape,bits,modulus=q)


@pytest.mark.parametrize("bits",[8,16,32,64])
def test_signed_tensor_boundaries(bits):
    a=np.array([-(2**(bits-1)),2**(bits-1)-1],dtype=np.int64)
    wire=codec.tensor(a,(2,),bits,signed=True)
    assert np.array_equal(codec.tensor_from(wire,(2,),bits,signed=True),a)
    with pytest.raises(ValueError):codec.tensor(np.array([1.5]),(1,),bits,signed=True)


def test_frame_parameters_and_duplicates_are_strict():
    p=small();raw=codec.params_bytes(p)
    assert codec.params_from(raw)==p
    with pytest.raises(ValueError):codec.params_from(raw[:-1]+b',"d":4}')
    framed=codec.frame(b"test",[b"x",raw])
    assert codec.unframe(framed,b"test",2)==(b"x",raw)
    for bad in [framed[:-1],framed+b"x",b"v2"+framed]:
        with pytest.raises(ValueError):codec.unframe(bad,b"test",2)


@pytest.mark.parametrize("name,k,logid,logsign",[("I",65,20.65344655,38.91896454),("II",153,21.27494034,40.16194759)])
def test_published_widths_reproduce_appendix_formula(name,k,logid,logsign):
    p=published(name)
    assert p.d==2048 and p.k==k and p.q==3**k
    assert abs(math.log2(p.identity_width_squared)/2-logid)<1e-7
    assert abs(math.log2(p.signature_width_squared)/2-logsign)<1e-7
    assert RingParams.from_record(p.record())==p


@pytest.mark.parametrize("d",[4,8,32])
def test_enclosed_negacyclic_transform_matches_direct_interval_evaluation(d):
    from sage.all import ComplexIntervalField
    a=np.arange(2*3*d,dtype=np.int64).reshape(2,3,d)%17-8
    result,error=enclosed_transform(a,twiddles(d));f=ComplexIntervalField(128)
    for i in range(2):
        for j in range(3):
            for h in range(d):
                root=(-f.gen()*f.pi()*(2*h+1)/d).exp()
                exact=sum(int(x)*root**z for z,x in enumerate(a[i,j]))
                delta=exact-f(result[i,j,h])
                assert delta.real().abs().upper()<error
                assert delta.imag().abs().upper()<error


def test_gaussian_exponent_fast_guard_against_directed_intervals():
    from sage.all import RealIntervalField
    x=np.linspace(0,512,2049);out=_exp_approx(x);f=RealIntervalField(128)
    for a,b in zip(x,out):
        reference=(-f(float(a))).exp()
        assert (reference-f(float(b))).abs().upper()<2**-24


def test_ternary_draws_full_digits_and_modular_syndrome():
    source=ByteSource(DeterministicRandom(b"target ternary math"))
    q=3**9;target=np.array([0,1,2,3,q-1],dtype=object)
    x=ternary(target,9,16,source)
    assert all((sum(int(x[j,h])*3**j for j in range(9))-int(u))%q==0 for h,u in enumerate(target))
    assert len(set(int(v) for v in x.flat))>4


def test_rounding_has_gaussian_variance_at_noninteger_centers():
    source=ByteSource(DeterministicRandom(b"round Gaussian QA"))
    center=np.full(12000,0.375)
    x=round_gaussian(center,16,source)
    assert abs(float(x.mean())-.375)<.08
    assert abs(float(x.var())-16/(2*np.pi))<.14


def test_low_rank_factor_matches_full_dense_covariance_and_uses_bound():
    t=np.arange(3*2*4,dtype=np.int64).reshape(3,2,4)%5-2
    plan=FourierPlan(t,2**20,16)
    for f in range(2):
        tt=plan.t[f];j=np.vstack((-tt,np.eye(2)))
        factor=plan.alpha*np.eye(5)-j@plan.b[f]@j.conj().T
        target=(2**20-16)*np.eye(5)-144*j@j.conj().T
        assert np.max(np.abs(factor@factor.conj().T-target))<1e-7
    assert plan.certificate()["dense_covariance_allocated"] is False
    with pytest.raises(ValueError):FourierPlan(t,100,16)


def test_spectral_draw_matches_small_dense_gaussian_moments():
    plan=FourierPlan(np.ones((1,1,4),dtype=np.int64),2**12,16)
    source=ByteSource(DeterministicRandom(b"Fourier Gaussian QA"))
    draws=np.array([plan.sample(source).reshape(-1) for _ in range(1500)])
    # J=[-C(1+X+X^2+X^3); I] with column-action negacyclic C.
    from experiments.research.candidates.sageloli.backend import _expand_ring_matrix
    t=np.array(_expand_ring_matrix((((1,1,1,1),),),4),dtype=np.float64)
    j=np.vstack((-t,np.eye(4)));expected=(2**12*np.eye(8)-144*j@j.T)/(2*np.pi)
    assert np.max(np.abs(draws.mean(axis=0)))<3
    assert np.max(np.abs(np.cov(draws.T)-expected))<80
