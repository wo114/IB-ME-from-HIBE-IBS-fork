"""Explicit native-engine checks; run after building in prescribed WSL Sage."""
import numpy as np
import pytest
from experiments.research.candidates.sageloli.ring.native import Library,SmallMatrix,WideRow,build
from experiments.research.candidates.sageloli.algebra import ring_matvec


@pytest.fixture(scope="session")
def library(tmp_path_factory):return Library(build(tmp_path_factory.mktemp("native")))


@pytest.mark.parametrize("d",[4,8,64])
def test_small_ntt_crt_matches_independent_schoolbook(library,d):
    rng=np.random.default_rng(1234+d)
    a=rng.integers(-1000,1001,(3,2,d),dtype=np.int64)
    x=rng.integers(-30,31,(2,d),dtype=np.int64)
    handle=SmallMatrix(library,a)
    expected=ring_matvec(a.tolist(),x.tolist(),d)
    assert np.array_equal(handle.apply(x),np.array(expected,dtype=np.int64))
    handle.close()
    with pytest.raises(ValueError):handle.apply(x)


@pytest.mark.parametrize("k",[65,153])
def test_wide_flint_matches_python_integer_ring_equation(library,k):
    q=3**k;a=np.array([[q-1,2,q//2,9],[4,q-2,3,1]],dtype=object)
    x=np.array([[-11,7,0,4],[1,-2,3,-4]],dtype=np.int64)
    handle=WideRow(library,a,q)
    expected=ring_matvec((a.tolist(),),x.tolist(),4,q)[0]
    assert tuple(handle.apply(x))==expected


def test_ntt_refuses_ambiguous_crt_range(library):
    a=np.full((1,1,4),2**40,dtype=np.int64)
    handle=SmallMatrix(library,a)
    with pytest.raises(ValueError,match="range"):
        handle.apply(np.full((1,4),2**40,dtype=np.int64))
    huge=SmallMatrix(library,np.full((1,1,2048),2**62,dtype=np.int64))
    with pytest.raises(ValueError,match="range"):
        huge.apply(np.full((1,2048),2**62,dtype=np.int64))


def test_degree_2048_signed_product_crosses_single_prime_range(library):
    from sage.all import PolynomialRing,ZZ
    d=2048;rng=np.random.default_rng(2048)
    a=rng.integers(-2**20,2**20,(1,2,d),dtype=np.int64)
    x=rng.integers(-2**18,2**18,(2,d),dtype=np.int64)
    ring=PolynomialRing(ZZ,"X");X=ring.gen()
    expected=sum(ring(a[0,j].tolist())*ring(x[j].tolist()) for j in range(2))%(X**d+1)
    answer=SmallMatrix(library,a).apply(x)[0]
    assert max(abs(int(v)) for v in answer)>2013265921
    assert answer.tolist()==[int(expected[i]) for i in range(d)]
