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
