"""Public native reuse checks; no complete HIBE or security assertion."""

from copy import deepcopy
from pathlib import Path
import subprocess
import pytest

from experiments.research.reuse.qfall_bridge import public_fixture, run_fixture, validate_root


@pytest.mark.parametrize("args", [(True,17,8),(0,17,8),(5,17,8),(1,1,8),(1,2**41,8),
                                  (1,17,True),(1,17,0),(1,17,97),(4,2**40,96)])
def test_fixture_inputs_are_bounded_before_native_execution(args):
    with pytest.raises(ValueError):
        public_fixture(*args, seed=b"test")


def test_fixture_distribution_recipe_and_replay():
    f = public_fixture(2,257,16,seed=b"public-recipe")
    assert f == public_fixture(2,257,16,seed=b"public-recipe")
    assert len(f["r"]) == 16 and all(len(row)==18 for row in f["r"])
    assert set(x for row in f["r"] for x in row) <= {-1,0,1}
    assert f["public_test_fixture"] is True


def _sage():
    pytest.importorskip("sage.all", reason="native reuse requires prescribed WSL Sage")


def _native():
    _sage()
    root=Path(__file__).resolve().parents[1]
    binary=root/"test-results/qfall-target/release/ibme-qfall-public-fixture"
    if not binary.exists():
        pytest.skip("explicit qFALL native build required; this is not a pass")
    return binary


@pytest.mark.parametrize("n,q,m_bar", [(1,17,8),(2,257,16),(1,65537,24)])
def test_real_qfall_basis_is_complete_and_reproducible(n,q,m_bar):
    binary=_native()
    f=public_fixture(n,q,m_bar,seed=b"qfall-completeness")
    a=run_fixture(f,binary)
    assert a==run_fixture(f,binary)
    b=validate_root(f,a)
    assert b.public.q==q and b.public.ncols==m_bar+n*(q-1).bit_length()


@pytest.mark.parametrize("change", ["relation","basis","parameter","admission","integer","shape"])
def test_native_output_cannot_skip_independent_algebra_checks(change):
    binary=_native()
    f=public_fixture(1,17,8,seed=b"native-binding")
    output=run_fixture(f,binary)
    if change=="relation": output["a"][0][0]=str((int(output["a"][0][0])+1)%17)
    elif change=="basis": output["basis"][0][0]=str(int(output["basis"][0][0])+1)
    elif change=="parameter": output["n"]=2
    elif change=="admission": output["backend_admitted"]=True
    elif change=="integer": output["basis"][0][0]="00"
    else: output["basis"].pop()
    with pytest.raises(ValueError): validate_root(f,output)


@pytest.mark.parametrize("field,value", [("public_test_fixture",False),("q",1),("m_bar",999)])
def test_rust_frontend_rejects_bad_fixture_before_matrix_construction(field,value):
    binary=_native()
    f=public_fixture(1,17,8,seed=b"bad-input")
    f[field]=value
    with pytest.raises(RuntimeError): run_fixture(f,binary)


def test_sage_native_coset_sampling_and_seeded_replay():
    _sage()
    from experiments.research.chkp_basis import ModMatrixReference,complete_kernel_basis
    from experiments.research.reuse.sage_native_gpv import NativePublicGPV
    b=complete_kernel_basis(ModMatrixReference([[1,2]],17))
    s=NativePublicGPV(b,2**18,public_test_fixture=True)
    targets=[(i%17,) for i in range(256)]
    first=s.sample_batch(targets,test_seed=19)
    assert first.preimages==s.sample_batch(targets,test_seed=19).preimages
    assert len(first.preimages)==256
    assert s.certificate()["whole_sampler_tv_upper"] is None
    assert s.certificate()["production_random_api"] is False


@pytest.mark.parametrize("case", ["private","dimension","width","target","count","seed"])
def test_native_comparison_rejects_invalid_inputs(case):
    _sage()
    from sage.all import identity_matrix,ZZ
    from experiments.research.chkp_basis import ModMatrixReference,complete_kernel_basis
    from experiments.research.reuse.sage_native_gpv import NativePublicGPV
    b=complete_kernel_basis(ModMatrixReference([[1,0]],17))
    if case=="private":
        with pytest.raises(ValueError): NativePublicGPV(b,512)
        return
    if case=="dimension":
        large=complete_kernel_basis(ModMatrixReference([[1]+[0]*256],17))
        with pytest.raises(ValueError): NativePublicGPV(large,2**24,public_test_fixture=True)
        return
    if case=="width":
        with pytest.raises(ValueError): NativePublicGPV(b,1,public_test_fixture=True)
        return
    s=NativePublicGPV(b,2**18,public_test_fixture=True)
    with pytest.raises(ValueError):
        s.sample_batch([(17,)] if case=="target" else [(0,)]*257 if case=="count" else [(0,)],
                       test_seed=True if case=="seed" else 1)
    assert s.draws==0


def test_native_randbasis_abort_is_not_retried(monkeypatch):
    _sage()
    from experiments.research.chkp_basis import ModMatrixReference,complete_kernel_basis
    from experiments.research.reuse.sage_native_gpv import NativePublicGPV
    from experiments.research.gaussian_reference import SamplingAbort
    b=complete_kernel_basis(ModMatrixReference([[1,0]],17))
    s=NativePublicGPV(b,2**18,public_test_fixture=True)
    calls=[]
    def fail(target):
        calls.append(target)
        raise SamplingAbort("forced native draw failure")
    monkeypatch.setattr(s,"_draw",fail)
    with pytest.raises(SamplingAbort): s.randomize_public_basis(test_seed=4,max_vectors=8)
    assert len(calls)==1


def test_native_sigma_conversion_and_coset_center_have_correct_moments():
    _sage()
    import math
    from experiments.research.chkp_basis import ModMatrixReference,complete_kernel_basis
    from experiments.research.reuse.sage_native_gpv import NativePublicGPV
    basis=complete_kernel_basis(ModMatrixReference([[1]],131))
    sampler=NativePublicGPV(basis,2**24,public_test_fixture=True)
    values=[]
    for i in range(32):
        batch=sampler.sample_batch([(124,)]*256,test_seed=400+i)
        values.extend(x[0] for x in batch.preimages)
    variance=2**24/(2*math.pi)
    mean=sum(values)/len(values)
    observed=sum((x-mean)**2 for x in values)/len(values)
    assert abs(mean)<5*math.sqrt(variance/len(values))
    assert 0.9<observed/variance<1.1


def test_public_code_chain_combines_real_components_without_claiming_a_backend():
    binary=_native()
    from experiments.research.reuse.public_chain_probe import one_probe
    report=one_probe(17,8,binary)
    assert report["dimensions"]==dict(root=13,parent=26,leaf=39)
    assert report["preimage_equations_verified"]==256
    assert report["parent_full_basis_randomized"]
    assert report["phase_failures"]>0  # predetermined tiny negative control
    assert not report["fixed_leaf_cache_used"] and not report["full_hibe_implemented"]
