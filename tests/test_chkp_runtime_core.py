"""Exact core and explicit resource-profile checks; small public test inputs."""
import pytest
pytest.importorskip("sage.all")
from sage.all import QQ, ZZ, matrix
from ibme.core.randomness import DeterministicRandom
from ibme.lattice.chkp.basis import ModMatrixReference, gram_schmidt_squared_lengths
from ibme.lattice.chkp.root_basis import private_root_basis
from ibme.lattice.chkp.extended_gpv import ExtendedGPV
from ibme.lattice.chkp.finite_gaussian import FirstFiniteOptions
from ibme.lattice.chkp.tobasis import canonical_basis


@pytest.mark.parametrize("q", [2, 3, 17, 257])
@pytest.mark.parametrize("n", [1, 2])
def test_private_binary_gadget_complete_kernel_and_public_gs(q, n):
    k, mbar = (q-1).bit_length(), 3
    ab = [[(i*7+j+1) % q for j in range(mbar)] for i in range(n)]
    trap = [[((i+2*j) % 3)-1 for j in range(n*k)] for i in range(mbar)]
    result = private_root_basis(ab, trap, q)
    a, b = matrix(ZZ, result.public.rows), matrix(ZZ, result.basis_rows)
    assert all(x % q == 0 for x in (a*b).list())
    assert abs(b.det()) == q**n
    assert max(gram_schmidt_squared_lengths(result.basis_rows)) <= 10*(1+sum(x*x for r in trap for x in r))


def test_implicit_extended_sampler_syndromes_and_no_invalid_entropy():
    basis = private_root_basis([[2, 4]], [[0]*5,[0]*5], 17)
    extension = ModMatrixReference(((3, 7),), 17)
    options = FirstFiniteOptions(tail_bits=32, mass_bits=64, precision_bits=128,
                                 gaussian_abort_bits=32, max_uniform_trials=48)
    sampler = ExtendedGPV(basis, extension, 2**16, epsilon_bits=16, options=options)
    rng = DeterministicRandom(b"public-test/chkp/implicit-extension")
    for y in (0, 1, 16):
        x = sampler.sample((y,), rng=rng)
        assert len(x) == basis.public.ncols+2
        assert sum(a*v for a,v in zip(sampler.basis.public.rows[0],x)) % 17 == y
    class NoEntropy:
        def read(self, n):
            raise AssertionError("invalid syndrome consumed entropy")
    for bad in [(True,), (17,), (-1,), (), (0, 1), b"0"]:
        with pytest.raises(ValueError):
            sampler.sample(bad, rng=NoEntropy())
    assert 0 <= sampler.tv_upper < 1


def test_promoted_historical_imports_are_same_objects():
    from experiments.research.chkp_basis import KernelBasis as old
    from ibme.lattice.chkp.basis import KernelBasis as current
    from experiments.research.first_suite.identity import ROHIBEContext as old_context
    from ibme.lattice.chkp.identity import ROHIBEContext as current_context
    assert old is current
    assert old_context is current_context


def test_tobasis_explicit_resource_limit_is_checked():
    basis = private_root_basis([[1]], [[0]*5], 17)
    for budget in (True, 0, 513, basis.public.ncols-1):
        with pytest.raises(ValueError):
            canonical_basis(basis, max_dimension=budget)
