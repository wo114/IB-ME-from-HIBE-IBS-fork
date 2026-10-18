"""Wide-q A3 gadget: complete lattice, literal sampling and hard boundaries."""

from dataclasses import replace
from fractions import Fraction
from itertools import count

import pytest

pytest.importorskip("sage.all", reason="use prescribed WSL ~/miniconda3/envs/sage")
from sage.all import ZZ, matrix, previous_prime

from ibme.core.errors import InvalidParameterError, RandomnessError
from ibme.core.randomness import DeterministicRandom, SecureRandom
from ibme.lattice.chkp.joint_parameters import smoothing_factor
from ibme.lattice.matrix_sampling import prime_gadget as module
from ibme.lattice.matrix_sampling.prime_gadget import PrimeGadgetSampler, prime_gadget_kernel
from ibme.lattice.matrix_sampling.scalar import MatrixFiniteOptions


Q77 = 149785881362170169333047
OPTIONS = MatrixFiniteOptions(tail_bits=192, gaussian_abort_bits=192,
    mass_bits=320, precision_bits=384, max_uniform_trials=256)


def plan(rows=3, q=Q77, options=OPTIONS):
    return PrimeGadgetSampler(rows, q, 20*smoothing_factor((q-1).bit_length(), 192),
                              epsilon_bits=192, options=options)


class NoEntropy:
    def __init__(self): self.calls = 0
    def read(self, count):
        self.calls += 1
        raise AssertionError("invalid input consumed private entropy")


@pytest.mark.parametrize("q", [3, 17, 2**61-1, Q77, 2**127-1])
def test_kernel_is_complete_with_the_declared_column_convention(q):
    kernel = prime_gadget_kernel(q)
    b = matrix(ZZ, kernel.basis_rows)
    a = matrix(ZZ, kernel.public.rows)
    assert abs(b.det()) == q
    assert all(int(x) % q == 0 for x in (a*b).list())
    assert b.nrows() == b.ncols() == (q-1).bit_length()


@pytest.fixture(scope="module")
def sampler():
    return plan()


def test_wide_q_product_coset_has_real_gaussian_samples_and_system_entropy(sampler):
    targets = (0, 1, Q77-1)
    for rng in (DeterministicRandom(b"A3-public-q77-TEST"), None):
        output = sampler.sample(targets, rng=rng)
        assert len(output) == sampler.rows*sampler.k
        for row, target in enumerate(targets):
            assert sum(2**i*output[row*sampler.k+i] for i in range(sampler.k)) % Q77 == target


def test_largest_supported_modulus_samples_without_a_product_basis():
    q = int(previous_prime(2**256))
    sampler = plan(rows=1, q=q)
    output = sampler.sample((q-1,), rng=DeterministicRandom(b"A3-public-q256-TEST"))
    assert sum(2**i*x for i,x in enumerate(output)) % q == q-1
    assert sampler.public_certificate()["public_kernel_entries"] == 256**2


def test_certificate_accounts_for_every_block_and_abort(sampler):
    certificate = sampler.public_certificate()
    assert Fraction(certificate["tv_upper_including_abort"]) == min(
        Fraction(1), 3*Fraction(certificate["block"]["tv_upper_including_abort"]))
    assert certificate["random_tape_bytes"] == 3*certificate["block"]["random_tape_bytes"]
    assert certificate["expanded_product_basis_entries"] == 0
    assert certificate["complete_HIBE_domain_admitted"] is False
    assert (certificate["security_claim"], certificate["backend_admitted"],
            certificate["parameters_are_formal"]) == ("none", False, False)


@pytest.mark.parametrize("targets", [(0, 1), (0, 1, 2, 3), (0, 1, Q77),
    (0, -1, 2), (0, True, 2), (0, 1.0, 2), b"abc", None])
def test_invalid_syndromes_are_rejected_before_entropy(sampler, targets):
    source = NoEntropy()
    with pytest.raises(ValueError): sampler.sample(targets, rng=source)
    assert source.calls == 0


def test_unbounded_syndrome_iterator_is_consumed_only_to_dimension_boundary(sampler):
    seen = []
    def infinite():
        for value in count():
            seen.append(value)
            yield value
    with pytest.raises(ValueError, match="dimension"):
        sampler.sample(infinite(), rng=NoEntropy())
    assert len(seen) == sampler.rows+1


@pytest.mark.parametrize("q", [True, 3.0, 1, 4, 9, 2**256+1])
def test_bad_moduli_are_rejected_before_kernel_allocation(monkeypatch, q):
    def forbidden(*args, **kwargs): raise AssertionError("invalid q allocated a kernel")
    monkeypatch.setattr(module, "matrix", forbidden)
    with pytest.raises(ValueError): prime_gadget_kernel(q)


def test_whole_call_tape_gate_cannot_be_satisfied_by_a_single_block_budget(sampler):
    options = replace(OPTIONS, max_tape_bytes=sampler.block.random_tape_bytes)
    with pytest.raises(ValueError, match="whole-call tape"):
        plan(options=options)


def test_dimension_gate_precedes_kernel_or_sampler_allocation(monkeypatch):
    def forbidden(*args, **kwargs): raise AssertionError("oversize product prepared a kernel")
    monkeypatch.setattr(module, "prime_gadget_kernel", forbidden)
    with pytest.raises(ValueError, match="coordinate resource"):
        plan(rows=16384, q=int(previous_prime(2**256)))


def test_bad_entropy_is_an_error_without_a_substitute_sample(sampler):
    class ShortEntropy:
        def read(self, count): return b""
    with pytest.raises(RandomnessError): sampler.sample((0, 1, Q77-1), rng=ShortEntropy())


def test_preparing_public_geometry_constructs_no_private_trapdoor(monkeypatch):
    from ibme.lattice.matrix_sampling import mp12_structured as tool
    def forbidden(*args, **kwargs): raise AssertionError("public plan performed private work")
    monkeypatch.setattr(SecureRandom, "read", forbidden)
    monkeypatch.setattr(tool.StructuredTrapdoor, "__post_init__", forbidden)
    monkeypatch.setattr(tool.StructuredPreimageSampler, "__init__", forbidden)
    assert plan(rows=4096).public_certificate()["output_coordinates"] == 4096*77


def test_q77_gadget_support_does_not_admit_existing_hibe_or_wire():
    from ibme.hibe.mp12_structured.params import StructuredHIBEParams
    from ibme.lattice.matrix_sampling.mp12_structured import gadget_block
    with pytest.raises(ValueError, match="outside resource range"): gadget_block(Q77)
    with pytest.raises(InvalidParameterError): StructuredHIBEParams(q=Q77)
