"""Yu full-basis bridge checks under the prescribed WSL Sage environment.

Public tiny profile: q=3, n=1, AP09 m1=d=3, m2=12, C'=8;
gamma^2=32768, delta^2=67108864, K=32, epsilon_bits=16, default OnlineOptions.
The complete path has dimensions 15 -> 17 -> 19 and is NOT secure.
Only lattice blocks are in scope (no identity/message encoding or ROM).
Real sampling uses OS entropy; no generated seed, key, or geometry is saved.
The root fixture fixes A1 to full rank to require successful algebra tests;
it is NOT an AP09 public-distribution experiment. Separate failure injection
tests check guards and propagation and do not count as real sampling runs.
"""

from dataclasses import replace
from fractions import Fraction
from types import SimpleNamespace

import pytest

pytest.importorskip("sage.all", reason="Use WSL ~/miniconda3/envs/sage/bin/python")
from sage.all import QQ, ZZ, matrix

from ibme.core.randomness import SecureRandom
from experiments.research.candidates.yu import trapdoors as yu
from experiments.research.chkp_basis import KernelBasis, ModMatrixReference
from experiments.research.chkp_basis_reduce import reduce_basis
from experiments.research.chkp_genbasis import AP09Parameters, genbasis_certificate
from experiments.research.chkp_gpv import CHKPGPVSampler
from experiments.research.gaussian_reference import SamplingAbort
from experiments.research.online_gaussian_reference import OnlineOptions


GAMMA_SQUARED, DELTA_SQUARED, MAX_VECTORS = 32768, 67108864, 32


class NoEntropy:
    def read(self, size):
        pytest.fail("invalid input consumed entropy")


class RankPrefix:
    """Explicit nonuniform A1 fixture, followed by real random AP09 R."""

    def __init__(self):
        self.prefix = iter((1, 2, 0))
        self.tail = SecureRandom()

    def read(self, size):
        value = next(self.prefix, None)
        if value is None:
            return self.tail.read(size)
        assert size == 1
        return bytes((value,))


@pytest.fixture(scope="module")
def params():
    return AP09Parameters(n=1, q=3, random_rows=3, m1=3, m2=12, hadamard_scale=8)


@pytest.fixture(scope="module")
def root(params):
    return yu.generate_root(params, RankPrefix())


@pytest.fixture(scope="module")
def block():
    return ModMatrixReference(((1, 2),), 3)


@pytest.fixture(scope="module")
def user(root, block):
    return yu.issue_basis(root, block, GAMMA_SQUARED, MAX_VECTORS, rng=SecureRandom())


def check_complete(basis, dimension):
    assert isinstance(basis, KernelBasis)
    assert basis.public.ncols == dimension
    a, s = matrix(ZZ, basis.public.rows), matrix(ZZ, basis.basis_rows)
    assert all(value % basis.public.q == 0 for value in (a * s).list())
    assert abs(s.det()) == basis.public.q ** basis.public.nrows
    assert basis.security_claim == "none"


def test_real_ap09_root_is_complete(params, root):
    check_complete(root, 15)
    # This public, parameter-only certificate is not a secret geometry dump.
    cert = genbasis_certificate(params)
    assert not cert["near_uniform_bound_nonvacuous"]
    assert not yu.backend_admitted and not yu.parameters_are_formal


def test_generate_root_calls_ap09_once(params, monkeypatch):
    original, calls = yu.gen_basis, []

    def spy(p, *, rng):
        calls.append(p)
        return original(p, rng=rng)

    monkeypatch.setattr(yu, "gen_basis", spy)
    check_complete(yu.generate_root(params, RankPrefix()), 15)
    assert calls == [params]


def test_real_randomized_user_is_complete_and_not_plain_extension(root, block, user):
    check_complete(user, 17)
    assert user.public == root.public.append(block)
    assert user.basis_rows != yu.ext_basis(root, block).basis_rows
    # The shared algebra type's flag does not record algorithm provenance.
    assert user.is_randomized is False


@pytest.mark.parametrize("values", [(0, 0), (1, 2), (2, 1)])
def test_real_zero_preimages_integer_equation_and_fig5_norm(user, values):
    block = ModMatrixReference((values,), 3)
    signature = yu.sample_zero(user, block, DELTA_SQUARED, rng=SecureRandom())
    public = user.public.append(block)
    assert len(signature) == 19
    assert all(type(value) is int for value in signature)
    assert all(sum(a * x for a, x in zip(row, signature)) % 3 == 0 for row in public.rows)
    assert 0 < sum(x * x for x in signature) <= DELTA_SQUARED * 19


def test_raw_randbasis_and_explicit_deterministic_postprocessor(root, block, monkeypatch):
    def no_lll(*args, **kwargs):
        pytest.fail("postprocess=False called LLL")

    monkeypatch.setattr(yu, "reduce_basis", no_lll)
    raw = yu.issue_basis(root, block, GAMMA_SQUARED, MAX_VECTORS,
                         rng=SecureRandom(), postprocess=False)
    check_complete(raw, 17)
    expected = reduce_basis(raw).basis
    calls = []

    def fixed_randomized(self, *, rng):
        calls.append(self.sampler.width_squared)
        return SimpleNamespace(basis=raw)

    def fixed_lll(value):
        assert value == raw
        return SimpleNamespace(basis=expected)

    monkeypatch.setattr(yu.CHKPRandBasis, "sample", fixed_randomized)
    monkeypatch.setattr(yu, "reduce_basis", fixed_lll)
    actual = yu.issue_basis(root, block, GAMMA_SQUARED, MAX_VECTORS, rng=NoEntropy())
    assert actual == expected and calls == [QQ(GAMMA_SQUARED)]
    # Postprocessing does not change the lattice; the fixed delta is admitted.
    assert CHKPGPVSampler(yu.ext_basis(actual, block), DELTA_SQUARED,
                          epsilon_bits=16).width_squared == DELTA_SQUARED


@pytest.mark.parametrize("width", [True, 0, -1, 32768.0, object(), "1e999999", "1/0"])
@pytest.mark.parametrize("operation", ["issue", "sample"])
def test_invalid_width_rejected_before_entropy(root, block, width, operation):
    with pytest.raises(ValueError):
        if operation == "issue":
            yu.issue_basis(root, block, width, MAX_VECTORS, rng=NoEntropy())
        else:
            yu.sample_zero(root, block, width, rng=NoEntropy())


@pytest.mark.parametrize("kwargs", [
    {"max_vectors": True}, {"max_vectors": 16}, {"max_vectors": 4097},
    {"max_vectors": 32.0}, {"postprocess": 1}, {"postprocess": "yes"},
    {"epsilon_bits": True}, {"epsilon_bits": 1}, {"epsilon_bits": 16.0},
    {"options": {}}, {"rng": object()},
])
def test_issue_strict_parameters(root, block, kwargs):
    arguments = dict(max_vectors=MAX_VECTORS, rng=NoEntropy())
    arguments.update(kwargs)
    with pytest.raises(ValueError):
        yu.issue_basis(root, block, GAMMA_SQUARED, **arguments)


@pytest.mark.parametrize("bad", [
    None, ((1, 2),), ModMatrixReference(((1, 2),), 5),
    ModMatrixReference(((1,),), 3), ModMatrixReference(((1, 2, 0),), 3),
    ModMatrixReference(((1, 2), (0, 1)), 3),
    ModMatrixReference(((1,) * 15,), 3),
])
def test_block_shape_modulus_and_gadget_width(root, bad):
    for operation in (
        lambda: yu.issue_basis(root, bad, GAMMA_SQUARED, MAX_VECTORS, rng=NoEntropy()),
        lambda: yu.sample_zero(root, bad, DELTA_SQUARED, rng=NoEntropy()),
    ):
        with pytest.raises(ValueError):
            operation()


@pytest.mark.parametrize("rows", [(), ((True, 1),), ((3, 1),), ((1.0, 2),), ((1,),)])
def test_forged_block_revalidated_before_sampling(root, rows):
    bad = object.__new__(ModMatrixReference)
    object.__setattr__(bad, "q", 3)
    object.__setattr__(bad, "rows", rows)
    with pytest.raises(ValueError):
        yu.sample_zero(root, bad, DELTA_SQUARED, rng=NoEntropy())


@pytest.mark.parametrize("corruption", ["sublattice", "equation"])
def test_forged_parent_rechecks_containment_and_completeness(root, block, corruption):
    rows = [list(row) for row in root.basis_rows]
    if corruption == "sublattice":
        rows = [[2 * value for value in row] for row in rows]
    else:
        rows[0][0] += 1  # A1[0] is 1 in the required-success fixture.
    bad = object.__new__(KernelBasis)
    object.__setattr__(bad, "public", root.public)
    object.__setattr__(bad, "basis_rows", tuple(map(tuple, rows)))
    with pytest.raises(ValueError, match="complete kernel|A S"):
        yu.sample_zero(bad, block, DELTA_SQUARED, rng=NoEntropy())


def test_root_strict_parameters_and_odd_modulus(params):
    for bad in (None, {}, replace(params, q=2), object()):
        with pytest.raises(ValueError):
            yu.generate_root(bad, NoEntropy())
    with pytest.raises(ValueError, match="rng"):
        yu.generate_root(params, object())


def test_ap09_rank_abort_has_no_retry(params):
    class Zero:
        calls = 0

        def read(self, size):
            self.calls += 1
            return bytes(size)

    rng = Zero()
    with pytest.raises(SamplingAbort, match="rank failure"):
        yu.generate_root(params, rng)
    assert rng.calls == params.n * params.m1


@pytest.mark.parametrize("stage", ["randbasis", "lll"])
def test_issue_stage_failure_propagates_once(root, block, user, monkeypatch, stage):
    calls = []
    error = SamplingAbort("injected finite-resource abort")

    def fail(*args, **kwargs):
        calls.append(1)
        raise error

    if stage == "randbasis":
        monkeypatch.setattr(yu.CHKPRandBasis, "sample", fail)
    else:
        monkeypatch.setattr(yu.CHKPRandBasis, "sample", lambda *a, **k: SimpleNamespace(basis=user))
        monkeypatch.setattr(yu, "reduce_basis", fail)
    with pytest.raises(SamplingAbort) as caught:
        yu.issue_basis(root, block, GAMMA_SQUARED, MAX_VECTORS, rng=NoEntropy())
    assert caught.value is error and len(calls) == 1


@pytest.mark.parametrize("operation", ["root", "issue", "sample"])
def test_entropy_failure_propagates_once(params, root, block, user, operation):
    class Broken:
        calls = 0

        def read(self, size):
            self.calls += 1
            raise OSError("entropy unavailable")

    rng = Broken()
    with pytest.raises(OSError, match="entropy unavailable"):
        if operation == "root":
            yu.generate_root(params, rng)
        elif operation == "issue":
            yu.issue_basis(root, block, GAMMA_SQUARED, MAX_VECTORS, rng=rng)
        else:
            yu.sample_zero(user, block, DELTA_SQUARED, rng=rng)
    assert rng.calls == 1


@pytest.mark.parametrize("kind", ["zero", "outlier", "equation", "length", "float", "bool"])
def test_sample_output_guards_without_retry(user, block, monkeypatch, kind):
    values = [0] * 19
    error = ArithmeticError
    if kind == "zero":
        error = SamplingAbort
    elif kind == "outlier":
        values[0], error = 3 * 10**8, SamplingAbort
    elif kind == "equation":
        values[0] = 1
    elif kind == "length":
        values.pop()
    elif kind == "float":
        values[0] = 3.0
    else:
        values[0] = True
    calls = []

    def sample(self, syndrome, *, rng):
        assert syndrome == (0,)
        calls.append(1)
        return tuple(values)

    monkeypatch.setattr(yu.CHKPGPVSampler, "sample", sample)
    with pytest.raises(error):
        yu.sample_zero(user, block, DELTA_SQUARED, rng=NoEntropy())
    assert len(calls) == 1


def test_signed_integer_coordinates_are_not_reduced_mod_q(user, block, monkeypatch):
    expected = (-3,) + (0,) * 18
    monkeypatch.setattr(yu.CHKPGPVSampler, "sample", lambda *a, **k: expected)
    assert yu.sample_zero(user, block, DELTA_SQUARED, rng=NoEntropy()) == expected


def test_toy_public_q_multiple_is_an_explicit_forgery(root, block):
    # These tiny parameters make Fig. 5's public algebra/norm predicate
    # forgeable for EVERY identity/message block; do not hide it with hashing.
    public = root.public.append(block).append(block)
    forgery = (public.q,) + (0,) * (public.ncols - 1)
    assert all(sum(a * x for a, x in zip(row, forgery)) % public.q == 0
               for row in public.rows)
    assert 0 < sum(x * x for x in forgery) <= DELTA_SQUARED * public.ncols
    assert yu.security_claim == "none"


def test_oversized_extension_and_lll_rejected_before_entropy(root, monkeypatch):
    # Public, algebra-only fixtures for resource rejection, not secret TrapGen.
    wide = yu.ext_basis(root, ModMatrixReference(((0,) * 48,), 3))
    block = ModMatrixReference(((1, 2),), 3)
    with pytest.raises(ValueError, match="LLL dimension cap"):
        yu.issue_basis(wide, block, GAMMA_SQUARED, 100, rng=NoEntropy())
    widest = yu.ext_basis(root, ModMatrixReference(((0,) * 177,), 3))
    with pytest.raises(ValueError, match="dimension resource limit"):
        yu.sample_zero(widest, block, DELTA_SQUARED, rng=NoEntropy())


def test_no_adaptive_width_or_hardcap_relaxation(root, block, user):
    with pytest.raises(ValueError, match="Width fails"):
        yu.issue_basis(root, block, Fraction(1, 2), MAX_VECTORS, rng=NoEntropy())
    with pytest.raises(ValueError, match="Scalar squared width"):
        yu.sample_zero(user, block, 10**15, rng=NoEntropy())
    with pytest.raises(ValueError, match="Public scalar tape exceeds resource budget"):
        yu.sample_zero(user, block, DELTA_SQUARED, rng=NoEntropy(),
                       options=OnlineOptions(max_tape_bytes=1))
