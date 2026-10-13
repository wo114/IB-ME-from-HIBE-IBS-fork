"""State/adapter tests with explicit public algebra fixtures.

Only the issuance consumer is instrumented; these are not evidence of real
AP09/BasisDel generation or a complete positive-profile HIBE lifecycle.
"""

from dataclasses import replace
from types import SimpleNamespace
import pytest

pytest.importorskip("sage.all", reason="prescribed WSL Sage required")
from sage.all import GF, matrix
from ibme.core.errors import EncodingError, InvalidParameterError, SerializationError
from ibme.lattice.research import ModMatrixReference, SamplingAbort
from experiments.research.chkp_basis import complete_kernel_basis
from ibme.hibe.abb_rom import backend as module
from ibme.hibe.abb_rom.backend import ABBROMHIBE, ABBSamplingAbort
from ibme.hibe.abb_rom.params import ABBROMParams
from ibme.hibe.abb_rom.objects import ABBPublicKey, ABBMasterSecret, ABBLevel1Key, ABBLevel2Key
from ibme.hibe.abb_rom.key_validation import expected_matrix


class CountingEntropy:
    def __init__(self, error=None):
        self.calls = 0
        self.error = error

    def read(self, count):
        self.calls += 1
        if self.error:
            raise self.error
        return bytes(count)


@pytest.fixture
def instrumented(monkeypatch):
    params = replace(ABBROMParams(), name="abb-state-public-fixture", q=101,
        random_rows=8, root_m1=8, root_m2=36, hadamard_scale=40,
        matrix_gaussian_squared_width=16)
    public = ABBPublicKey(params, (tuple((j*j+3) % 101 for j in range(44)),), (7,))
    master = ABBMasterSecret(public, complete_kernel_basis(expected_matrix(public, ())).basis_rows)
    backend = ABBROMHIBE()
    # This fixture deliberately does not meet the complete byte-HIBE setup gate.
    monkeypatch.setattr(backend, "_oracle", lambda p: None)
    calls = []

    class PublicBasisDelFixture:
        def __init__(self, parent, transformation, width, **kwargs):
            target = matrix(GF(101), parent.public.rows) * matrix(GF(101), transformation).inverse()
            self.result = complete_kernel_basis(ModMatrixReference(target, 101))
            self.width = width

        def sample(self, *, rng=None):
            calls.append(self.width)
            if rng is not None:
                rng.read(1)
            return SimpleNamespace(basis=self.result)

    monkeypatch.setattr(module, "MatrixBasisDel", PublicBasisDelFixture)
    monkeypatch.setattr(module, "matrix_checked_lll", lambda basis, upper: basis)
    return backend, master, calls


def test_fixed_parent_and_child_survive_full_tree_restore_without_new_entropy(instrumented):
    backend, master, calls = instrumented
    rng = CountingEntropy()
    parent = backend.extract(master, b"Bob", rng=rng)
    leaf = backend.derive(parent, b"Alice", rng=rng)
    assert parent.identity == b"Bob"
    assert (leaf.parent_identity, leaf.child_identity) == (b"Bob", b"Alice")
    assert rng.calls == 2 and len(calls) == 2
    loaded = ABBMasterSecret.from_bytes(master.to_bytes())
    sentinel = CountingEntropy(error=AssertionError("fixed address used entropy"))
    reused_parent = backend.extract(loaded, b"Bob", rng=sentinel)
    reused_leaf = backend.derive(reused_parent, b"Alice", rng=sentinel)
    assert reused_leaf.to_bytes() == leaf.to_bytes()
    assert sentinel.calls == 0 and len(calls) == 2


@pytest.mark.parametrize("stage", ["parent", "child"])
@pytest.mark.parametrize("error", [SamplingAbort("injected finite abort"), OSError("injected source failure")])
def test_failed_address_is_retained_across_restore_and_cannot_reissue(instrumented, stage, error):
    backend, master, calls = instrumented
    parent = backend.extract(master, b"Bob") if stage == "child" else None
    owner = master if stage == "parent" else parent
    issue = backend.extract if stage == "parent" else backend.derive
    address = b"Carol" if stage == "parent" else b"Eve"
    cache = owner.parents if stage == "parent" else owner.children
    rng = CountingEntropy(error=error)
    with pytest.raises(ABBSamplingAbort if isinstance(error, SamplingAbort) else OSError):
        issue(owner, address, rng=rng)
    assert cache[address] is None and rng.calls == 1
    restored = type(owner).from_bytes(owner.to_bytes())
    sentinel = CountingEntropy(error=AssertionError("failed address used entropy"))
    with pytest.raises(ABBSamplingAbort, match="already failed"):
        issue(restored, address, rng=sentinel)
    assert sentinel.calls == 0


def test_parent_and_child_capacity_and_identity_limits_precede_issuance(instrumented):
    backend, master, calls = instrumented
    master.parents.update({b"a": None, b"b": None})
    rng = CountingEntropy(error=AssertionError("invalid call used entropy"))
    for invalid in (b"", b"x"*87):
        with pytest.raises(EncodingError): backend.extract(master, invalid, rng=rng)
    with pytest.raises(InvalidParameterError, match="capacity"):
        backend.extract(master, b"c", rng=rng)
    rows = complete_kernel_basis(expected_matrix(master.public_key, (b"Bob",))).basis_rows
    parent = ABBLevel1Key(master.public_key, b"Bob", rows, {b"a": None, b"b": None})
    with pytest.raises(InvalidParameterError, match="capacity"):
        backend.derive(parent, b"c", rng=rng)
    assert rng.calls == 0 and not calls


def test_mutated_parent_cache_cannot_return_a_key_for_another_address(instrumented):
    backend, master, calls = instrumented
    parent = backend.extract(master, b"Bob")
    master.parents[b"Carol"] = parent
    with pytest.raises(InvalidParameterError, match="binding"):
        backend.extract(master, b"Carol")
    with pytest.raises(SerializationError, match="binding"):
        master.to_bytes()


def test_mutated_child_cache_cannot_return_a_key_for_another_address(instrumented):
    backend, master, calls = instrumented
    parent = backend.extract(master, b"Bob")
    leaf = backend.derive(parent, b"Alice")
    parent.children[b"Eve"] = leaf
    with pytest.raises(InvalidParameterError, match="binding"):
        backend.derive(parent, b"Eve")
    with pytest.raises(SerializationError, match="binding"):
        parent.to_bytes()


def test_byte_profile_gate_rejects_changed_width_and_noise_before_setup_entropy():
    backend = ABBROMHIBE()
    sentinel = CountingEntropy(error=AssertionError("unadmitted setup used entropy"))
    for params in (replace(ABBROMParams(), sigma1_squared=1),
                   replace(ABBROMParams(), noise_width_numerator=5)):
        with pytest.raises(InvalidParameterError):
            backend.setup(params, rng=sentinel)
    assert sentinel.calls == 0


def test_pending_persistence_precedes_entropy_and_failed_writer_does_not_sample(instrumented):
    backend,master,calls=instrumented
    snapshots=[]
    rng=CountingEntropy()
    def save_pending(owner):
        snapshots.append(ABBMasterSecret.from_bytes(owner.to_bytes()))
        assert rng.calls==0
    backend._persist_pending=save_pending
    backend.extract(master,b"Bob",rng=rng)
    assert snapshots[0].parents[b"Bob"] is None and rng.calls==1
    def broken_writer(owner):raise OSError("injected persistence failure")
    backend._persist_pending=broken_writer
    unused=CountingEntropy(error=AssertionError("failed state writer used entropy"))
    with pytest.raises(OSError):backend.extract(master,b"Carol",rng=unused)
    assert master.parents[b"Carol"] is None and unused.calls==0


def test_registration_is_independent_and_size_formula_matches_wire(instrumented):
    from ibme.hibe.abb_rom.registration import backend_spec
    from ibme.assembly.registry import BackendRegistry, default_registry
    from ibme.hibe.abb_rom.objects import ABBCiphertext
    backend, master, calls = instrumented
    spec = backend_spec()
    registry = BackendRegistry([spec])
    assert registry.get("hibe", "abb-rom-finite").available
    assert spec.parse_params(ABBROMParams().to_record()) == ABBROMParams()
    with pytest.raises(InvalidParameterError): default_registry().get("hibe", "abb-rom-finite")
    assert set(spec.decoders) == {"hpk", "hmsk", "sk1", "sk2"}
    assert isinstance(spec.factory(None, "reference"), ABBROMHIBE)
    for size in (0, 1, 32):
        ct = ABBCiphertext(master.public_key.params, master.public_key.context, size,
            ((0,)*45,)*(8*size))
        assert len(ct.to_bytes()) == spec.ciphertext_size(ct.params, size, 86)
    with pytest.raises(SerializationError):
        spec.check_object(master.public_key, ABBROMParams())


def test_hybrid_preflight_rejects_large_capsule_and_accepts_explicit_q104_profile():
    pytest.importorskip("cryptography")
    from ibme.assembly import make_suite, validate_suite
    from ibme.assembly.registry import default_registry
    from ibme.hibe.abb_rom.registration import backend_spec
    from ibme.hibe.abb_rom.profiles import q104_research_params
    registry = default_registry()
    registry.register(backend_spec())
    selected = dict(hibe="abb-rom-finite", ibs="luo-module", transport="hybrid", registry=registry)
    too_large = validate_suite(make_suite(hibe_params=ABBROMParams(), **selected), registry=registry)
    assert not too_large.ok and any("capsule budget" in x for x in too_large.errors)
    fits = validate_suite(make_suite(hibe_params=q104_research_params(), **selected), registry=registry)
    assert fits.ok, fits.errors
    assert fits.capacity["inner_hibe_identity_bytes"] == 86
    assert fits.capacity["inner_hibe_payload_bytes"] == 32
    assert not fits.metadata["combination_tested"]


def test_decrypt_consumes_one_fresh_samplepre_per_bit_and_preserves_msb_order(instrumented, monkeypatch):
    from ibme.hibe.abb_rom.objects import ABBCiphertext
    backend, master, calls = instrumented
    parent = backend.extract(master, b"Bob")
    leaf = backend.derive(parent, b"Alice")
    target_matrix = expected_matrix(master.public_key, (b"Bob", b"Alice"))
    pivot = next(i for i,x in enumerate(target_matrix.rows[0]) if x)
    lifted = [0]*44
    lifted[pivot] = 7*pow(target_matrix.rows[0][pivot], -1, 101) % 101
    targets = []

    class PublicLiftInstrumentation:
        random_tape_bytes = 1
        def __init__(self, *args, **kwargs): pass
        def sample(self, target, *, rng):
            targets.append(target)
            rng.read(1)
            return tuple(lifted)

    monkeypatch.setattr(module, "MatrixFiniteGPV", PublicLiftInstrumentation)
    bits = tuple((0x85 >> shift) & 1 for shift in reversed(range(8)))
    ct = ABBCiphertext(leaf.public_key.params, leaf.public_key.context, 1,
        tuple((bit*50,)+(0,)*44 for bit in bits))
    rng = CountingEntropy()
    assert backend.decrypt(leaf, ct, rng=rng) == b"\x85"
    assert targets == [(7,)]*8 and rng.calls == 8
    # Explicit public lift instrumentation verifies wrapper calls, not GPV.


@pytest.mark.parametrize("failure", ["equation", "norm"])
def test_bad_samplepre_is_never_decoded_or_retried(instrumented, monkeypatch, failure):
    from ibme.hibe.abb_rom.objects import ABBCiphertext
    backend, master, calls = instrumented
    parent = backend.extract(master, b"Bob")
    leaf = backend.derive(parent, b"Alice")
    public = expected_matrix(master.public_key, (b"Bob", b"Alice"))
    pivot = next(i for i,x in enumerate(public.rows[0]) if x)
    x = [0]*44
    if failure == "norm":
        x[pivot] = 7*pow(public.rows[0][pivot], -1, 101) % 101
        column = matrix(leaf.basis).column(0)
        x = [a+10**100*int(b) for a,b in zip(x,column)]
    sampled = []

    class BadSample:
        random_tape_bytes = 1
        def __init__(self, *args, **kwargs): pass
        def sample(self, target, *, rng):
            sampled.append(target)
            rng.read(1)
            return tuple(x)

    monkeypatch.setattr(module, "MatrixFiniteGPV", BadSample)
    ct = ABBCiphertext(leaf.public_key.params, leaf.public_key.context, 1, ((0,)*45,)*8)
    with pytest.raises(ArithmeticError if failure=="equation" else ABBSamplingAbort):
        backend.decrypt(leaf,ct,rng=CountingEntropy())
    assert sampled == [(7,)]
