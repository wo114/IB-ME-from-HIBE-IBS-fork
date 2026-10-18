"""Author-manuscript two-depth object/assembly tests on an algebra-only fixture.

The fixture is publicly solvable and deliberately insecure. Real sampling of
the new first-level KEM is tested separately in test_chkp_level1_kem.py.
"""

from dataclasses import replace

import pytest

pytest.importorskip("sage.all", reason="author2011 complete-basis fixture needs Sage")

from ibme.assembly import default_registry, make_suite, validate_suite
from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.hibe.chkp.author2011 import (
    Author2011HIBE, Author2011PublicKey, Author2011MasterSecret,
    Author2011Level1Key, Author2011Level2Key, Author2011Ciphertext,
    ciphertext_size, check_object)
from ibme.hibe.chkp.objects import (
    CHKPPublicKey, CHKPMasterSecret, CHKPLevel1SecretKey,
    CHKPLevel2SecretKey, _scope)
from ibme.hibe.chkp.params import CHKPParams
from ibme.lattice.chkp.basis import ModMatrixReference, complete_kernel_basis
from ibme.lattice.chkp.delegation_state import MasterTreeState
from ibme.lattice.chkp.identity import ROHIBEContext
from ibme.lattice.chkp.level1_kem import validate_level1_preimages
from ibme.lattice.chkp.seed_kem import SeedCapsule


def _fixture():
    p = CHKPParams(n=1, q=17, m_bar=1, r_width_squared=1,
        root_gs_squared_bound=1024, parent_width_squared=131072,
        leaf_width_squared=201326592, alpha_numerator=1, alpha_denominator=17,
        epsilon_bits=16, parent_max_vectors=44, lll_policy="none")
    rows = (tuple(int(j == 0) for j in range(p.m)),)
    oracle = ROHIBEContext(p.n, p.m, p.q, rows, p.to_bytes(), identity_bytes=p.identity_bytes)
    base_public = CHKPPublicKey(p, oracle)
    public = Author2011PublicKey(base_public)
    tree = MasterTreeState(_scope(base_public), complete_kernel_basis(ModMatrixReference(rows, p.q)))
    receiver = tree.issue(b"receiver", lambda plan: complete_kernel_basis(
        ModMatrixReference(oracle.parent_rows(plan.receiver), p.q)))
    vectors = tuple((target[0],) + (0,) * (2*p.m-1)
                    for target in (oracle.g((b"receiver",), j) for j in range(256)))
    key = validate_level1_preimages(oracle, b"receiver", vectors, p.parent_width_squared)
    master = Author2011MasterSecret(public, CHKPMasterSecret(base_public, tree))
    master._entries[b"receiver"] = key
    parent = Author2011Level1Key(public, CHKPLevel1SecretKey(base_public, receiver), key)
    return public, master, parent


def _capsule(public, seed):
    bits = tuple((byte >> shift) & 1 for byte in seed for shift in range(7, -1, -1))
    return Author2011Ciphertext(SeedCapsule(public.context, public.params.q,
        (0,) * public.params.leaf_dimension,
        tuple(bit * (public.params.q // 2) for bit in bits)))


def test_first_level_decap_and_second_level_delegate_are_both_available():
    public, master, parent = _fixture()
    backend = Author2011HIBE()
    seed = bytes(range(32))
    ciphertext = _capsule(public, seed)
    assert backend.decrypt_level1(parent, ciphertext) == seed
    assert len(ciphertext.capsule.preamble) == 3*public.params.m
    assert backend.validate_key_binding(public, parent)
    assert backend.extract(master, b"receiver", rng=object()).to_bytes() == parent.to_bytes()

    receiver = parent.base.state
    leaf = receiver.derive(b"sender", lambda plan: tuple(
        (target[0],) + (0,) * (public.params.leaf_dimension-1)
        for target in plan.seed_plan.targets))
    child = Author2011Level2Key(public, CHKPLevel2SecretKey(public.base, leaf))
    assert backend.decrypt(child, _capsule(public, seed)) == seed
    assert backend.validate_key_binding(public, child)


def test_new_private_wire_roundtrip_and_zero_entropy_reuse():
    public, master, parent = _fixture()
    for obj in (public, master, parent):
        loaded = type(obj).from_bytes(obj.to_bytes())
        assert loaded.to_bytes() == obj.to_bytes()
        if obj is not public:
            assert Author2011HIBE().validate_key_binding(public, loaded)
    restored = Author2011MasterSecret.from_bytes(master.to_bytes())
    reused = Author2011HIBE().extract(restored, b"receiver", rng=object())
    assert reused.to_bytes() == parent.to_bytes()
    with pytest.raises(SerializationError):
        Author2011Level1Key.from_bytes(parent.to_bytes() + b"!")
    with pytest.raises(SerializationError):
        Author2011MasterSecret.from_bytes(master.to_bytes()[:-1])


def test_new_master_keeps_failed_address_occupied():
    public, _, _ = _fixture()
    root = complete_kernel_basis(ModMatrixReference(public.oracle.root_rows, public.params.q))
    master = Author2011MasterSecret(public,
        CHKPMasterSecret(public.base, MasterTreeState(_scope(public.base), root)))
    def fail(): raise RuntimeError("injected sampling failure")
    with pytest.raises(RuntimeError):
        master.issue(b"failed", fail)
    restored = Author2011MasterSecret.from_bytes(master.to_bytes())
    with pytest.raises(InvalidParameterError, match="no reissue"):
        Author2011HIBE().extract(restored, b"failed", rng=object())


def test_first_level_preimage_failure_after_parent_ready_stays_blocked(monkeypatch):
    import ibme.lattice.chkp.level1_kem as level1
    from ibme.hibe.chkp.backend import CHKPHIBE

    public, _, _ = _fixture()
    root = complete_kernel_basis(ModMatrixReference(public.oracle.root_rows, public.params.q))
    master = Author2011MasterSecret(public,
        CHKPMasterSecret(public.base, MasterTreeState(_scope(public.base), root)))

    def issue_parent(self, base_master, receiver, *, rng=None):
        state = base_master.state.issue(receiver, lambda plan: complete_kernel_basis(
            ModMatrixReference(public.oracle.parent_rows(receiver), public.params.q)))
        return CHKPLevel1SecretKey(base_master.public_key, state)

    def fail(*args, **kwargs): raise RuntimeError("injected first-level preimage failure")
    monkeypatch.setattr(CHKPHIBE, "extract", issue_parent)
    monkeypatch.setattr(level1, "sample_level1_preimages", fail)
    with pytest.raises(RuntimeError, match="preimage failure"):
        Author2011HIBE().extract(master, b"receiver")
    assert master.base.state.lookup(b"receiver").identity == b"receiver"
    restored = Author2011MasterSecret.from_bytes(master.to_bytes())
    with pytest.raises(InvalidParameterError, match="no reissue"):
        Author2011HIBE().extract(restored, b"receiver", rng=object())


def test_first_level_capacity_rejection_precedes_occupation_and_entropy(monkeypatch):
    import ibme.hibe.chkp.author2011 as service

    public, _, _ = _fixture()
    root = complete_kernel_basis(ModMatrixReference(public.oracle.root_rows, public.params.q))
    master = Author2011MasterSecret(public,
        CHKPMasterSecret(public.base, MasterTreeState(_scope(public.base), root)))
    monkeypatch.setattr(service, "MAX_OBJECT_BYTES", 1024)
    calls = []
    def forbidden(): calls.append(True)
    with pytest.raises((InvalidParameterError, SerializationError)):
        master.issue(b"new", forbidden)
    assert calls == [] and master._entries == {}


def test_master_ready_address_without_parent_is_a_wire_error():
    _, master, _ = _fixture()
    raw = master.to_bytes()
    position = raw.rfind(b"receiver")
    assert position >= 0
    altered = raw[:position] + b"receives" + raw[position + len(b"receiver"):]
    with pytest.raises(SerializationError, match="ready parent basis"):
        Author2011MasterSecret.from_bytes(altered)


def test_extended_hybrid_private_cap_is_type_scoped():
    from ibme.protocol.hybrid_hibe import HybridLimits, HybridPublicKey, HybridMasterSecret

    class TinyPublic:
        def to_bytes(self): return b"public"
        @classmethod
        def from_bytes(cls, data):
            assert data == b"public"
            return cls()

    class LargeSecret:
        hybrid_component_max_bytes = 64 * 2**20
        def __init__(self, raw): self.raw = raw
        def to_bytes(self): return self.raw
        @classmethod
        def from_bytes(cls, data): return cls(data)

    class LegacySecret(LargeSecret):
        hybrid_component_max_bytes = 16 * 2**20

    assert Author2011MasterSecret.hybrid_component_max_bytes == 64 * 2**20
    assert Author2011Level1Key.hybrid_component_max_bytes == 64 * 2**20
    raw = b"x" * (16 * 2**20 + 1)
    public = HybridPublicKey(HybridLimits(), TinyPublic())
    wrapped = HybridMasterSecret(public, LargeSecret(raw))
    wire = wrapped.to_bytes()
    assert HybridMasterSecret.from_bytes(wire, TinyPublic, LargeSecret).to_bytes() == wire
    with pytest.raises(SerializationError, match="component exceeds budget"):
        HybridMasterSecret.from_bytes(wire, TinyPublic, LegacySecret)


def test_versioned_route_and_capacity_are_explicit():
    spec = default_registry().get("hibe", "chkp-author2011")
    assert spec.version == "chkp-author2011-3m-v1"
    assert spec.persistent_identity_cache and spec.key_binding
    suite = make_suite(hibe="chkp-author2011", ibs="luo-module", transport="hybrid")
    report = validate_suite(suite)
    assert report.ok, report.errors
    assert report.metadata["security_claim"] == "none"
    assert report.metadata["backend_admitted"] is False
    assert ciphertext_size(spec.presets["hybrid-research"], 32, 86) > 3919
    public, _, _ = _fixture()
    with pytest.raises(SerializationError):
        check_object(public, replace(public.params, q=19))
