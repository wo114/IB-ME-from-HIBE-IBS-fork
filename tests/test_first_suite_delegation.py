"""Exact master/parent lifecycle and real finite Gaussian delegation controls."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from fractions import Fraction
from pathlib import Path

import pytest
pytest.importorskip("sage.all", reason="Use prescribed WSL Sage; skip is not pass")
from sage.all import ZZ, matrix

from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.core.randomness import DeterministicRandom
from experiments.research.chkp_basis import KernelBasis, ModMatrixReference, complete_kernel_basis, ext_basis
from experiments.research.first_suite.identity import ROHIBEContext, Reader
from experiments.research.first_suite.delegation_state import (DelegationScope, MasterTreeState,
    ParentAddressBlocked, ReceiverState, MASTER_MAGIC, PARENT_MAGIC, validate_basis)
from experiments.research.first_suite.leaf_state import SeedAddressBlocked


def fixture():
    # Publicly computable toy root: tests no trapdoor secrecy or security grade.
    o = ROHIBEContext(1, 2, 5, ((1, 0),), b"TEST-ONLY/master-parent-layout", identity_bytes=64)
    scope = DelegationScope(o, Fraction(25), Fraction(4096), Fraction(2**21),
                            b"TEST-ONLY/parent", b"TEST-ONLY/leaf", epsilon_bits=16)
    root = complete_kernel_basis(ModMatrixReference(o.root_rows, o.q))
    return scope, root


def public_parent(plan):
    return complete_kernel_basis(ModMatrixReference(plan.scope.oracle.parent_rows(plan.receiver), plan.scope.oracle.q))


def public_leaf(plan):
    # These publicly computable vectors test lifecycle only, not Gaussianity.
    p = plan.seed_plan
    q = p.scope.oracle.q
    return tuple((t[0] if t[0] <= q // 2 else t[0] - q,) + (0,) * (p.dimension - 1) for t in p.targets)


def no_generation(plan): pytest.fail("restored/cached key attempted generation")


def test_root_parent_child_snapshots_preserve_one_owned_tree_and_all_vectors():
    scope, root = fixture()
    tree = MasterTreeState(scope, root)
    receiver = tree.issue(b"Bob", public_parent)
    assert tree.issue(b"Bob", no_generation) is receiver
    key = receiver.derive(b"Alice", public_leaf)
    assert receiver.derive(b"Alice", no_generation) is key
    master_raw, receiver_raw = tree.to_bytes(), receiver.to_bytes()
    restored = MasterTreeState.from_bytes(master_raw, expected_scope=scope)
    recovered = restored.issue(b"Bob", no_generation)
    assert recovered.derive(b"Alice", no_generation).preimages == key.preimages
    assert restored.to_bytes() == master_raw and recovered.to_bytes() == receiver_raw
    standalone = ReceiverState.from_bytes(receiver_raw, expected_scope=scope, expected_identity=b"Bob")
    assert standalone.derive(b"Alice", no_generation).preimages == key.preimages
    assert "basis" not in repr(tree).lower() or "hidden" in repr(tree).lower()
    assert "hidden" in repr(receiver)


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_parent_failure_is_not_retried_after_master_restore(error):
    scope, root = fixture()
    tree, calls = MasterTreeState(scope, root), []
    def fail(plan):
        calls.append(1)
        raise error("forced delegation interruption")
    with pytest.raises(error): tree.issue(b"Bob", fail)
    restored = MasterTreeState.from_bytes(tree.to_bytes(), expected_scope=scope)
    with pytest.raises(ParentAddressBlocked): restored.issue(b"Bob", fail)
    assert len(calls) == 1


def test_child_failure_is_inside_the_master_snapshot_and_blocks_after_reload():
    scope, root = fixture()
    tree = MasterTreeState(scope, root)
    receiver = tree.issue(b"Bob", public_parent)
    def fail(plan): raise KeyboardInterrupt("child interrupted")
    with pytest.raises(KeyboardInterrupt): receiver.derive(b"Alice", fail)
    restored = MasterTreeState.from_bytes(tree.to_bytes(), expected_scope=scope)
    with pytest.raises(SeedAddressBlocked): restored.lookup(b"Bob").derive(b"Alice", no_generation)


def test_callbacks_can_snapshot_in_progress_without_lock_order_deadlock():
    scope, root = fixture()
    tree, snapshots = MasterTreeState(scope, root), []
    def parent(plan):
        snapshots.append(tree.to_bytes())
        return public_parent(plan)
    receiver = tree.issue(b"Bob", parent)
    def leaf(plan):
        snapshots.append(tree.to_bytes())
        return public_leaf(plan)
    receiver.derive(b"Alice", leaf)
    parent_interrupted = MasterTreeState.from_bytes(snapshots[0], expected_scope=scope)
    with pytest.raises(ParentAddressBlocked): parent_interrupted.lookup(b"Bob")
    leaf_interrupted = MasterTreeState.from_bytes(snapshots[1], expected_scope=scope)
    with pytest.raises(SeedAddressBlocked): leaf_interrupted.lookup(b"Bob").lookup(b"Alice")


def test_same_identity_concurrent_issuance_and_snapshots_are_serialized():
    scope, root = fixture()
    tree, calls = MasterTreeState(scope, root), []
    def parent(plan):
        calls.append(plan.receiver)
        return public_parent(plan)
    with ThreadPoolExecutor(max_workers=4) as pool:
        receivers = list(pool.map(lambda _: tree.issue(b"Bob", parent), range(8)))
    assert calls == [b"Bob"] and all(r is receivers[0] for r in receivers)
    with ThreadPoolExecutor(max_workers=4) as pool:
        keys = list(pool.map(lambda _: receivers[0].derive(b"Alice", public_leaf), range(8)))
    assert all(k is keys[0] for k in keys)
    assert MasterTreeState.from_bytes(tree.to_bytes(), expected_scope=scope).lookup(b"Bob").lookup(b"Alice").preimages == keys[0].preimages


@pytest.mark.parametrize("change", ["root", "parent_width", "leaf_width", "profile", "capacity"])
def test_scope_changes_cannot_relabel_an_existing_private_tree(change):
    scope, root = fixture()
    tree = MasterTreeState(scope, root)
    receiver = tree.issue(b"Bob", public_parent)
    alterations = dict(root={"oracle": replace(scope.oracle, root_rows=((2, 0),))},
                       parent_width={"parent_width_squared": Fraction(8192), "leaf_width_squared": Fraction(2**22)},
                       leaf_width={"leaf_width_squared": Fraction(2**22)}, profile={"parent_profile": b"OTHER"},
                       capacity={"max_receivers": 7})
    changed = replace(scope, **alterations[change])
    with pytest.raises(SerializationError, match="scope"):
        MasterTreeState.from_bytes(tree.to_bytes(), expected_scope=changed)
    with pytest.raises(SerializationError, match="scope"):
        ReceiverState.from_bytes(receiver.to_bytes(), expected_scope=changed)
    with pytest.raises(SerializationError, match="identity"):
        ReceiverState.from_bytes(receiver.to_bytes(), expected_scope=scope, expected_identity=b"Carol")


def test_bad_parent_matrix_or_gs_bound_keeps_the_receiver_failed():
    scope, root = fixture()
    for bad in ("public", "GS"):
        tree = MasterTreeState(scope, root)
        def parent(plan):
            base = public_parent(plan)
            if bad == "public": return root
            rows = matrix(ZZ, base.basis_rows)
            rows.add_multiple_of_column(0, 1, 10**7)
            return KernelBasis(base.public, rows)
        with pytest.raises(InvalidParameterError): tree.issue(b"Bob", parent)
        restored = MasterTreeState.from_bytes(tree.to_bytes(), expected_scope=scope)
        with pytest.raises(ParentAddressBlocked): restored.lookup(b"Bob")


def test_column_norm_certificate_preserves_exact_gs_acceptance_with_fallback():
    scope, root = fixture()
    assert validate_basis(root, scope.oracle.root_rows, scope.oracle.q, 25).basis_rows == root.basis_rows
    # Huge parallel components leave GS lengths unchanged, so failure of the
    # cheap sufficient certificate MUST fall through to exact GS and accept.
    rows = matrix(ZZ, root.basis_rows)
    rows.add_multiple_of_column(1, 0, 10**7)
    sheared = KernelBasis(root.public, rows)
    assert max(sum(row[j]**2 for row in sheared.basis_rows) for j in range(2)) > 25
    assert validate_basis(sheared, scope.oracle.root_rows, scope.oracle.q, 25).basis_rows == sheared.basis_rows
    # A first-column shear preserves the lattice but really increases GS.
    rows = matrix(ZZ, root.basis_rows)
    rows.add_multiple_of_column(0, 1, 10**7)
    with pytest.raises(InvalidParameterError, match="Gram-Schmidt"):
        validate_basis(KernelBasis(root.public, rows), scope.oracle.root_rows, scope.oracle.q, 25)


def test_whole_tree_and_receiver_wire_growth_rejected_before_private_generation(monkeypatch):
    from experiments.research.first_suite import delegation_state as module
    scope, root = fixture()
    tree = MasterTreeState(scope, root)
    monkeypatch.setattr(module, "MAX_WIRE", len(tree.to_bytes()) + 10)
    raw = tree.to_bytes()
    with pytest.raises(InvalidParameterError, match="wire"):
        tree.issue(b"Bob", no_generation)
    assert tree.to_bytes() == raw
    monkeypatch.setattr(module, "MAX_WIRE", 16 * 2**20)
    receiver = tree.issue(b"Bob", public_parent)
    raw = tree.to_bytes()
    monkeypatch.setattr(module, "MAX_WIRE", len(raw) + 10)
    with pytest.raises(InvalidParameterError, match="wire"):
        receiver.derive(b"Alice", no_generation)
    assert tree.to_bytes() == raw


def test_master_and_parent_strict_formats_and_private_basis_equation_corruption():
    scope, root = fixture()
    tree = MasterTreeState(scope, root)
    receiver = tree.issue(b"Bob", public_parent)
    for raw, load in ((tree.to_bytes(), lambda b: MasterTreeState.from_bytes(b, expected_scope=scope)),
                      (receiver.to_bytes(), lambda b: ReceiverState.from_bytes(b, expected_scope=scope))):
        for bad in (raw[:-1], raw + b"\0", b"X" + raw[1:]):
            with pytest.raises(SerializationError): load(bad)
    raw = tree.to_bytes()
    r = Reader(raw)
    r.take(len(MASTER_MAGIC)); r.blob(16 * 2**20)
    basis_start = r.pos + 4
    basis_blob = r.blob(16 * 2**20)
    # m=2 root's first coefficient is +5. Changing it to +6 breaks A*S=0.
    assert basis_blob[4:10] == b"\0\0\0\0\x01\x05"
    bad = raw[:basis_start + 9] + b"\x06" + raw[basis_start + 10:]
    with pytest.raises(SerializationError, match="basis"):
        MasterTreeState.from_bytes(bad, expected_scope=scope)


def test_real_finite_randbasis_and_gpv_follow_the_same_owned_lifecycle():
    from experiments.research.chkp_gpv import CHKPGPVSampler
    from experiments.research.chkp_randbasis import CHKPRandBasis
    from experiments.research.chkp_basis_reduce import reduce_basis
    scope, root = fixture()
    parent_calls, leaf_calls = [], []
    def parent(plan):
        raw = ext_basis(plan.root_basis, ModMatrixReference(plan.scope.oracle.h((plan.receiver,)), plan.scope.oracle.q))
        sampler = CHKPGPVSampler(raw, str(plan.scope.parent_width_squared), epsilon_bits=16)
        result = CHKPRandBasis(sampler, max_vectors=raw.public.ncols + 32).sample(rng=DeterministicRandom(b"first-parent-real-randbasis"))
        parent_calls.append(result.draws_used)
        # Predeclared deterministic postprocessing, not a failure-triggered
        # fallback. The raw randomized basis can violate the existing scalar
        # width cap through tiny GS lengths; preserve that constructor gate.
        return reduce_basis(result.basis).basis
    def leaf(plan):
        p = plan.seed_plan
        raw = ext_basis(plan.parent_basis, ModMatrixReference(p.scope.oracle.h((p.scope.receiver, p.sender)), p.scope.oracle.q))
        assert raw.public.rows == p.public_rows
        sampler = CHKPGPVSampler(raw, str(p.scope.width_squared), epsilon_bits=16)
        rng = DeterministicRandom(b"first-parent-real-leaf-gpv")
        leaf_calls.append(1)
        return tuple(sampler.sample(target, rng=rng) for target in p.targets)
    tree = MasterTreeState(scope, root)
    receiver = tree.issue(b"Bob", parent)
    key = receiver.derive(b"Alice", leaf)
    restored = MasterTreeState.from_bytes(tree.to_bytes(), expected_scope=scope)
    assert restored.issue(b"Bob", no_generation).derive(b"Alice", no_generation).preimages == key.preimages
    assert len(key.preimages) == 256 and len(parent_calls) == len(leaf_calls) == 1
    assert parent_calls[0] >= 4


def test_actual_qfall_owned_tree_restores_both_levels_without_sampler(tmp_path):
    binary = Path(__file__).resolve().parents[1] / "test-results/qfall-target/release/ibme-qfall-public-fixture"
    if not binary.exists(): pytest.skip("explicit qFALL build required; skip is not pass")
    from experiments.research.first_suite.tree_probe import one_probe
    report = one_probe(17, 8, binary, tmp_path)
    assert report["parent_generations"] == report["leaf_generations"] == 1
    assert report["fixed_leaf_vectors"] == 256
    assert report["actual_noise_calls"] == report["expected_noise_calls"] == 295
    assert report["seed_bit_errors"] > 0
    fresh = report["fresh_process"]
    assert fresh["new_parent_generations"] == fresh["new_leaf_generations"] == 0
    assert fresh["master_snapshot_byte_equal"] and fresh["receiver_snapshot_byte_equal"]
    assert fresh["standalone_receiver_vectors_equal"]
    assert fresh["parent_failure_tombstone_blocked"] and fresh["leaf_failure_tombstone_blocked"]
    assert not fresh["native_sampler_module_loaded"]
    assert (tmp_path / "public-generation-receipt.json").is_file()
