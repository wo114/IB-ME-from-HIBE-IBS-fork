"""Fixed-address cache behaviour; explicit small public research fixtures."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
pytest.importorskip("sage.all", reason="Use prescribed WSL Sage; skip is not pass")
from sage.all import QQ

from ibme.core.randomness import DeterministicRandom
from experiments.research import chkp_leaf_cache as cachemod
from experiments.research.chkp_leaf_cache import FixedLeafCache, CacheBlockedError
from experiments.research.chkp_leaf_cache_types import CacheScope, LeafPlan
from experiments.research.chkp_basis import ModMatrixReference, complete_kernel_basis
from experiments.research.chkp_gpv import CHKPGPVSampler
from experiments.research.gaussian_reference import SamplingAbort


@pytest.fixture
def env():
    sampler = CHKPGPVSampler(complete_kernel_basis(ModMatrixReference([[1, 0]], 2)), 512, epsilon_bits=16)
    plan = LeafPlan.from_sampler(sampler, [(0,), (1,)])
    scope = CacheScope(b"test-only-full-public-context", b"receiver", 2, 2)
    return sampler, plan, scope, FixedLeafCache(scope)


class NoEntropy:
    def read(self, n):
        pytest.fail("Cache hit or preflight rejection consumed entropy")


def test_repeat_restore_bit_lookup_no_resampling(env, monkeypatch):
    sampler, plan, scope, store = env
    first = store.resolve(b"alice", plan, sampler=sampler, rng=DeterministicRandom(b"cache"))
    snapshot = store.to_bytes()
    def forbidden(*a, **k):
        pytest.fail("Cache hit re-entered sampling")
    monkeypatch.setattr(cachemod, "sample_leaf_preimages", forbidden)
    assert store.resolve(b"alice", plan, rng=NoEntropy()) == first
    restored = FixedLeafCache.from_bytes(snapshot, expected_scope=scope)
    assert restored.resolve(b"alice", plan, rng=NoEntropy()) == first
    assert restored.to_bytes() == snapshot
    assert [restored.bit(b"alice", plan, i) for i in range(2)] == list(first.preimages)
    assert not hasattr(first, "basis") and not hasattr(first, "rng")
    assert not restored.backend_admitted and restored.security_claim == "none"


@pytest.mark.parametrize("position", [-1, 2, True, 0.0, "0"])
def test_bit_capacity_not_silently_extended(env, position):
    _, plan, _, store = env
    with pytest.raises(ValueError):
        store.bit(b"alice", plan, position)


def test_missing_is_not_implicitly_sampled(env):
    _, plan, _, store = env
    before = store.to_bytes()
    with pytest.raises(KeyError):
        store.lookup(b"alice", plan)
    assert store.to_bytes() == before


@pytest.mark.parametrize("change", ["width", "targets", "matrix", "profile", "capacity"])
def test_plan_changes_rejected_without_state_change(env, change):
    sampler, plan, _, store = env
    store.resolve(b"alice", plan, sampler=sampler, rng=DeterministicRandom(b"binding"))
    if change == "width":
        changed = replace(plan, width_squared=513)
    elif change == "targets":
        changed = replace(plan, targets=tuple(reversed(plan.targets)))
    elif change == "matrix":
        changed = replace(plan, public=ModMatrixReference([[0, 1]], 2))
    elif change == "profile":
        other = CHKPGPVSampler(sampler.basis, 512, epsilon_bits=17)
        changed = LeafPlan.from_sampler(other, plan.targets)
    else:
        changed = replace(plan, targets=[(0,)])
    before = store.to_bytes()
    with pytest.raises(ValueError):
        store.resolve(b"alice", changed, rng=NoEntropy())
    assert store.to_bytes() == before


def test_distinct_children_and_no_eviction(env):
    sampler, plan, scope, store = env
    for who in (b"alice", b"bob"):
        store.resolve(who, plan, sampler=sampler, rng=DeterministicRandom(who))
    snapshot = store.to_bytes()
    with pytest.raises(ValueError, match="capacity"):
        store.resolve(b"carol", plan, sampler=sampler, rng=NoEntropy())
    assert store.to_bytes() == snapshot
    other = FixedLeafCache.from_bytes(snapshot, expected_scope=scope)
    assert other.lookup(b"alice", plan) == store.lookup(b"alice", plan)
    assert other.lookup(b"bob", plan) == store.lookup(b"bob", plan)


@pytest.mark.parametrize("error", [SamplingAbort, ValueError, RuntimeError, KeyboardInterrupt])
def test_failure_tombstone_no_partial_return_or_retry(env, monkeypatch, error):
    sampler, plan, scope, store = env
    calls, original = [], sampler.sample
    def fail(y, *, rng=None):
        calls.append(y)
        if len(calls) == 2:
            raise error("forced second-vector failure")
        return original(y, rng=rng)
    monkeypatch.setattr(sampler, "sample", fail)
    with pytest.raises(error):
        store.resolve(b"alice", plan, sampler=sampler, rng=DeterministicRandom(b"failure"))
    restored = FixedLeafCache.from_bytes(store.to_bytes(), expected_scope=scope)
    for state in (store, restored):
        with pytest.raises(CacheBlockedError):
            state.resolve(b"alice", plan, sampler=sampler, rng=NoEntropy())
        with pytest.raises(CacheBlockedError):
            state.lookup(b"alice", plan)
    assert len(calls) == 2


def test_preflight_rejection_does_not_reserve_address(env, monkeypatch):
    sampler, plan, _, store = env
    before = store.to_bytes()
    with pytest.raises(ValueError, match="Sampler"):
        store.resolve(b"alice", plan, rng=NoEntropy())
    monkeypatch.setattr(sampler, "random_tape_bytes", 256*1024*1024)
    with pytest.raises(ValueError, match="tape"):
        store.resolve(b"alice", plan, sampler=sampler, rng=NoEntropy())
    assert store.to_bytes() == before


def test_worst_case_snapshot_gate_precedes_sampling(env, monkeypatch):
    sampler, plan, _, store = env
    before = store.to_bytes()
    monkeypatch.setattr(cachemod, "MAX_WIRE", len(before)+1)
    with pytest.raises(ValueError, match="snapshot"):
        store.resolve(b"alice", plan, sampler=sampler, rng=NoEntropy())
    assert store.to_bytes() == before


def test_same_owner_threads_share_one_batch(env, monkeypatch):
    sampler, plan, _, store = env
    calls, original = [], cachemod.sample_leaf_preimages
    def counted(*a, **kw):
        calls.append(1)
        return original(*a, **kw)
    monkeypatch.setattr(cachemod, "sample_leaf_preimages", counted)
    def work(i):
        return store.resolve(b"alice", plan, sampler=sampler, rng=DeterministicRandom(bytes([i])))
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(work, range(4)))
    assert results.count(results[0]) == 4 and calls == [1]


@pytest.mark.parametrize("bad", [b"", b"a"*257, "alice", None])
def test_bad_identity_before_state_change(env, bad):
    _, plan, _, store = env
    before = store.to_bytes()
    with pytest.raises(ValueError):
        store.resolve(bad, plan)
    assert store.to_bytes() == before


@pytest.mark.parametrize("kwargs", [dict(capacity=0), dict(capacity=33), dict(capacity=True),
    dict(max_entries=0), dict(max_entries=9), dict(public_context=b""),
    dict(public_context=memoryview(bytearray(65537))), dict(parent_identity=b"")])
def test_scope_validation(kwargs):
    args = dict(public_context=b"context", parent_identity=b"receiver", capacity=2)
    args.update(kwargs)
    with pytest.raises(ValueError):
        CacheScope(**args)


def test_readonly_public_scope_and_input_snapshots(env):
    _, plan, _, _ = env
    context, parent = bytearray(b"ctx"), bytearray(b"rcv")
    scope = CacheScope(context, parent, 2)
    context[0] = parent[0] = 0
    assert scope.public_context == b"ctx" and scope.parent_identity == b"rcv"
    store = FixedLeafCache(scope)
    with pytest.raises(AttributeError):
        store.scope = scope
    assert "ctx" not in repr(store) and "rcv" not in repr(store)
    with pytest.raises(ValueError):
        replace(plan, width_squared=QQ(1)/2**1025)
