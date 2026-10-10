"""Strict parsing, trusted context matching, and explicit authenticity limits."""

from dataclasses import replace
import pytest
pytest.importorskip("sage.all", reason="Use prescribed WSL Sage; skip is not pass")

from ibme.core.encoding import encode_bytes
from ibme.core.errors import SerializationError
from ibme.core.randomness import DeterministicRandom
from experiments.research.chkp_basis import ModMatrixReference, complete_kernel_basis
from experiments.research.chkp_gpv import CHKPGPVSampler
from experiments.research.chkp_leaf_cache import FixedLeafCache
from experiments.research.chkp_leaf_cache_types import CacheScope, LeafPlan, CacheEntry
from experiments.research import chkp_leaf_cache_wire as wire


@pytest.fixture
def state():
    sampler = CHKPGPVSampler(complete_kernel_basis(ModMatrixReference([[1, 0]], 2)), 512, epsilon_bits=16)
    plan = LeafPlan.from_sampler(sampler, [(0,), (1,)])
    scope = CacheScope(b"full-test-context", b"receiver", 2, 2)
    store = FixedLeafCache(scope)
    store.resolve(b"alice", plan, sampler=sampler, rng=DeterministicRandom(b"wire"))
    raw = store.to_bytes()
    r = wire.Reader(raw)
    r.take(len(wire.MAGIC)); r.blob(65536); r.blob(256); r.count(32); r.count(8)
    count_pos = r.pos
    r.count(8)
    entry_start = r.pos
    r.blob(256)
    state_pos = r.pos
    r.take(1)
    plan_start = r.pos
    plan_blob = r.blob(wire.MAX_PLAN_BYTES)
    vectors_start = r.pos
    return scope, plan, store, raw, count_pos, entry_start, state_pos, plan_start, plan_blob, vectors_start


@pytest.mark.parametrize("change", ["context", "parent", "capacity", "entries"])
def test_expected_scope_must_match(state, change):
    scope, _, _, raw, *_ = state
    kwargs = {"context": {"public_context": b"another context"},
              "parent": {"parent_identity": b"another receiver"},
              "capacity": {"capacity": 1}, "entries": {"max_entries": 1}}[change]
    with pytest.raises(SerializationError, match="scope"):
        FixedLeafCache.from_bytes(raw, expected_scope=replace(scope, **kwargs))


@pytest.mark.parametrize("mutation", ["truncate", "append", "version", "count", "duplicate", "state", "huge_plan"])
def test_invalid_top_level_wire(state, mutation):
    scope, _, _, raw, cp, start, sp, pp, _, _ = state
    if mutation == "truncate":
        bad = raw[:-1]
    elif mutation == "append":
        bad = raw+b"\x00"
    elif mutation == "version":
        bad = b"X"+raw[1:]
    elif mutation == "count":
        bad = raw[:cp]+wire.u32(3)+raw[cp+4:]
    elif mutation == "duplicate":
        bad = raw[:cp]+wire.u32(2)+raw[cp+4:]+raw[start:]
    elif mutation == "state":
        bad = raw[:sp]+b"\x02"+raw[sp+1:]
    else:
        bad = raw[:pp]+b"\xff"*4+raw[pp+4:]
    with pytest.raises(SerializationError):
        FixedLeafCache.from_bytes(bad, expected_scope=scope)


@pytest.mark.parametrize("encoded", [b"\x02"+wire.unsigned(1), b"\x01"+wire.unsigned(0),
    b"\x00"+encode_bytes(b""), b"\x00"+encode_bytes(b"\x00\x01"),
    b"\x00"+encode_bytes(b"\x01"+b"\x00"*1024)])
def test_noncanonical_or_oversized_signed_integer(state, encoded):
    scope, _, _, raw, *rest = state
    start = rest[-1]
    r = wire.Reader(raw[start:])
    r.sint()
    bad = raw[:start]+encoded+raw[start+r.pos:]
    with pytest.raises(SerializationError):
        FixedLeafCache.from_bytes(bad, expected_scope=scope)


@pytest.mark.parametrize("mutation", ["zero_rows", "big_dimension", "residue", "profile", "fraction", "trailing"])
def test_plan_is_canonical_and_bounded(state, mutation):
    scope, _, _, raw, _, _, _, pp, blob, vs = state
    r = wire.Reader(blob)
    r.take(len(wire.PLAN_MAGIC)); npos=r.pos; r.count(16); dpos=r.pos; r.count(192)
    r.uint(64); fraction_start=r.pos; r.uint(1024); r.uint(1024); fraction_end=r.pos
    profile_start=r.pos; profile=r.blob(4096); profile_end=r.pos
    row_start=r.pos; r.uint(64); row_end=r.pos
    if mutation == "zero_rows":
        badplan = blob[:npos]+wire.u32(0)+blob[npos+4:]
    elif mutation == "big_dimension":
        badplan = blob[:dpos]+wire.u32(193)+blob[dpos+4:]
    elif mutation == "residue":
        badplan = blob[:row_start]+wire.unsigned(2)+blob[row_end:]
    elif mutation == "profile":
        badplan = blob[:profile_start]+encode_bytes(b"X"+profile[1:])+blob[profile_end:]
    elif mutation == "fraction":
        badplan = blob[:fraction_start]+wire.unsigned(1024)+wire.unsigned(2)+blob[fraction_end:]
    else:
        badplan = blob+b"\x00"
    bad = raw[:pp]+encode_bytes(badplan)+raw[vs:]
    with pytest.raises(SerializationError):
        FixedLeafCache.from_bytes(bad, expected_scope=scope)


def test_all_truncations_rejected(state):
    scope, _, _, raw, *_ = state
    for n in range(len(raw)):
        with pytest.raises(SerializationError):
            FixedLeafCache.from_bytes(raw[:n], expected_scope=scope)


def test_bad_equation_rejected_but_valid_replacement_is_not_authenticated(state):
    scope, plan, store, raw, *rest = state
    start = rest[-1]
    r = wire.Reader(raw[start:]); x = r.sint(); end = start+r.pos
    with pytest.raises(SerializationError, match="equation"):
        FixedLeafCache.from_bytes(raw[:start]+wire.signed(x+1)+raw[end:], expected_scope=scope)
    # Deliberately records a NON-goal: x+q still satisfies Ax=y. Format checks
    # are not an authentication mechanism for private storage.
    altered = FixedLeafCache.from_bytes(raw[:start]+wire.signed(x+2)+raw[end:], expected_scope=scope)
    assert altered.lookup(b"alice", plan) != store.lookup(b"alice", plan)


def test_empty_snapshot_canonical_and_no_pickle():
    scope = CacheScope(b"context", b"parent", 1)
    raw = FixedLeafCache(scope).to_bytes()
    assert raw.startswith(wire.MAGIC)
    assert FixedLeafCache.from_bytes(raw, expected_scope=scope).to_bytes() == raw


def test_total_nbytes_checked_before_copy(state):
    scope = state[0]
    data = memoryview(bytearray(wire.MAX_WIRE+4)).cast("I")
    with pytest.raises(SerializationError, match="length"):
        FixedLeafCache.from_bytes(data, expected_scope=scope)


def test_unordered_entries_rejected(state):
    scope, plan, store, _, *_ = state
    batch = store.lookup(b"alice", plan)
    entries = {b"alice": CacheEntry(plan, batch.preimages), b"bob": CacheEntry(plan, batch.preimages)}
    prefix = wire.dump(scope, {})[:-4]+wire.u32(2)
    bad = prefix+wire.pack_entry(b"bob", entries[b"bob"])+wire.pack_entry(b"alice", entries[b"alice"])
    with pytest.raises(SerializationError, match="unordered"):
        FixedLeafCache.from_bytes(bad, expected_scope=scope)
