"""Single-owner fixed-capacity CHKP leaf cache; RESEARCH ONLY.

Addresses are (scope.public_context, receiver, sender, bit index). Plans must
come from a trusted caller; this module does NOT implement H/G. Only vectors
are retained. No sampler, RNG, root/parent/leaf basis is stored or serialized.
Persistence uses explicit to_bytes/from_bytes of trusted private snapshots;
no disk transactions, anti-rollback, cross-process writers or storage crypto.
"""

from threading import RLock

from .chkp_leaf_cache_types import CacheScope, LeafPlan, CacheEntry, bounded_bytes, MAX_ID, MAX_WIRE, VECTOR_BITS
from .chkp_leaf_cache_wire import dump, load, pack_entry
from .chkp_leaf_reference import LeafPreimages, sample_leaf_preimages, MAX_LEAF_TAPE_BYTES
from .online_gaussian_reference import exact_integer


class CacheBlockedError(RuntimeError):
    """This address previously failed; no automatic resampling is permitted."""


class FixedLeafCache:
    security_claim = "none"
    backend_admitted = False

    def __init__(self, scope):
        if not isinstance(scope, CacheScope):
            raise ValueError("Need a validated CacheScope")
        self._scope, self._entries, self._lock = scope, {}, RLock()

    @property
    def scope(self):
        return self._scope

    def __repr__(self):
        return "FixedLeafCache(RESEARCH, private state hidden)"

    def _address(self, child, plan):
        child = bounded_bytes(child, "sender identity", MAX_ID)
        if not isinstance(plan, LeafPlan) or len(plan.targets) != self.scope.capacity:
            raise ValueError("Leaf plan must match fixed capacity")
        return child

    def _existing(self, child, plan):
        entry = self._entries.get(child)
        if entry is None:
            return None
        if entry.plan != plan:
            raise ValueError("Existing address has a different leaf plan")
        if entry.preimages is None:
            raise CacheBlockedError("Address blocked after a prior failed attempt")
        return LeafPreimages(plan.public, plan.targets, entry.preimages)

    def lookup(self, child, plan):
        """Read only; a missing address is NOT created or sampled."""
        child = self._address(child, plan)
        with self._lock:
            value = self._existing(child, plan)
            if value is None:
                raise KeyError("Leaf address is not cached")
            return value

    def bit(self, child, plan, position):
        position = exact_integer(position, "bit position", maximum=self.scope.capacity-1)
        return self.lookup(child, plan).preimages[position]

    def resolve(self, child, plan, *, sampler=None, rng=None):
        """Create all fixed positions atomically in memory, or reuse unchanged.

        A hit needs no sampler or entropy. Input/resource rejection does not
        reserve an address. Once execution starts it is FAILED until all
        vectors validate; any exception/interruption leaves that tombstone.
        Persist the state after both success and failure. Reopening an older
        snapshot or creating another owner is outside this consistency model.
        """
        child = self._address(child, plan)
        with self._lock:
            existing = self._existing(child, plan)
            if existing is not None:
                return existing
            if len(self._entries) >= self.scope.max_entries:
                raise ValueError("Cache entry capacity exhausted; no eviction")
            if not plan.matches(sampler):
                raise ValueError("Sampler does not match leaf plan")
            if self.scope.capacity*sampler.random_tape_bytes > MAX_LEAF_TAPE_BYTES:
                raise ValueError("Whole leaf batch tape exceeds resource budget")
            tombstone = CacheEntry(plan, None)
            # One sign byte + uint32 length + at most VECTOR_BITS/8 bytes/value.
            reserved = self.scope.capacity*plan.public.ncols*(5+(VECTOR_BITS+7)//8)
            if len(dump(self.scope, self._entries))+len(pack_entry(child, tombstone))+reserved > MAX_WIRE:
                raise ValueError("Worst-case snapshot byte budget exceeded")
            self._entries[child] = tombstone
            batch = sample_leaf_preimages(sampler, plan.targets, rng=rng)
            entry = CacheEntry(plan, batch.preimages)
            self._entries[child] = entry
            return LeafPreimages(plan.public, plan.targets, entry.preimages)

    def to_bytes(self):
        """Export sensitive plaintext state; caller must protect storage."""
        with self._lock:
            return dump(self.scope, self._entries)

    @classmethod
    def from_bytes(cls, data, *, expected_scope):
        entries = load(data, expected_scope)
        state = cls(expected_scope)
        state._entries = entries
        return state
