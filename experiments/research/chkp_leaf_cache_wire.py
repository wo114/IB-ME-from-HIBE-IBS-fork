"""Canonical bounded private snapshot, NOT encrypted/authenticated storage.

All counts, integer lengths and total bytes are bounded before allocation or
expensive algebra. Trusted expected scope is mandatory on restore. A valid
replacement preimage or a rolled-back snapshot cannot be detected here.
"""

from math import gcd

from sage.all import QQ

from ibme.core.encoding import encode_bytes, decode_bytes
from ibme.core.errors import EncodingError, SerializationError
from .chkp_basis import ModMatrixReference
from .chkp_leaf_cache_types import (
    CacheScope, LeafPlan, CacheEntry, bounded_bytes, MAX_WIRE, MAX_CONTEXT,
    MAX_ID, MAX_ROWS, MAX_DIMENSION, PUBLIC_BITS, WIDTH_BITS, VECTOR_BITS,
)

MAGIC = b"IBME/CHKP/LEAF-CACHE/1\x00"
PLAN_MAGIC = b"LEAF-PLAN/1\x00"
MAX_PLAN_BYTES = 128 * 1024


def u32(x):
    return int(x).to_bytes(4, "big")


def unsigned(x):
    x = int(x)
    return encode_bytes(x.to_bytes(max(1, (x.bit_length()+7)//8), "big"))


def signed(x):
    return bytes([int(x < 0)]) + unsigned(abs(x))


def pack_plan(plan):
    a, w = plan.public, plan.width_squared
    parts = [PLAN_MAGIC, u32(a.nrows), u32(a.ncols), unsigned(a.q),
             unsigned(w.numerator()), unsigned(w.denominator()), encode_bytes(plan.profile)]
    parts += [unsigned(v) for row in a.rows for v in row]
    parts += [unsigned(v) for row in plan.targets for v in row]
    return b"".join(parts)


def pack_entry(child, entry):
    parts = [encode_bytes(child), bytes([entry.preimages is not None]), encode_bytes(pack_plan(entry.plan))]
    if entry.preimages is not None:
        parts += [signed(x) for row in entry.preimages for x in row]
    return b"".join(parts)


def dump(scope, entries):
    parts = [MAGIC, encode_bytes(scope.public_context), encode_bytes(scope.parent_identity),
             u32(scope.capacity), u32(scope.max_entries), u32(len(entries))]
    size = sum(map(len, parts))
    for child, entry in sorted(entries.items()):
        blob = pack_entry(child, entry)
        size += len(blob)
        if size > MAX_WIRE:
            raise ValueError("Cache snapshot exceeds byte budget")
        parts.append(blob)
    return b"".join(parts)


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, n):
        end = self.pos+n
        if end > len(self.data):
            raise ValueError("Truncated cache snapshot")
        value, self.pos = self.data[self.pos:end], end
        return value

    def count(self, cap):
        n = int.from_bytes(self.take(4), "big")
        if n > cap:
            raise ValueError("Cache field/count exceeds resource budget")
        return n

    def blob(self, cap):
        start = self.pos
        self.count(cap)  # check BEFORE decode_bytes makes the field slice
        value, self.pos = decode_bytes(self.data, start)
        return value

    def uint(self, bits):
        data = self.blob((bits+7)//8)
        if not data or (len(data) > 1 and data[0] == 0):
            raise ValueError("Noncanonical unsigned integer")
        value = int.from_bytes(data, "big")
        if value.bit_length() > bits:
            raise ValueError("Integer exceeds resource bound")
        return value

    def sint(self):
        sign = self.take(1)[0]
        value = self.uint(VECTOR_BITS)
        if sign > 1 or (sign and value == 0):
            raise ValueError("Noncanonical sign or negative zero")
        return -value if sign else value

    def end(self):
        if self.pos != len(self.data):
            raise ValueError("Trailing snapshot data")


def parse_plan(data, capacity):
    r = Reader(data)
    if r.take(len(PLAN_MAGIC)) != PLAN_MAGIC:
        raise ValueError("Unknown leaf plan version")
    n, d, q = r.count(MAX_ROWS), r.count(MAX_DIMENSION), r.uint(PUBLIC_BITS)
    if not 1 <= n <= d:
        raise ValueError("Invalid public dimensions")
    numerator, denominator = r.uint(WIDTH_BITS), r.uint(WIDTH_BITS)
    if not numerator or not denominator or gcd(numerator, denominator) != 1:
        raise ValueError("Noncanonical positive rational")
    profile = r.blob(4096)
    rows = tuple(tuple(r.uint(PUBLIC_BITS) for _ in range(d)) for _ in range(n))
    targets = tuple(tuple(r.uint(PUBLIC_BITS) for _ in range(n)) for _ in range(capacity))
    r.end()
    if q < 2 or any(v >= q for group in (rows, targets) for row in group for v in row):
        raise ValueError("Noncanonical residue or modulus")
    return LeafPlan(ModMatrixReference(rows, q), QQ(numerator)/denominator, profile, targets)


def load(data, expected_scope):
    if not isinstance(expected_scope, CacheScope):
        raise ValueError("A trusted expected CacheScope is required")
    try:
        raw = bounded_bytes(data, "snapshot", MAX_WIRE)
        r = Reader(raw)
        if r.take(len(MAGIC)) != MAGIC:
            raise ValueError("Unknown cache version")
        scope = CacheScope(r.blob(MAX_CONTEXT), r.blob(MAX_ID), r.count(32), r.count(8))
        if scope != expected_scope:
            raise ValueError("Snapshot scope/capacity mismatch")
        count, previous, entries = r.count(scope.max_entries), b"", {}
        for _ in range(count):
            child = bounded_bytes(r.blob(MAX_ID), "sender identity", MAX_ID)
            if child <= previous:
                raise ValueError("Duplicate or unordered cache address")
            previous = child
            state = r.take(1)[0]
            if state not in (0, 1):
                raise ValueError("Unknown cache state")
            plan = parse_plan(r.blob(MAX_PLAN_BYTES), scope.capacity)
            samples = (tuple(tuple(r.sint() for _ in range(plan.public.ncols))
                             for _ in range(scope.capacity)) if state else None)
            entries[child] = CacheEntry(plan, samples)
        r.end()
        if dump(scope, entries) != raw:
            raise ValueError("Noncanonical snapshot")
        return entries
    except (ValueError, TypeError, EncodingError) as exc:
        raise SerializationError(str(exc)) from exc
