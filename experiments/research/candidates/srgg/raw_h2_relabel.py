"""Basis reference for an exact partial-byte SRGG H2 oracle relabeling.

This is a finite classical reference for the reversible identity proved in
raw-h2-relabel.md. It does not implement a quantum computer, program SHAKE,
replace H1, or establish QROM security. Query metadata is public/bounded;
the circuit schedule depends only on metadata, never on oracle reply bits.
"""
from __future__ import annotations

from dataclasses import dataclass


MAX_BYTES = 65536
MAX_POINT_BYTES = 2*1024*1024


def _int(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("bounded exact integer required: "+name)
    return value


def _degree(value):
    _int(value, "degree", 2, 512)
    if value & (value-1):
        raise ValueError("power-of-two degree required")
    return value


def relabel_prefix(prefix, degree):
    """The involution g(c)=(c_low XOR c_high,c_high); spare bits unchanged."""
    n = _degree(degree)
    width = (n+7)//8
    if type(prefix) is not bytes or len(prefix) != width:
        raise ValueError("complete fixed-width challenge prefix required")
    half = n//2
    word = int.from_bytes(prefix, "little")
    word ^= ((word >> half) & ((1 << half)-1))
    return word.to_bytes(width, "little")


def _query(point, offset, size):
    if type(point) is not bytes or len(point) > MAX_POINT_BYTES:
        raise ValueError("bounded raw input bytes required")
    _int(offset, "offset", 0, MAX_BYTES)
    _int(size, "size", 0, MAX_BYTES)
    if offset+size > MAX_BYTES:
        raise ValueError("raw byte query exceeds cap")


def _read(oracle, point, offset, size):
    data = oracle(point, offset, size)
    if type(data) is not bytes or len(data) != size:
        raise ValueError("raw oracle returned invalid bytes")
    return data


def _xor(first, second):
    if len(first) != len(second):
        raise ValueError("equal output register sizes required")
    return bytes(x^y for x, y in zip(first, second))


@dataclass(frozen=True)
class BasisResult:
    output: bytes
    scratch_is_zero: bool
    prefix_query_count: int
    suffix_query_count: int


def relabeled_basis_query(oracle, *, degree, point, offset, size, target):
    """Simulate XOR by a slice of g(F_prefix)||F_suffix on one basis input.

    Always issues two full-prefix queries and one suffix query (possibly an
    empty suffix). In a circuit these are XOR queries; the second prefix
    query uncomputes scratch. This routine checks that its classical oracle
    really is one fixed function. It cannot check quantum coherence.

    The same simulator works in the reverse direction because g is its own
    inverse. The unqueried padding of a fixed MAX_BYTES output register is
    implicitly unchanged. Values of target in the active slice are arbitrary.
    """
    n = _degree(degree)
    _query(point, offset, size)
    if type(target) is not bytes or len(target) != size:
        raise ValueError("active output register must have requested size")
    if not callable(oracle):
        raise TypeError("raw byte oracle required")
    width = (n+7)//8
    end = offset+size
    prefix_end = max(offset, min(end, width))
    prefix_size = max(0, prefix_end-offset)
    suffix_start = max(offset, width)
    suffix_size = max(0, end-suffix_start)

    # Fixed query schedule: metadata can be controlled coherently. No reply
    # bit selects a query, branch, rejection, or source of randomness.
    scratch = _read(oracle, point, 0, width)
    transformed = relabel_prefix(scratch, n)
    prefix = transformed[offset:prefix_end] if prefix_size else b""
    suffix = _read(oracle, point, suffix_start, suffix_size)
    restored = _read(oracle, point, 0, width)
    scratch = _xor(scratch, restored)
    if any(scratch):
        raise ValueError("oracle changed between compute and uncompute")
    return BasisResult(_xor(target, prefix+suffix), True, 2, 1)


def conjugated_full_prefix(oracle, *, degree, point, target):
    """One full-prefix XOR query conjugated by g on the target register."""
    n = _degree(degree)
    width = (n+7)//8
    _query(point, 0, width)
    transformed_target = relabel_prefix(target, n)
    reply = _read(oracle, point, 0, width)
    return relabel_prefix(_xor(transformed_target, reply), n)
