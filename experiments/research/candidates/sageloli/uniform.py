"""Bounded, unbiased reduction of random or SHAKE bytes modulo q.

For a width-byte candidate X, accept exactly X < B - (B % q), where
B = 256**width.  Every residue has the same number of accepted preimages.
The accepted value is therefore exactly uniform for independent uniform input
bytes, including after conditioning on success of a bounded trial budget.
SHAKE output is used as the random-oracle byte stream, not as fresh entropy.

Resource exhaustion and entropy failures are explicit aborts.  No caller
should silently reroll the operation after this module aborts.  With a byte
budget sufficient for all trials, each value's exhaustion probability is at
most 2**(-max_trials_per_value), since the acceptance probability is >= 1/2.
The separate byte cap can cause an earlier abort; it is not a statistical
distance certificate or a cryptographic security admission.
"""

from __future__ import annotations

from hashlib import shake_256

from ibme.core.encoding import encode_bytes
from ibme.core.types import validate_bytes


DEFAULT_MAX_TRIALS_PER_VALUE = 192
MAX_TRIALS_PER_VALUE = 4096
MAX_MODULUS_BITS = 4096
MAX_VALUES = 1 << 20
MAX_BYTES = 64 << 20
_BYTES_LIKE = (bytes, bytearray, memoryview)


class UniformSamplingAbort(RuntimeError):
    """The finite rejection sampler failed without returning partial output."""


def _integer(value, low, high, name):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"invalid {name}")
    return value


def _layout(q, count, max_trials_per_value, max_bytes):
    _integer(q, 2, 1 << MAX_MODULUS_BITS, "modulus")
    _integer(count, 0, MAX_VALUES, "value count")
    _integer(max_trials_per_value, 1, MAX_TRIALS_PER_VALUE, "trial budget")
    _integer(max_bytes, 1, MAX_BYTES, "byte budget")
    width = max(1, ((q - 1).bit_length() + 7) // 8)
    if count * width > max_bytes:
        raise ValueError("byte budget cannot hold even one candidate per value")
    space = 1 << (8 * width)
    return width, space - space % q


def uniform_mod_q(rng, q, count, *,
                  max_trials_per_value=DEFAULT_MAX_TRIALS_PER_VALUE,
                  max_bytes=MAX_BYTES):
    """Return ``count`` unbiased residues, or raise ``UniformSamplingAbort``.

    ``rng`` must implement the project's ``read(n) -> bytes`` contract.
    Invalid parameters are rejected before reading.  Every successful read
    has exactly the requested width; exceptions, wrong types and wrong
    lengths abort immediately rather than being treated as rejected values.
    Total consumed bytes never exceed ``max_bytes``.  ``count=0`` consumes
    no bytes while still checking the source and public parameters.
    """
    width, limit = _layout(q, count, max_trials_per_value, max_bytes)
    if not callable(getattr(rng, "read", None)):
        raise TypeError("rng must provide read(n) -> bytes")
    output, consumed = [], 0
    for _ in range(count):
        for _ in range(max_trials_per_value):
            if consumed + width > max_bytes:
                raise UniformSamplingAbort("uniform byte budget exhausted")
            try:
                raw = rng.read(width)
            except Exception as exc:
                raise UniformSamplingAbort("uniform byte source failed") from exc
            if not isinstance(raw, _BYTES_LIKE):
                raise UniformSamplingAbort("uniform byte source returned an invalid result")
            raw = bytes(raw)
            if len(raw) != width:
                raise UniformSamplingAbort("uniform byte source returned an invalid result")
            consumed += width
            candidate = int.from_bytes(raw, "big")
            if candidate < limit:
                output.append(candidate % q)
                break
        else:
            raise UniformSamplingAbort("uniform rejection trial budget exhausted")
    return tuple(output)


class Shake256Stream:
    """A bounded read cursor over the core domain-framed SHAKE-256 output.

    hashlib.digest(n) returns a prefix rather than advancing a cursor.  This
    adapter caches geometrically increasing prefixes and explicitly slices
    at its cursor, so rejected candidates and successive reads never reuse
    the same prefix.  Chunking does not change the byte sequence.  Retained
    output is bounded by ``max_bytes``; prefix recomputation is geometric.
    """

    __slots__ = ("_state", "_buffer", "_position", "_max_bytes")

    def __init__(self, domain, payload, *, max_bytes=MAX_BYTES):
        _integer(max_bytes, 1, MAX_BYTES, "byte budget")
        domain = validate_bytes(domain, name="SHAKE domain")
        payload = validate_bytes(payload, name="SHAKE payload")
        if not domain:
            raise ValueError("SHAKE domain must be nonempty")
        if len(domain) > MAX_BYTES or len(payload) > MAX_BYTES:
            raise ValueError("SHAKE input exceeds resource cap")
        self._state = shake_256(encode_bytes(domain) + payload)
        self._buffer, self._position, self._max_bytes = b"", 0, max_bytes

    def read(self, size):
        _integer(size, 0, self._max_bytes, "SHAKE read length")
        end = self._position + size
        if end > self._max_bytes:
            raise UniformSamplingAbort("SHAKE byte budget exhausted")
        if end > len(self._buffer):
            length = min(self._max_bytes, max(end, 64, 2 * len(self._buffer)))
            self._buffer = self._state.digest(length)
        result = self._buffer[self._position:end]
        self._position = end
        return result


def shake_uniform_mod_q(domain, payload, q, count, *,
                        max_trials_per_value=DEFAULT_MAX_TRIALS_PER_VALUE,
                        max_bytes=MAX_BYTES):
    """Use the same rejection engine for domain-separated SHAKE hashing."""
    _layout(q, count, max_trials_per_value, max_bytes)
    stream = Shake256Stream(domain, payload, max_bytes=max_bytes)
    return uniform_mod_q(stream, q, count,
                         max_trials_per_value=max_trials_per_value, max_bytes=max_bytes)


__all__ = ["UniformSamplingAbort", "uniform_mod_q", "shake_uniform_mod_q", "Shake256Stream"]
