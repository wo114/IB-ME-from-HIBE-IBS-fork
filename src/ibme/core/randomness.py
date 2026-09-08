"""Random sources with a frozen ``read(n) -> bytes`` protocol.

FROZEN INTERFACE: the method ``read(n: int) -> bytes`` is the cross-module
random-source contract; the lattice samplers (task B) and everything above
them inject randomness exclusively through it.

Two strictly separated implementations are provided:

* :class:`SecureRandom` -- production randomness from the operating system
  CSPRNG (``secrets``/``os.urandom``).  It deliberately accepts **no** seed:
  constructing one with an argument raises ``TypeError``.
* :class:`DeterministicRandom` -- a reproducible SHAKE-256 stream for tests
  and reproducible test vectors only.  Same seed in, same byte stream out;
  it must never be used as production randomness.

Production and test randomness share no code path that could mix them: the
deterministic stream is derived purely from the seed, and the secure source
never touches any seedable state.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Protocol, runtime_checkable

from .errors import RandomnessError

_BYTES_LIKE = (bytes, bytearray, memoryview)


@runtime_checkable
class RandomSource(Protocol):
    """The frozen random-source protocol consumed by the lattice samplers."""

    def read(self, n: int) -> bytes: ...  # pragma: no cover - protocol stub


def _check_length(n: int) -> int:
    """Validate the ``read`` length argument (shared by both sources)."""
    if not isinstance(n, int) or isinstance(n, bool):
        raise RandomnessError(f"read() length must be an int, got {n!r}")
    if n < 0:
        raise RandomnessError(f"read() length must be non-negative, got {n}")
    return n


class SecureRandom:
    """Production randomness backed by the operating system CSPRNG.

    ``read(n)`` returns ``n`` cryptographically secure bytes
    (``secrets.token_bytes``).  The class holds no state and no seed can be
    supplied: ``SecureRandom(seed)`` raises ``TypeError``.
    """

    __slots__ = ()

    def read(self, n: int) -> bytes:
        _check_length(n)
        return secrets.token_bytes(n)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "SecureRandom(<system CSPRNG>)"


class DeterministicRandom:
    """Reproducible SHAKE-256 byte stream for tests and fixed test vectors.

    The stream is defined as the concatenation of 64-byte blocks::

        block_i = SHAKE256(u32be(len(seed)) || seed || u64be(i), 64)

    so the delivered byte sequence is independent of how it is chunked by
    ``read`` calls: ``r.read(7) + r.read(9)`` equals ``r.read(16)`` of a
    freshly seeded instance.  The seed must be a non-empty bytes-like value;
    different seeds produce different streams (heuristic property of
    SHAKE-256, pinned by tests for concrete seeds).

    SECURITY: deterministic output -- never use for production keys,
    nonces, signatures or any secret material.
    """

    __slots__ = ("_seed_material", "_counter", "_buffer")

    _BLOCK_SIZE = 64

    def __init__(self, seed: bytes) -> None:
        if not isinstance(seed, _BYTES_LIKE):
            raise RandomnessError(
                f"seed must be bytes-like, got {type(seed).__name__}"
            )
        seed_bytes = bytes(seed)
        if not seed_bytes:
            raise RandomnessError("seed must be non-empty bytes")
        # Length-prefixed seed (no unprefixed concatenation, spec section 1)
        # keeps the derivation unambiguous.
        self._seed_material = (
            len(seed_bytes).to_bytes(4, "big") + seed_bytes
        )
        self._counter = 0
        self._buffer = bytearray()

    def _next_block(self) -> bytes:
        block = hashlib.shake_256(
            self._seed_material + self._counter.to_bytes(8, "big")
        ).digest(self._BLOCK_SIZE)
        self._counter += 1
        return block

    def read(self, n: int) -> bytes:
        _check_length(n)
        while len(self._buffer) < n:
            self._buffer += self._next_block()
        out = bytes(self._buffer[:n])
        del self._buffer[:n]
        return out

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "DeterministicRandom(<test-only reproducible stream>)"
