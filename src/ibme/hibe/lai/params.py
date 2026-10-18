"""Lai 2015 ideal-lattice HIBE parameters (research A point).

This module is Sage-free so registry/catalog discovery works on hosts that do
not have SageMath installed.  Any actual lattice operation imports the engine
lazily and fails with an explicit dependency error instead of falling back to a
mock or a different algorithm.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from ibme.core.errors import InvalidParameterError

VERSION = "lai-a-256-v1"


def _is_prime(value: int) -> bool:
    if type(value) is not int or value < 2:
        return False
    if value % 2 == 0:
        return value == 2
    if value % 3 == 0:
        return value == 3
    factor = 5
    while factor * factor <= value:
        if value % factor == 0 or value % (factor + 2) == 0:
            return False
        factor += 6
    return True


def _is_power_of_two(value: int) -> bool:
    return type(value) is int and value > 0 and value & (value - 1) == 0


@dataclass(frozen=True)
class LaiParams:
    """A-point research parameters; no security admission.

    ``q = 2^31 + 513`` is prime and ``q = 1 (mod 2n = 512)``; ``n = 256``
    carries a 256-bit binary identity per level and ``k*n = 8192`` message
    bits, enough for the 32 B hybrid seed.  The parameters are *research*
    parameters: they are not a NIST category and are not formally estimated.
    """

    q: int = 2147484161
    n: int = 256
    k: int = 32
    l: int = 2
    p: int = 2
    sigma: float = 2.0
    sigma_r: float = 1.0
    identity_bytes: int = 86
    max_message_bytes: int = 32
    message_mode: str = "seed32"

    def __post_init__(self) -> None:
        if not _is_prime(self.q) or self.q < 3:
            raise InvalidParameterError("Lai q must be an odd prime")
        if not _is_power_of_two(self.n) or self.n < 2:
            raise InvalidParameterError("Lai n must be a power of two >= 2")
        if self.q % (2 * self.n) != 1:
            raise InvalidParameterError("Lai q must equal 1 (mod 2n)")
        if type(self.k) is not int or not (2 ** (self.k - 1) < self.q < 2 ** self.k):
            raise InvalidParameterError("Lai k must equal ceil(log2 q)")
        if type(self.l) is not int or self.l < 1:
            raise InvalidParameterError("Lai l must be a positive integer")
        if self.p != 2:
            raise InvalidParameterError("Lai prototype packs messages with p=2 only")
        if self.q >= 2 ** 40:
            raise InvalidParameterError("Lai 5-byte serialization requires q < 2^40")
        if not (0 < self.sigma and math.isfinite(self.sigma)):
            raise InvalidParameterError("Lai sigma must be finite and > 0")
        if not (0 < self.sigma_r and math.isfinite(self.sigma_r)):
            raise InvalidParameterError("Lai sigma_r must be finite and > 0")
        if type(self.identity_bytes) is not int or not 1 <= self.identity_bytes <= 1024:
            raise InvalidParameterError("Lai identity_bytes must be in 1..1024")
        if type(self.max_message_bytes) is not int or self.max_message_bytes < 0:
            raise InvalidParameterError("Lai max_message_bytes must be non-negative")
        if self.max_message_bytes > (self.k * self.n - 8) // 8:
            raise InvalidParameterError("Lai max_message_bytes exceeds the ring payload")
        if self.message_mode not in ("seed32", "framed32"):
            raise InvalidParameterError("Lai message_mode must be seed32 or framed32")

    @property
    def coefficient_bytes(self) -> int:
        if self.q < 2 ** 24:
            return 3
        if self.q < 2 ** 32:
            return 4
        return 5

    @property
    def message_capacity_bits(self) -> int:
        return self.k * self.n

    @property
    def version(self) -> str:
        return VERSION
