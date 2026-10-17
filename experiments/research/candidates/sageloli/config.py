"""Explicit teaching profiles for the adaptive Sageloli IBS backends.

The profiles mirror the dimensions from HAL v1 Figures 5--8 and Table 2/4.
They are executable research profiles only: no security level or parameter
admission is claimed.  Matrix SIS and Ring-SIS deliberately use separate
parameter classes so their private algebra cannot leak through the common IBS
interface.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import ClassVar


def _integer(value, low, high, name):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"invalid {name}")
    return value


@dataclass(frozen=True)
class SISParams:
    """Small composite-modulus matrix profile (n=2, k=4, m=16, q=3^4)."""

    n: int = 2
    k: int = 4
    m: int = 16
    q: int = 81
    identity_width_squared: int = 2**28
    signature_width_squared: int = 2**56
    r_squared: int = 16
    identity_max_bytes: int = 256
    message_max_bytes: int = 4096
    max_users: int = 32
    salt_bytes: int = 32
    max_sign_attempts: int = 64
    security_claim: ClassVar[str] = "none"
    backend_admitted: ClassVar[bool] = False
    parameters_are_formal: ClassVar[bool] = False

    def __post_init__(self):
        _integer(self.n, 1, 8, "n")
        _integer(self.k, 1, 16, "k")
        # The construction needs a nonempty Abar block and the Table 2
        # profile requires the conservative m >= 2*n*k width.
        _integer(self.m, 2 * self.n * self.k, 256, "m")
        _integer(self.q, 3**self.k, 3**self.k, "q")
        if self.q != 3**self.k:
            raise ValueError("Sageloli uses q=3^k, a composite modulus")
        _integer(self.m + self.nk, 1, 128, "coefficient dimension")
        _integer(self.identity_width_squared, 1, 2**70, "identity_width_squared")
        _integer(self.signature_width_squared, 1, 2**70, "signature_width_squared")
        _integer(self.r_squared, 16, 16, "r_squared")
        _integer(self.identity_max_bytes, 1, 4096, "identity_max_bytes")
        _integer(self.message_max_bytes, 0, 2**20, "message_max_bytes")
        _integer(self.max_users, 1, 4096, "max_users")
        _integer(self.salt_bytes, 1, 64, "salt_bytes")
        _integer(self.max_sign_attempts, 1, 256, "max_sign_attempts")

    @property
    def nk(self) -> int:
        return self.n * self.k

    @property
    def signature_dimension(self) -> int:
        return self.m + self.nk

    @property
    def s_id_squared(self) -> int:
        return self.identity_width_squared

    @property
    def s_sign_squared(self) -> int:
        return self.signature_width_squared

    @property
    def gadget(self) -> tuple[tuple[int, ...], ...]:
        return tuple(
            tuple((3**(j // self.n)) if i == j % self.n else 0 for j in range(self.nk))
            for i in range(self.n)
        )

    def record(self) -> dict:
        return asdict(self)

    @classmethod
    def from_record(cls, value):
        if not isinstance(value, dict) or set(value) != set(cls().record()):
            raise ValueError("complete SIS parameter record required")
        return cls(**value)


@dataclass(frozen=True)
class RSISParams:
    """Ring-SIS profile corresponding to d=4, k=9, l=22, q=3^9."""

    d: int = 4
    k: int = 9
    l: int = 22
    q: int = 19683
    identity_width_squared: int = 2**36
    signature_width_squared: int = 2**66
    r_squared: int = 16
    identity_max_bytes: int = 256
    message_max_bytes: int = 4096
    max_users: int = 32
    salt_bytes: int = 32
    max_sign_attempts: int = 64
    security_claim: ClassVar[str] = "none"
    backend_admitted: ClassVar[bool] = False
    parameters_are_formal: ClassVar[bool] = False

    def __post_init__(self):
        _integer(self.d, 4, 16, "d")
        if self.d & (self.d - 1):
            raise ValueError("d must be a power of two with four-quarter root noise")
        _integer(self.k, 1, 16, "k")
        _integer(self.l, self.k + 1, 128, "l")
        _integer(self.q, 3**self.k, 3**self.k, "q")
        if self.q != 3**self.k:
            raise ValueError("Sageloli uses q=3^k, a composite modulus")
        _integer(self.d * (self.l + self.k), 1, 128, "coefficient dimension")
        _integer(self.identity_width_squared, 1, 2**70, "identity_width_squared")
        _integer(self.signature_width_squared, 1, 2**70, "signature_width_squared")
        _integer(self.r_squared, 16, 16, "r_squared")
        _integer(self.identity_max_bytes, 1, 4096, "identity_max_bytes")
        _integer(self.message_max_bytes, 0, 2**20, "message_max_bytes")
        _integer(self.max_users, 1, 4096, "max_users")
        _integer(self.salt_bytes, 1, 64, "salt_bytes")
        _integer(self.max_sign_attempts, 1, 256, "max_sign_attempts")

    @property
    def root_columns(self) -> int:
        return self.l - self.k

    @property
    def first_dimension(self) -> int:
        return self.d * self.l

    @property
    def second_dimension(self) -> int:
        return self.d * self.k

    @property
    def signature_columns(self) -> int:
        return self.l + self.k

    @property
    def signature_dimension(self) -> int:
        return self.first_dimension + self.second_dimension

    @property
    def s_id_squared(self) -> int:
        return self.identity_width_squared

    @property
    def s_sign_squared(self) -> int:
        return self.signature_width_squared

    @property
    def gadget(self) -> tuple[tuple[int, ...], ...]:
        # A one-row ring gadget: (1, 3, ..., 3^(k-1)).
        return tuple((3**j,) + (0,) * (self.d - 1) for j in range(self.k))

    def record(self) -> dict:
        return asdict(self)

    @classmethod
    def from_record(cls, value):
        if not isinstance(value, dict) or set(value) != set(cls().record()):
            raise ValueError("complete RSIS parameter record required")
        return cls(**value)


__all__ = ["SISParams", "RSISParams"]
