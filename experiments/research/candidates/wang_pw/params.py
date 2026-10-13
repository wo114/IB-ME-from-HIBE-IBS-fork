"""Explicit, bounded, UNSAFE debug profile; widths use exp(-pi*x²/s²)."""
from dataclasses import asdict, dataclass
from math import isqrt
from typing import ClassVar


@dataclass(frozen=True)
class Params:
    q: int = 17
    n: int = 1
    m_bar: int = 5
    generation_width_squared: int = 4
    master_quality: int = 128
    user_quality: int = 406350
    r_squared: int = 9
    gamma: int = 5
    salt_bytes: int = 32
    inner_identity_bytes: int = 32
    inner_message_bytes: int = 32
    identity_max_bytes: int = 256
    message_max_bytes: int = 4096
    tail_bits: int = 24
    mass_bits: int = 64
    precision_bits: int = 128
    gaussian_abort_bits: int = 24
    max_uniform_trials: int = 64
    security_claim: ClassVar[str] = "none"
    backend_admitted: ClassVar[bool] = False

    def __post_init__(self):
        bounds = {"q": (3, 2**32-1), "n": (1, 4), "m_bar": (1, 64),
                  "generation_width_squared": (1, 10**10), "master_quality": (0, 10**10),
                  "user_quality": (0, 10**10), "r_squared": (1, 10**6), "gamma": (2, 128),
                  "salt_bytes": (1, 64), "inner_identity_bytes": (1, 64),
                  "inner_message_bytes": (1, 64), "identity_max_bytes": (1, 4096),
                  "message_max_bytes": (1, 2**20), "tail_bits": (8, 1024),
                  "mass_bits": (32, 2048), "precision_bits": (96, 4096),
                  "gaussian_abort_bits": (8, 1024), "max_uniform_trials": (1, 4096)}
        for name, (low, high) in bounds.items():
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"{name} outside exact integer research range")
        if self.q % 2 == 0 or any(self.q % d == 0 for d in range(3, isqrt(self.q)+1, 2)):
            raise ValueError("prime q required by the reused MP12 engine")
        if self.m_bar < self.w or self.dimension > 128:
            raise ValueError("require m>=2w and MP12 reference dimension<=128")
        if self.signature_width_squared > 10**12 or self.delegation_width_squared > 10**12:
            raise ValueError("online Gaussian width resource limit exceeded")

    @property
    def w(self): return self.n*(self.q-1).bit_length()
    @property
    def m(self): return self.m_bar+self.w
    @property
    def dimension(self): return self.m+self.w
    @property
    def delegation_width_squared(self): return self.r_squared*(self.gamma+2)*(self.master_quality+1)
    @property
    def signature_width_squared(self): return self.r_squared*(self.gamma+2)*(self.user_quality+1)
    @property
    def signature_bound_squared(self): return self.signature_width_squared*self.dimension

    def record(self): return asdict(self)

    def online_options(self):
        return {name: getattr(self, name) for name in ("tail_bits", "mass_bits", "precision_bits",
                                                      "gaussian_abort_bits", "max_uniform_trials")}

    @classmethod
    def from_record(cls, record):
        if not isinstance(record, dict) or set(record) != set(cls().record()):
            raise ValueError("complete exact parameter snapshot required")
        return cls(**record)
