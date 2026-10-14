"""Flat, fully recorded parameters for the finite Foo--Li research runtime."""
from dataclasses import asdict, dataclass
from fractions import Fraction
from functools import lru_cache
import re

VERSION = "FooLi-IBS/1"


@dataclass(frozen=True)
class FooLiParams:
    # Default: the existing q=3 research regression, not a secure profile.
    q: int = 3
    n: int = 1
    m_bar: int = 1
    master_quality: int = 8
    user_quality: int = 3402
    generation_width_squared: int = 1
    master_r_squared: int = 9
    user_r_squared: int = 9
    gamma: int = 5
    epsilon0: str = "1/65536"
    identity_max_bytes: int = 256
    message_max_bytes: int = 4096
    max_users: int = 16
    tail_bits: int = 24
    mass_bits: int = 64
    precision_bits: int = 128
    gaussian_abort_bits: int = 24
    max_uniform_trials: int = 64
    max_gaussian_trials: int = 100000
    max_radius: int = 2**30
    rational_bits: int = 8192
    max_tape_bytes: int = 256*1024*1024

    def __post_init__(self):
        bounds = {"q": (2, 2**32), "n": (1, 128), "m_bar": (1, 128),
            "master_quality": (0, 10**12), "user_quality": (0, 10**12),
            "generation_width_squared": (1, 10**12), "master_r_squared": (1, 10**12),
            "user_r_squared": (1, 10**12), "gamma": (2, 128),
            "identity_max_bytes": (1, 4096), "message_max_bytes": (1, 1024*1024),
            "max_users": (1, 1024), "tail_bits": (8, 1024), "mass_bits": (32, 2048),
            "precision_bits": (96, 4096), "gaussian_abort_bits": (8, 1024),
            "max_uniform_trials": (1, 4096), "max_gaussian_trials": (1, 1000000),
            "max_radius": (1, 2**30), "rational_bits": (128, 8192),
            "max_tape_bytes": (1, 256*1024*1024)}
        for name, (low, high) in bounds.items():
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"Foo-Li {name} outside exact integer input range")
        if type(self.epsilon0) is not str or len(self.epsilon0) > 4096:
            raise ValueError("Foo-Li epsilon0 must be a bounded rational string")
        # Fraction accepts e.g. '1e-1000000000': a short string must never
        # trigger exponent-sized integer allocation before canonical checks.
        if re.fullmatch(r"[1-9][0-9]*/[1-9][0-9]*", self.epsilon0) is None:
            raise ValueError("Foo-Li epsilon0 requires canonical fraction syntax")
        parts = self.epsilon0.split("/")
        max_digits = self.rational_bits*30103//100000+1
        if any(len(part) > max_digits for part in parts):
            raise ValueError("Foo-Li epsilon0 exceeds rational bit budget")
        numerator, denominator = map(int, parts)
        if max(numerator.bit_length(), denominator.bit_length()) > self.rational_bits:
            raise ValueError("Foo-Li epsilon0 exceeds rational bit budget")
        epsilon = Fraction(numerator, denominator)
        if not 0 < epsilon <= Fraction(1, 4) or str(epsilon) != self.epsilon0:
            raise ValueError("Foo-Li epsilon0 must be canonical and in (0,1/4]")
        if self.dimension > 128:
            raise ValueError("Foo-Li online sampler dimension cap is 128")
        if self.user_quality < self.m*self.w*self.s_squared or self.t_squared < self.s_squared:
            raise ValueError("Foo-Li C3 quality or L4 width condition fails")

    @property
    def w(self): return self.n*(self.q-1).bit_length()

    @property
    def m(self): return self.m_bar+self.w

    @property
    def dimension(self): return self.m+self.w

    @property
    def s_squared(self): return self.master_r_squared*(self.gamma+2)*(self.master_quality+1)

    @property
    def t_squared(self): return self.user_r_squared*(self.gamma+2)*(self.user_quality+1)

    @property
    def signature_bound_squared(self): return self.dimension*self.t_squared

    def research_config(self):
        from experiments.research.foo_li_runtime_reference import ResearchConfig
        from experiments.research.online_gaussian_reference import OnlineOptions
        record = asdict(self)
        options = {name: record.pop(name) for name in OnlineOptions.__dataclass_fields__}
        return ResearchConfig(**record, options=OnlineOptions(**options))


@lru_cache(maxsize=8)
def preflight(params):
    """Public resource/class checks before setup entropy; cache public facts only."""
    if type(params) is not FooLiParams:
        raise TypeError("expected FooLiParams")
    from experiments.research.foo_li_runtime_reference import prepare
    prepare(params.research_config())
    return params
