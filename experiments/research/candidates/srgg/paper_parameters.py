"""Published SRGG inputs and explicit Gaussian notation, without new gates."""
from dataclasses import dataclass
from fractions import Fraction
from functools import lru_cache

from sage.all import QQ, RealIntervalField

from .paper_profiles import profile


@lru_cache(maxsize=1)
def pi_enclosure():
    interval = RealIntervalField(512).pi()
    return tuple(Fraction(int(QQ(x).numerator()), int(QQ(x).denominator()))
                 for x in interval.endpoints())


@dataclass(frozen=True)
class PaperParams:
    profile_name: str = "PARAM-I"
    interpretation: str = "table-standard-deviation"

    def __post_init__(self):
        profile(self.profile_name)
        if self.interpretation not in ("table-standard-deviation", "literal-density-width"):
            raise ValueError("explicit published Gaussian notation required")

    @property
    def source(self): return profile(self.profile_name)
    @property
    def degree(self): return self.source.degree
    @property
    def rank(self): return self.source.rank
    @property
    def p(self): return self.source.p
    @property
    def base(self): return self.source.base
    @property
    def digits(self): return self.source.digits
    @property
    def modulus(self): return self.source.Q
    @property
    def columns(self): return (2+self.digits)*self.rank
    @property
    def signature_norm_cap(self):
        squared = Fraction(self.source.gamma)**2
        return squared.numerator//squared.denominator

    def shape(self, reported):
        scale = sum(pi_enclosure()) if self.interpretation == "table-standard-deviation" else Fraction(1)
        return scale*Fraction(reported)**2

    @property
    def r_squared(self): return self.shape(self.source.r_stddev)
    @property
    def master_first_squared(self): return self.shape(self.source.master_first_stddev)
    @property
    def master_second_squared(self): return self.shape(self.source.master_second_stddev)
    @property
    def signature_first_squared(self): return self.shape(self.source.signature_first_stddev)
    @property
    def signature_second_squared(self): return self.shape(self.source.signature_second_stddev)

    def record(self):
        return {"profile_name": self.profile_name, "interpretation": self.interpretation,
                "source_sha256": self.source.source_sha256,
                "perturbation_noise_factor": 1, "hnf_representative": "centered-mod-Q",
                "gadget_remainder_representative": "centered-mod-p",
                "pi_precision_bits": 512, "r_published_approximation": "1.16"}

    @classmethod
    def from_record(cls, record):
        if type(record) is not dict:
            raise ValueError("paper parameter object required")
        result = cls(record.get("profile_name"), record.get("interpretation"))
        expected = result.record()
        if set(record) != set(expected) or any(
                type(record[name]) is not type(value) or record[name] != value
                for name, value in expected.items()):
            raise ValueError("paper parameter source or convention mismatch")
        return result

    def numerical_convention(self):
        low, high = pi_enclosure()
        return {"density": "exp(-pi*x^T*Sigma^-1*x)",
                "interpretation": self.interpretation,
                "pi_enclosure": [str(low), str(high)],
                "density_scale": str(low+high) if self.interpretation == "table-standard-deviation" else "1",
                "pi_scale_absolute_error_upper": str(high-low),
                "author_interpretation_confirmed": False,
                "published_r_is_rounded": True,
                "security_claim": "none", "parameters_are_formal": False}
