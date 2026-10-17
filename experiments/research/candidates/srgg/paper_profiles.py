"""Literal SRGG paper parameter sets, independent of optimization candidates.

Source: the locally frozen paper, Table 3 (p. 6), Section 5.1 (p. 9),
Tables 4--7 (p. 10). Decimal spellings retain the authors' final digits.
The published r approximately 1.16 is represented by that decimal, not as
an exact evaluation of the smoothing parameter. All security/performance
figures below are author reports, not reproduced results or admission.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from decimal import Decimal
from fractions import Fraction
from typing import ClassVar

SOURCE_PDF = "papers/2025_efficient_ibs_jia.pdf"
SOURCE_SHA256 = "258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152"
SOURCE_LOCATIONS = "Table 3 p.6; Section 5.1 p.9; Tables 4--7 p.10"
AUTHOR_ENVIRONMENT = (
    "C; gcc 8.3.0; Deepin 20.9; single Intel Core i7-10710U core at "
    "1.1 GHz; 8 GB RAM; Table 6 medians over 1000 executions"
)


@dataclass(frozen=True)
class AuthorReport:
    """Published estimates and measurements; no security category is inferred."""

    target_bits: int
    master_public_bytes: int
    master_secret_bytes: int
    user_secret_bytes: int
    signature_bytes: int
    key_recovery_bkz: int
    key_recovery_classical_bits: int
    key_recovery_quantum_bits: int
    forgery_bkz: int
    forgery_classical_bits: int
    forgery_quantum_bits: int
    setup_cycles: int
    extract_cycles: int
    sign_cycles: int
    verify_cycles: int
    setup_per_second: int
    extract_per_second: int
    sign_per_second: int
    verify_per_second: int

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer author report")


@dataclass(frozen=True)
class PaperProfile:
    """Immutable Table 4 input, with literal shared Section 5.1 parameters.

    These are execution inputs, not the earlier conservative sufficient gates.
    In particular no Q > 2*gamma or optimization-specific norm cap is applied.
    """

    name: str
    rank: int
    master_first_stddev: Decimal
    master_second_stddev: Decimal
    signature_first_stddev: Decimal
    signature_second_stddev: Decimal
    gamma: Decimal
    author_report: AuthorReport
    degree: int = 512
    p: int = 16383
    base: int = 31
    digits: int = 2
    r_stddev: Fraction = Fraction("1.16")
    extraction_query_bound: int = 1 << 40

    source_pdf: ClassVar[str] = SOURCE_PDF
    source_sha256: ClassVar[str] = SOURCE_SHA256
    source_locations: ClassVar[str] = SOURCE_LOCATIONS
    security_claim: ClassVar[str] = "none"
    backend_admitted: ClassVar[bool] = False
    parameters_are_formal: ClassVar[bool] = False
    nist_security_category: ClassVar[None] = None

    def __post_init__(self) -> None:
        if type(self.name) is not str or not self.name:
            raise ValueError("profile name must be a nonempty string")
        if type(self.rank) is not int or self.rank not in (2, 3, 4):
            raise ValueError("paper module rank must be 2, 3 or 4")
        for name, expected in (("degree", 512), ("p", 16383), ("base", 31),
                               ("digits", 2), ("extraction_query_bound", 1 << 40)):
            if type(getattr(self, name)) is not int or getattr(self, name) != expected:
                raise ValueError(f"paper {name} must equal {expected}")
        for name in ("master_first_stddev", "master_second_stddev",
                     "signature_first_stddev", "signature_second_stddev", "gamma"):
            value = getattr(self, name)
            if not isinstance(value, Decimal) or not value.is_finite() or value <= 0:
                raise ValueError(f"{name} must be a positive finite exact Decimal")
        if type(self.r_stddev) is not Fraction or self.r_stddev != Fraction("1.16"):
            raise ValueError("paper rounded r must be Fraction('1.16')")
        if not isinstance(self.author_report, AuthorReport):
            raise TypeError("author_report must be an AuthorReport")

    @property
    def q(self) -> int:
        return self.base ** self.digits

    @property
    def Q(self) -> int:
        return self.p * self.q

    @property
    def reported_target_bits(self) -> int:
        return self.author_report.target_bits

    def record(self) -> dict:
        """Return JSON-ready source data without converting decimals to floats."""
        result = asdict(self)
        for name in ("master_first_stddev", "master_second_stddev",
                     "signature_first_stddev", "signature_second_stddev", "gamma"):
            result[name] = str(getattr(self, name))
        result.update(
            r_stddev=str(self.r_stddev), r_published_approximation="1.16", q=self.q,
            Q=self.Q, source_pdf=SOURCE_PDF, source_sha256=SOURCE_SHA256,
            source_locations=SOURCE_LOCATIONS, author_environment=AUTHOR_ENVIRONMENT,
            reported_results_reproduced=False, security_claim="none",
            backend_admitted=False, parameters_are_formal=False,
            nist_security_category=None,
        )
        return result


profiles = (
    PaperProfile(
        "PARAM-I", 2, Decimal("2843.9"), Decimal("1023.0"),
        Decimal("843088.2"), Decimal("310891.6"), Decimal("42086491.7"),
        AuthorReport(100, 12320, 2048, 4900, 12148, 358, 105, 95,
                     352, 103, 93, 1520313, 5004676, 5203248, 1218478,
                     222, 104, 88, 236),
    ),
    PaperProfile(
        "PARAM-II", 3, Decimal("3399.4"), Decimal("1065.3"),
        Decimal("1046714.2"), Decimal("384614.5"), Decimal("63653172.0"),
        AuthorReport(180, 27680, 4608, 7396, 17786, 608, 178, 161,
                     586, 171, 155, 3445003, 5490761, 7007089, 1762221,
                     62, 46, 42, 87),
    ),
    PaperProfile(
        "PARAM-III", 4, Decimal("3867.7"), Decimal("1089.9"),
        Decimal("1238066.0"), Decimal("448859.2"), Decimal("86573930.5"),
        AuthorReport(256, 49184, 8192, 9892, 23516, 874, 255, 232,
                     828, 242, 219, 7294250, 9556676, 11521424, 2544205,
                     27, 25, 26, 48),
    ),
)


def profile(name: str) -> PaperProfile:
    """Look up a literal published name; aliases and inferred levels are rejected."""
    if type(name) is not str:
        raise TypeError("paper profile name must be a string")
    for item in profiles:
        if item.name == name:
            return item
    raise ValueError(f"unknown SRGG paper profile: {name!r}")
