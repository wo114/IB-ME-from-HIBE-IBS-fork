"""Exact moment bound for the *mathematical* SRGG Table 4 Setup retry gate.

For n=512 and the paper's w=2, the CBD1 witness R has a=2d rows and
b=wd columns.  Negacyclic Fourier diagonalization has no extra sqrt(n)
factor in a polynomial evaluation.  Its n frequencies occur in conjugate
pairs, leaving n/2 distinct complex a-by-b matrices R_j.  The Schur
complement in Algorithm 1 requires ||R_j||_2^2 < T at every frequency.

Each entry Z=sum_h chi_h*zeta_j^h has chi=B_1-B_2 with independent fair
bits.  A signed cyclic shift of the iid symmetric coefficients multiplies
Z by the primitive 2n-th root zeta_j.  For k<n, mixed moments used in
Tr((R_j R_j*)^k) vanish unless their powers balance.  Moreover, the
t^(2m) coefficient of E exp(t chi)=(1+cosh(t))/2 is bounded by that of
exp(t^2/4): 2(2m)! >= 4^m m!.  Since sum_h cos(h arg(zeta_j))^2=n/2,
the even real-projection moments are dominated by N(0,n/4), and rotation
gives E|Z|^(2m) <= m! (n/2)^m.  Independence between entries then bounds
the trace moment term by term by the complex Gaussian Wishart moment.

The hook formula below evaluates that Gaussian moment exactly.  Markov and
a union over n/2 frequencies bound only mathematical positive-definiteness
failure.  They do not bound interval-inconclusive roots, finite Fourier or
series preparation failures, the successful backend root distribution,
source-Schur sampling error, or any IBS security game.  All calculations
use exact rationals and draw no randomness.
"""

from __future__ import annotations

from fractions import Fraction
from hashlib import sha256
from math import comb, factorial
from pathlib import Path
import json

from .paper_parameters import PaperParams
from .paper_profiles import SOURCE_PDF, SOURCE_SHA256, profiles
from .paper_setup_conditioning import residual_threshold_squared


SCHEMA = "IBME/SRGG-PAPER-SETUP-ACCEPTANCE-MOMENT/1"
ORDERS = {"PARAM-I": 17, "PARAM-II": 22, "PARAM-III": 28}
SETUP_ATTEMPTS = 64


def _positive_integer(value: int, name: str, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError("bounded positive integer required: " + name)
    return value


def _rising(value: int, count: int) -> int:
    result = 1
    for offset in range(count):
        result *= value + offset
    return result


def _falling_below(value: int, count: int) -> int:
    result = 1
    for offset in range(1, count + 1):
        result *= value - offset
    return result


def wishart_trace_moment(rows: int, columns: int, order: int,
                         entry_second_moment: int | Fraction) -> Fraction:
    """E Tr((GG*)^order) for iid circular CN(0,entry_second_moment).

    The exact hook-character identity is

      v^k/k! sum_{r=0}^{min(a,b,k)-1} (-1)^r C(k-1,r)
        H_a(k,r) H_b(k,r),
      H_x(k,r)=prod_{j=0}^{k-r-1}(x+j) prod_{j=1}^r(x-j).

    It equals v^k sum_{sigma in S_k} a^cycles(gamma sigma)b^cycles(sigma),
    with gamma the full k-cycle; the latter form permits small-k independent
    tests without enumerating permutations in the original n=512 report.
    """
    a = _positive_integer(rows, "Wishart rows", 16)
    b = _positive_integer(columns, "Wishart columns", 16)
    k = _positive_integer(order, "moment order", 64)
    if isinstance(entry_second_moment, bool) or not isinstance(
            entry_second_moment, (int, Fraction)):
        raise ValueError("exact positive entry second moment required")
    v = Fraction(entry_second_moment)
    if v <= 0:
        raise ValueError("exact positive entry second moment required")
    numerator = sum(
        (-1)**r * comb(k - 1, r)
        * _rising(a, k - r) * _falling_below(a, r)
        * _rising(b, k - r) * _falling_below(b, r)
        for r in range(min(a, b, k))
    )
    quotient, remainder = divmod(numerator, factorial(k))
    if remainder or quotient <= 0:
        raise AssertionError("complex Wishart hook identity failed")
    return Fraction(quotient) * v**k


def _strict_dyadic_exponent(value: Fraction) -> int:
    """Largest m with the exact strict inequality value < 2^-m."""
    if not 0 < value < 1:
        raise ValueError("strict dyadic exponent requires a subunit probability")
    exponent = 0
    while value < Fraction(1, 1 << (exponent + 1)):
        exponent += 1
    if not value < Fraction(1, 1 << exponent):
        # Equality is possible only for a dyadic value; report one lower bit.
        exponent -= 1
    return exponent


def row_certificate(profile_name: str) -> dict:
    if type(profile_name) is not str or profile_name not in ORDERS:
        raise ValueError("one of the three frozen Table 4 profiles required")
    interpretations = [PaperParams(profile_name, name) for name in (
        "table-standard-deviation", "literal-density-width")]
    if any(p.degree != 512 or p.digits != 2 or p.base != 31 or
           p.rank not in (2, 3, 4) for p in interpretations):
        raise ValueError("original Table 4 shape changed")
    thresholds = [residual_threshold_squared(p.master_first_squared,
        p.master_second_squared, p.r_squared, p.base) for p in interpretations]
    if thresholds[0] != thresholds[1]:
        raise AssertionError("common density scaling must cancel from Setup gate")
    p = interpretations[0]
    n, a, b, k = p.degree, 2 * p.rank, p.digits * p.rank, ORDERS[profile_name]
    if a != b or 2 * k >= 2 * n:
        raise ValueError("Fourier moment assumptions do not match the paper")
    threshold = thresholds[0]
    second_moment = Fraction(n, 2)
    gaussian_moment = wishart_trace_moment(a, b, k, second_moment)
    rejection = Fraction(n, 2) * gaussian_moment / threshold**k
    if not 0 < rejection < 1:
        raise AssertionError("chosen original-parameter moment bound is vacuous")
    exhaustion = rejection**SETUP_ATTEMPTS
    exponent = _strict_dyadic_exponent(exhaustion)
    if rejection >= Fraction(1, 4) or exponent < 128:
        raise AssertionError("original-parameter retry bound did not reach 2^-128")
    return {
        "profile": profile_name,
        "interpretations": [p.interpretation for p in interpretations],
        "degree": n, "w": p.digits, "rank_d": p.rank,
        "Fourier_block_shape": [a, b],
        "conjugate_paired_blocks": n // 2,
        "polynomial_evaluation_normalization":
            "sum_h chi_h*zeta_j^h; no extra sqrt(n)",
        "entry_second_moment": str(second_moment),
        "moment_order": k,
        "moment_valid_because_order_less_than_degree": k < n,
        "positive_gate_threshold_squared_exact": str(threshold),
        "complex_gaussian_wishart_trace_moment_exact": str(gaussian_moment),
        "mathematical_one_attempt_rejection_upper_exact": str(rejection),
        "mathematical_one_attempt_rejection_upper_dyadic64_floor":
            (rejection * 2**64).numerator // (rejection * 2**64).denominator,
        "one_attempt_rejection_upper_below_quarter": rejection < Fraction(1, 4),
        "mathematical_64_attempt_exhaustion_upper_formula":
            "(" + str(rejection) + ")^64",
        "mathematical_64_attempt_exhaustion_strict_dyadic_upper":
            "2^-" + str(exponent),
        "mathematical_64_attempt_exhaustion_below_2_minus_128":
            exhaustion < Fraction(1, 2**128),
        "paper_conditioned_root_vs_raw_CBD1_tv_upper_exact": str(rejection),
        "paper_conditioned_root_vs_raw_scope":
            "mathematical witness only; true distance equals unknown rejection probability",
        "actual_backend_success_set_vs_paper_positive_set_tv_upper": None,
        "actual_backend_interval_inconclusive_probability_upper": None,
        "actual_backend_setup_fault_or_abort_upper": None,
        "all_accepted_root_finite_source_schur_tv_upper": None,
    }


def build_report() -> dict:
    root = Path(__file__).resolve().parents[4]
    if sha256((root / SOURCE_PDF).read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("frozen original paper checksum differs")
    if tuple(p.name for p in profiles) != tuple(ORDERS):
        raise ValueError("frozen Table 4 profile set/order differs")
    return {
        "schema": SCHEMA, "source_pdf": SOURCE_PDF,
        "source_sha256": SOURCE_SHA256,
        "paper_locations": "Algorithm 1 p.7; Table 3 p.6; Table 4 pp.9-10",
        "scope": "raw mathematical Algorithm 1 positive-definiteness gate and iid retry only",
        "raw_CBD1_coefficient_law": {"-1": "1/4", "0": "1/2", "1": "1/4"},
        "premises": [
            "independent uniform source bytes yield independent CBD1 witness coefficients",
            "each retry draws a fresh independent witness with the same law",
            "all original Table 4 squared widths share the same positive Gaussian-notation scale",
            "mathematical gate is strict Sigma_p-r^2 I positive-definiteness",
            "actual finite interval/Fourier/series success and faults are excluded",
        ],
        "one_attempt_method":
            "negacyclic Fourier direct sum; CBD1 moment dominance; exact complex Wishart hook moment; Markov union",
        "conditional_paper_root_law":
            "raw CBD1 witness conditioned on strict mathematical positive-definiteness",
        "bounded_retry_law":
            "(1-q_true^64)*conditional_paper_root_law + q_true^64*abort",
        "mathematical_positive_gate_bound_is_not_actual_backend_abort_bound": True,
        "rows": [row_certificate(p.name) for p in profiles],
        "source_parameters_unchanged": True,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
    }


if __name__ == "__main__":
    print(json.dumps(build_report(), ensure_ascii=False, indent=2))
