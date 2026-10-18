"""Directed interval for the source's Z^m smoothing definition and r≈1.16.

The paper explicitly defines eta via rho(s*Lambda*) with rho(x)=exp(-pi||x||²).
Its formal eta is not the printed 1.16 at the largest Table 4 dimension.
An implicit physical-standard-deviation conversion explains that printed
approximation, but is not in the eta definition.  No sampler width is changed.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path

from sage.all import QQ, RealIntervalField

from .paper_profiles import SOURCE_PDF, SOURCE_SHA256


SCHEMA = "IBME/SRGG-PAPER-SMOOTHING-ETA/1"
ROOT = Path(__file__).resolve().parents[4]
M = (2 + 2) * (4 + 1) * 512
EPSILON = Fraction(1, 1 << 24)
ROUNDED_R = Fraction(29, 25)
PHYSICAL_BRACKET = (Fraction(11600361, 10**7), Fraction(11600363, 10**7))
LITERAL_BRACKET = (Fraction(29077794, 10**7), Fraction(29077796, 10**7))


def _endpoint(value) -> Fraction:
    exact = value.exact_rational()
    return Fraction(int(exact.numerator()), int(exact.denominator()))


def _coarse(value: Fraction, *, upper: bool) -> str:
    """Exact 20-place decimal enclosure, avoiding huge dyadic output."""
    scale = 10**20
    quotient, remainder = divmod(value.numerator * scale, value.denominator)
    if upper and remainder:
        quotient += 1
    return f"{quotient // scale}.{quotient % scale:020d}"


def theta_bounds(*, width: Fraction, dimension: int, convention: str,
                 precision_bits: int = 512, first_tail_index: int = 4) -> dict:
    """Bound theta_Z(width)^dimension-1 with directed exponential intervals.

    For t=2*sum_{k>=1} a^(k^2), exact product theta is (1+t)^dimension-1.
    At k>=K, k^2 increases by at least 2K+1 per step, so the omitted tail
    is at most a^(K^2)/(1-a^(2K+1)).  Bernoulli lower and a geometric
    binomial upper apply when dimension*t_upper<1.

    The source's *formal eta definition* gives a=exp(-pi*width^2).  A separate
    hypothetical physical-standard-deviation conversion gives
    a=exp(-2*pi^2*width^2); this explains but does not validate the printed
    approximation r≈1.16 as eta.
    """
    if type(width) is not Fraction or not 0 < width <= 8:
        raise ValueError("width must be a bounded positive exact Fraction")
    if type(dimension) is not int or not 1 <= dimension <= 32768:
        raise ValueError("dimension outside explicit bound")
    if convention not in ("physical-standard-deviation", "literal-density-width"):
        raise ValueError("unknown Gaussian convention")
    if type(precision_bits) is not int or not 256 <= precision_bits <= 2048:
        raise ValueError("precision outside explicit bound")
    if type(first_tail_index) is not int or not 2 <= first_tail_index <= 8:
        raise ValueError("tail index outside explicit bound")

    field = RealIntervalField(precision_bits)
    w = field(QQ(width.numerator) / width.denominator)
    coefficient = (2 * field.pi()**2 if convention == "physical-standard-deviation"
                   else field.pi())
    interval = (-coefficient * w**2).exp()
    lower_a, upper_a = _endpoint(interval.lower()), _endpoint(interval.upper())
    if not 0 < lower_a <= upper_a < 1:
        raise ArithmeticError("directed exponential enclosure failed")
    lower_t = 2 * sum((lower_a**(k*k) for k in range(1, first_tail_index)),
                      Fraction(0))
    upper_t = 2 * (sum((upper_a**(k*k) for k in range(1, first_tail_index)),
                       Fraction(0)) +
                   upper_a**(first_tail_index**2) /
                   (1 - upper_a**(2*first_tail_index + 1)))
    lower_theta = dimension * lower_t
    x = dimension * upper_t
    upper_theta = x / (1-x) if x < 1 else None
    return {
        "width_exact": str(width),
        "dimension": dimension,
        "convention": convention,
        "precision_bits": precision_bits,
        "first_tail_index": first_tail_index,
        "theta_minus_one_lower_decimal_floor": _coarse(lower_theta, upper=False),
        "theta_minus_one_upper_decimal_ceiling": (
            None if upper_theta is None else _coarse(upper_theta, upper=True)),
        "upper_available": upper_theta is not None,
        "lower_exceeds_source_epsilon": lower_theta > EPSILON,
        "upper_below_source_epsilon": (
            upper_theta is not None and upper_theta < EPSILON),
    }


def build_report() -> dict:
    paper = ROOT / SOURCE_PDF
    digest = sha256(paper.read_bytes()).hexdigest()
    if digest != SOURCE_SHA256:
        raise ValueError("reviewed PDF checksum changed")
    physical_low = theta_bounds(width=PHYSICAL_BRACKET[0], dimension=M,
                                convention="physical-standard-deviation")
    physical_high = theta_bounds(width=PHYSICAL_BRACKET[1], dimension=M,
                                 convention="physical-standard-deviation")
    literal_low = theta_bounds(width=LITERAL_BRACKET[0], dimension=M,
                               convention="literal-density-width")
    literal_high = theta_bounds(width=LITERAL_BRACKET[1], dimension=M,
                                convention="literal-density-width")
    rounded_physical = theta_bounds(width=ROUNDED_R, dimension=M,
                                    convention="physical-standard-deviation")
    rounded_literal = theta_bounds(width=ROUNDED_R, dimension=M,
                                   convention="literal-density-width")
    for lower, upper in ((physical_low, physical_high),
                         (literal_low, literal_high)):
        if not lower["lower_exceeds_source_epsilon"] or not upper["upper_below_source_epsilon"]:
            raise ArithmeticError("smoothing-root bracket failed")
    if not (rounded_physical["lower_exceeds_source_epsilon"] and
            rounded_literal["lower_exceeds_source_epsilon"]):
        raise ArithmeticError("rounded source-width necessary check failed")
    if not (Fraction("1.155") < PHYSICAL_BRACKET[0] < PHYSICAL_BRACKET[1]
            < Fraction("1.165")):
        raise ArithmeticError("published two-decimal approximation not justified")
    return {
        "schema": SCHEMA,
        "paper": {"path": SOURCE_PDF, "sha256": digest,
                  "locations": "Gaussian convention p.3; Table 3 p.6; Section 5.1 p.9"},
        "source_dimension": M,
        "source_epsilon": str(EPSILON),
        "source_rounded_r": str(ROUNDED_R),
        "source_formal_eta_definition": "eta_epsilon(Z^m)=min{s>0:rho(s Z^m\\{0})<=epsilon}, rho(x)=exp(-pi||x||^2)",
        "formal_source_eta": {
            "width_open_bracket": [str(x) for x in LITERAL_BRACKET],
            "lower_endpoint": literal_low, "upper_endpoint": literal_high,
            "rounded_width": rounded_literal,
            "printed_1_16_matches_formal_eta_definition": False,
            "exact_rounded_value_satisfies_smoothing": False,
        },
        "hypothetical_physical_stddev_conversion": {
            "width_open_bracket": [str(x) for x in PHYSICAL_BRACKET],
            "lower_endpoint": physical_low, "upper_endpoint": physical_high,
            "rounded_width": rounded_physical,
            "relation_to_formal_eta": "eta_formal/sqrt(2*pi)",
            "implicit_unit_conversion_explains_printed_two_decimals": True,
            "this_is_the_source_formal_eta_definition": False,
            "exact_rounded_value_satisfies_smoothing": False,
        },
        "proof_scope": (
            "Exact Z^10240 theta bounds expose a discrepancy between the "
            "paper's formal eta definition and printed r≈1.16; an implicit "
            "unit conversion is a hypothesis, not a source fact. No width changes."),
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    payload = json.dumps(build_report(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        if args.output.exists():
            raise FileExistsError(args.output)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8", newline="\n")
    print(payload, end="")


if __name__ == "__main__":
    main()
