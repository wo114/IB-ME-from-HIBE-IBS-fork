"""Exact, HIBE-independent audit of the SRGG paper parameter gates.

The paper uses ``q`` in Theorem 1, ``Q=p*b**w`` in the construction, and
``2Q`` in the response relation.  It also prints an epsilon expression whose
radical is easy to misread in text extraction.  This module records each
literal interpretation separately and never changes the published rows to
make a theorem gate pass.

The result is a source/parameter audit, not a security proof, sampler law,
hardness estimate, or formal parameter admission.
"""

from __future__ import annotations

import argparse
from decimal import Decimal
from decimal import localcontext
from fractions import Fraction
import hashlib
import json
from math import isqrt
from pathlib import Path
from typing import Any

from .paper_profiles import SOURCE_PDF, SOURCE_SHA256, profiles


SCHEMA = "IBME/SRGG-PARAMETER-CLOSURE/1"
_R = Fraction(29, 25)
_W = 2
_N = 512
_P = 2**14 - 1
_BASE = 31
_QUERY_BOUND = 2**40
_R_DIMENSION = (_W + 2) * 5 * _N
_PI_DECIMAL = Decimal("3.1415926535897932384626433832795028841971693993751")


def _odd_strictly_above(value: Decimal) -> int:
    """Return the smallest odd integer strictly greater than ``value``."""

    floor = int(value)
    candidate = floor + 1
    if Decimal(candidate) <= value:
        candidate += 1
    if candidate % 2 == 0:
        candidate += 1
    return candidate


def _epsilon_parses() -> dict[str, dict[str, Any]]:
    """Return both exact parses of the printed ``1/(sqrt(Q_s) * 256)`` line.

    The reviewed page-9 equation uses the ordinary factor ``256`` under the
    radical: ``epsilon = 1/sqrt(Q_s * 256)``.  Two common transcription
    mistakes are retained as sensitivity checks because text extraction can
    lose the radical grouping.
    """

    sqrt_qs = isqrt(_QUERY_BOUND)
    parses = {
        "source_radical_over_Qs_times_256_inside": Fraction(1, isqrt(_QUERY_BOUND * 256)),
        "alternate_radical_over_Qs_times_2pow56_inside": Fraction(1, isqrt(_QUERY_BOUND * 2**56)),
        "alternate_radical_over_Qs_times_256_outside": Fraction(1, sqrt_qs * 256),
    }
    return {
        name: {
            "epsilon": str(value),
            "epsilon_denominator": value.denominator,
            "epsilon_bits": value.denominator.bit_length() - 1,
            "source_status": (
                "confirmed by page-9 equation: radical contains Q_s*256"
                if name == "source_radical_over_Qs_times_256_inside"
                else "alternate transcription; not the reviewed source equation"
            ),
        }
        for name, value in parses.items()
    }


def _literal_smoothing_countercheck(dimension: int, epsilon: Fraction) -> dict[str, Any]:
    """Give the strict shortest-dual-vector necessary-condition countercheck.

    With the literal shape width ``r=29/25``, ``pi*r^2 < 5`` and
    ``exp(5) < 243`` imply a shortest-dual contribution larger than
    ``2*dimension/243``.  If this exceeds epsilon, the literal width cannot
    satisfy the displayed necessary smoothing condition.  This is not a
    sufficient-parameter calculation.
    """

    lower = Fraction(2 * dimension, 243)
    return {
        "dimension": dimension,
        "literal_r": str(_R),
        "pi_r_squared_upper": str(Fraction(22, 7) * _R * _R),
        "pi_r_squared_less_than_five": Fraction(22, 7) * _R * _R < 5,
        "shortest_dual_mass_strict_lower": str(lower),
        "epsilon": str(epsilon),
        "necessary_condition_fails": lower > epsilon,
        "scope": "necessary-condition countercheck for literal shape width; not a sufficient smoothing proof",
    }


def _physical_stddev_diagnostic(dimension: int, epsilon: Fraction) -> dict[str, Any]:
    """Numerically inspect the alternative physical-stddev reading.

    If the table's ``r`` is a physical standard deviation, the density shape
    would be ``2*pi*r^2``.  This is deliberately a high-precision diagnostic,
    not a transcendental interval certificate: the source does not specify
    that normalization or the number of digits retained for ``r``.
    """

    with localcontext() as context:
        context.prec = 80
        r = Decimal("1.16")
        eps = Decimal(epsilon.numerator) / Decimal(epsilon.denominator)
        pi = _PI_DECIMAL
        mass = Decimal(2 * dimension) * (-(pi * (2 * pi * r * r))).exp()
        required = (-((eps / Decimal(2 * dimension)).ln()) /
                    (2 * pi * pi)).sqrt()
        return {
            "interpretation": "table r is physical stddev; density shape = 2*pi*r^2",
            "dimension": dimension,
            "literal_r": "1.16",
            "epsilon": str(epsilon),
            "first_dual_mass_decimal": format(mass, ".30E"),
            "epsilon_decimal": format(eps, ".30E"),
            "literal_necessary_condition_passes": mass <= eps,
            "required_r_lower_diagnostic": format(required, ".30f"),
            "required_r_minus_literal_diagnostic": format(required - r, ".30E"),
            "certificate_status": "numerical diagnostic only; normalization and interval proof unresolved",
        }


def _modulus_row(profile: Any) -> dict[str, Any]:
    gamma = profile.gamma
    q_gadget = profile.q
    Q = profile.Q
    candidates = {
        "gadget_q": q_gadget,
        "ibs_Q": Q,
        "verification_2Q": 2 * Q,
    }
    gates = {}
    for name, modulus in candidates.items():
        gates[name] = {
            "modulus": modulus,
            "odd": modulus % 2 == 1,
            "gt_2gamma": Decimal(modulus) > 2 * gamma,
            "theorem_odd_and_gt_2gamma": (
                modulus % 2 == 1 and Decimal(modulus) > 2 * gamma
            ),
            "modulus_minus_2gamma": str(Decimal(modulus) - 2 * gamma),
        }
    minimum_odd = _odd_strictly_above(2 * gamma)
    width = 1
    while _P * (_BASE**width) < minimum_odd:
        width += 1
    return {
        "profile": profile.name,
        "rank": profile.rank,
        "degree_n": profile.degree,
        "p": profile.p,
        "gadget_base": profile.base,
        "gadget_digits_w": profile.digits,
        "gadget_q": q_gadget,
        "Q": Q,
        "gamma": str(gamma),
        "theorem_1_literal_requirement": "odd q > max(2*gamma, s1*eta_epsilon(Z^m))",
        "modulus_candidates": gates,
        "minimum_odd_integer_above_2gamma": minimum_odd,
        "diagnostic_smallest_w_with_p_times_31_pow_w_above_2gamma": width,
        "diagnostic_Q_at_that_w": _P * (_BASE**width),
        "diagnostic_is_new_parameter": True,
        "mapping_status": "unresolved: paper theorem q is not identified with gadget q, Q, or 2Q",
        "admission": False,
    }


def build_report(paper: Path | None = None) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[4]
    paper = root / SOURCE_PDF if paper is None else Path(paper)
    digest = hashlib.sha256(paper.read_bytes()).hexdigest()
    if digest != SOURCE_SHA256:
        raise ValueError("SRGG paper digest differs from the frozen reviewed version")

    epsilon = _epsilon_parses()
    rows = []
    for item in profiles:
        dimension = _R_DIMENSION
        smoothing = {
            name: _literal_smoothing_countercheck(
                dimension, Fraction(1, data["epsilon_denominator"])
            )
            for name, data in epsilon.items()
        }
        source_epsilon = Fraction(1, epsilon[
            "source_radical_over_Qs_times_256_inside"]["epsilon_denominator"])
        rows.append({"modulus_gates": _modulus_row(item), "smoothing": smoothing})
        rows[-1]["physical_stddev_diagnostic"] = _physical_stddev_diagnostic(
            dimension, source_epsilon
        )

    return {
        "schema": SCHEMA,
        "paper": {"path": SOURCE_PDF, "sha256": digest, "locations":
                  "Theorem 1 p.4; Table 3 p.6; Algorithms 7-8 p.8; Section 5.1 p.9"},
        "scope": "HIBE-independent SRGG source-symbol and parameter-gate audit",
        "source_constants": {
            "n": _N,
            "p": _P,
            "base": _BASE,
            "published_w": _W,
            "Q_s": _QUERY_BOUND,
            "published_r": str(_R),
            "visual_formula_reading": "epsilon = 1/sqrt(Q_s*256); alternate grouping parses retained for sensitivity",
            "r_dimension_expression": "(2+w)*5*512",
            "r_dimension": _R_DIMENSION,
            "epsilon_grouping_confirmed_from_pdf": True,
            "author_interpretation_confirmed": False,
            "zeta_shape_factor_from_exact_operator": 2,
            "algorithm_displayed_perturbation_factor": 1,
            "factor_mapping_status": "unresolved",
        },
        "epsilon_parses": epsilon,
        "rows": rows,
        "global_status": {
            "source_rows_reproduced": True,
            "theorem_modulus_mapping_closed": False,
            "gaussian_normalization_closed": False,
            "finite_sampler_to_final_signature_law_closed": False,
            "hardness_estimate_formally_validated": False,
            "security_claim": "none",
            "parameters_are_formal": False,
            "backend_admitted": False,
            "nist_security_category": None,
        },
        "limitations": [
            "The diagnostic w=3 modulus is not a published row and does not reuse published widths or gamma.",
            "The smoothing check is only a necessary-condition counterexample for Z^m.",
            "No value here identifies the HNF key or signature output law.",
            "No generic or structured attack estimate is inferred from these gates.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--paper", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = build_report(args.paper)
    encoded = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8", newline="\n")
    print(encoded, end="")


if __name__ == "__main__":
    main()
