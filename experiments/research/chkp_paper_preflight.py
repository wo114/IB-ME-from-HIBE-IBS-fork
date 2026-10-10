"""Exact preflight checks for a CHKP depth-two paper-derived candidate.

This module translates the numeric conditions that are explicit in CHKP
sections 5.1--5.3.  It deliberately does not invent the paper's unspecified
constant C, the omega tail factor in the alpha condition, a certified basis,
or a security level.  The result is therefore a screening report, never
backend admission.

The current GPV research implementation has a dimension cap of 192.  For a
depth-two CHKP hierarchy this makes the leaf dimension 3*m <= 192, which is
reported as an implementation constraint rather than a paper theorem.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from fractions import Fraction


MAX_GPV_DIMENSION = 192
MAX_AP09_ROOT_DIMENSION = 192
MAX_AP09_N = 16
MAX_AP09_Q = 2**61 - 1


def ceil_log2(value: int) -> int:
    if type(value) is not int or value < 2:
        raise ValueError("value must be an integer >= 2")
    return (value - 1).bit_length()


def _is_prime(value: int) -> bool:
    """Deterministic Miller--Rabin for the current <= 2**61-1 screen."""
    if type(value) is not int or value < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if value in small:
        return True
    if any(value % p == 0 for p in small):
        return False
    odd, exponent = value - 1, 0
    while odd % 2 == 0:
        odd //= 2
        exponent += 1
    # This base set is deterministic for n < 2^64.
    for base in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        if base % value == 0:
            continue
        x = pow(base, odd, value)
        if x in (1, value - 1):
            continue
        for _ in range(exponent - 1):
            x = (x * x) % value
            if x == value - 1:
                break
        else:
            return False
    return True


def _positive_int(value, name):
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _square_width_condition(q: int, width_squared: int, dimension: int) -> dict:
    """Check q >= 4*s*(dimension+1) without taking a square root."""
    lhs = q * q
    rhs = 16 * width_squared * (dimension + 1) ** 2
    return {
        "q_squared": str(lhs),
        "required_q_squared": str(rhs),
        "passed": lhs >= rhs,
    }


@dataclass(frozen=True)
class PaperCandidate:
    n: int
    m: int
    q: int
    s1_squared: int
    s2_squared: int
    depth: int = 2

    def __post_init__(self):
        for name in ("n", "m", "q", "s1_squared", "s2_squared"):
            _positive_int(getattr(self, name), name)
        if self.depth != 2:
            raise ValueError("this preflight is fixed to the selected depth-two CHKP route")
        if self.q > MAX_AP09_Q:
            raise ValueError("q exceeds the current AP09 research bound")


def screen_candidate(candidate: PaperCandidate) -> dict:
    """Return a JSON-safe, non-admitting report for one numeric candidate."""
    n, m, q = candidate.n, candidate.m, candidate.q
    log_q_ceiling = ceil_log2(q)
    dimensions = {"root": m, "level_1": 2 * m, "level_2_leaf": 3 * m}
    floor_rhs = n * log_q_ceiling
    m_floor = m >= floor_rhs
    dimension_cap = all(value <= MAX_GPV_DIMENSION for value in dimensions.values())
    root_cap = m <= MAX_AP09_ROOT_DIMENSION
    n_cap = n <= MAX_AP09_N
    q_cap = q <= MAX_AP09_Q
    q_prime = _is_prime(q)
    width_conditions = {
        "level_1": _square_width_condition(q, candidate.s1_squared, dimensions["level_1"]),
        "level_2_leaf": _square_width_condition(q, candidate.s2_squared, dimensions["level_2_leaf"]),
    }
    known_static = all((m_floor, dimension_cap, root_cap, n_cap, q_cap,
                        q_prime, *(item["passed"] for item in width_conditions.values())))
    return {
        "scope": "CHKP depth-two paper-derived numeric preflight",
        "source": {
            "paper": "papers/2010_bonsai_trees_cash.pdf",
            "sections": ["5.1 Lemma 5.1", "5.2 Equations (5.1)/(5.2)",
                         "5.3 ROHIBE and Theorem 5.2"],
            "model": "classical random oracle model",
        },
        "parameters": {
            "n": n, "m": m, "q": q, "depth": candidate.depth,
            "s1_squared": candidate.s1_squared,
            "s2_squared": candidate.s2_squared,
            "epsilon_bits": None,
        },
        "dimensions": dimensions,
        "paper_relations": {
            "m_ge_C_n_log2_q": {
                "known_floor_m_ge_n_ceil_log2_q": m_floor,
                "floor_rhs": floor_rhs,
                "observed_ratio_m_over_n_ceil_log2_q": str(Fraction(m, floor_rhs)),
                "status": "C_is_unspecified_in_paper; no fixed C is invented",
            },
            "q_ge_4_s_t_m_t_plus_1": width_conditions,
            "alpha_condition": {
                "status": "not_evaluated",
                "reason": "requires a chosen omega(sqrt(log n)) tail factor and alpha",
            },
        },
        "implementation_constraints": {
            "current_gpv_dimension_cap": MAX_GPV_DIMENSION,
            "current_ap09_root_dimension_cap": MAX_AP09_ROOT_DIMENSION,
            "current_ap09_n_cap": MAX_AP09_N,
            "current_ap09_q_cap": MAX_AP09_Q,
            "dimension_cap_passed": dimension_cap,
            "root_cap_passed": root_cap,
            "n_cap_passed": n_cap,
            "q_cap_passed": q_cap,
            "q_prime": q_prime,
            "random_tape_and_to_basis": "requires the actual basis and sampler run",
            "noise_and_decryption": "requires alpha, error distribution, and HIBE equations",
        },
        "known_static_conditions_passed": known_static,
        "backend_admitted": False,
        "parameters_are_formal": False,
        "security_claim": "none",
        "unresolved": [
            "paper constant C in m >= C*n*log2(q)",
            "omega tail factor and alpha/noise budget",
            "GenBasis distribution and finite quality certificate",
            "actual GS lengths after ExtBasis/RandBasis/optional postprocessing",
            "SampleD/RandBasis random tape and memory",
            "IBS composition and whole-system security estimate",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("n", "m", "q", "s1_squared", "s2_squared"):
        parser.add_argument(f"--{name.replace('_', '-')}", type=int, required=True)
    parser.add_argument("--output", type=str,
                        help="write the deterministic JSON report to this path")
    args = vars(parser.parse_args(argv))
    output = args.pop("output")
    try:
        report = screen_candidate(PaperCandidate(**args))
    except ValueError as exc:
        parser.error(str(exc))
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if output:
        from pathlib import Path
        Path(output).write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0 if report["known_static_conditions_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
