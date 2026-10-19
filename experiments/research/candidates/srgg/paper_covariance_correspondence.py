"""Exact coefficient-ring audit of SRGG Table 3 against Algorithm 7.

This is a source-correspondence check, not a substitute sampler or security
proof. In particular, the paper's factor-one perturbation is never changed.
"""
from __future__ import annotations

from fractions import Fraction
from hashlib import sha256
from itertools import product
import json
from pathlib import Path

from .paper_profiles import SOURCE_SHA256, profiles


SCHEMA = "IBME/SRGG-PAPER-COVARIANCE-CORRESPONDENCE/1"
ROOT = Path(__file__).resolve().parents[4]
PAPER = "papers/2025_efficient_ibs_jia.pdf"
BOUND_SOURCES = (
    "experiments/research/candidates/srgg/paper_covariance_correspondence.py",
    "experiments/research/candidates/srgg/paper_algebra.py",
    "experiments/research/candidates/srgg/paper_profiles.py",
    "experiments/research/candidates/srgg/paper_parameters.py",
    "experiments/research/candidates/srgg/paper_backend.py",
    "experiments/research/candidates/srgg/paper_schur_backend.py",
    "experiments/research/candidates/srgg/structured_geometry.py",
    "experiments/research/candidates/srgg/structured_execution.py",
    "experiments/research/candidates/srgg/wide_scalar.py",
)


def _vector(value, *, degree=None):
    if type(value) not in (tuple, list):
        raise TypeError("exact coefficient vector required")
    if degree is None:
        degree = len(value)
    if type(degree) is not int or degree < 2 or degree > 512 or degree & (degree - 1):
        raise ValueError("power-of-two degree in [2, 512] required")
    if len(value) != degree or any(type(x) is not int for x in value):
        raise ValueError("fixed-degree integer coefficients required")
    return tuple(value)


def zeta_apply(value):
    """Multiply by 1+X^(n/2) modulo X^n+1, in coefficient order."""
    value = _vector(value)
    h = len(value) // 2
    return tuple(value[i] - value[i+h] for i in range(h)) + tuple(
        value[i] + value[i+h] for i in range(h))


def zeta_star_apply(value):
    """Multiply by 1-X^(n/2), the transpose of zeta_apply."""
    value = _vector(value)
    h = len(value) // 2
    return tuple(value[i] + value[i+h] for i in range(h)) + tuple(
        value[i+h] - value[i] for i in range(h))


def inverse_center(challenge):
    """Algorithm 7 center -c/zeta = -zeta_star*c/2 in K_R."""
    return tuple(Fraction(-x, 2) for x in zeta_star_apply(challenge))


def coset_inverse(shift, challenge):
    """Return u for shift=zeta*u+c, or None outside this exact coset."""
    shift = _vector(shift)
    challenge = _vector(challenge, degree=len(shift))
    h = len(shift) // 2
    a = tuple(shift[i] - challenge[i] for i in range(len(shift)))
    if any((a[i] - a[i+h]) & 1 for i in range(h)):
        return None
    return tuple((a[i] + a[i+h]) // 2 for i in range(h)) + tuple(
        (a[i+h] - a[i]) // 2 for i in range(h))


def check_sample(u, challenge):
    """Check the exact pushforward energy and support, without floating point."""
    u = _vector(u)
    challenge = _vector(challenge, degree=len(u))
    shift = tuple(x + y for x, y in zip(zeta_apply(u), challenge))
    center = inverse_center(challenge)
    centered_energy = sum((Fraction(x) - y) ** 2 for x, y in zip(u, center))
    shifted_energy = sum(x*x for x in shift)
    if 2 * centered_energy != shifted_energy or coset_inverse(shift, challenge) != u:
        raise ArithmeticError("paper zeta pushforward identity failed")
    return shifted_energy


def shape_balance(squared_width, perturbation_factor=1):
    """Continuous-convolution shape accounting; no discrete-law assertion."""
    squared_width = Fraction(squared_width)
    if squared_width <= 0 or type(perturbation_factor) is not int or perturbation_factor not in (1, 2):
        raise ValueError("positive squared width and explicit factor one/two required")
    return {
        "input_u_shape": str(squared_width),
        "zeta_u_shape": str(2*squared_width),
        "perturbation_subtraction": str(perturbation_factor*squared_width),
        "excess_over_target": str((2-perturbation_factor)*squared_width),
    }


def _hash(name):
    path = (ROOT / name).resolve()
    if not path.is_relative_to(ROOT) or not path.is_file():
        raise ValueError("missing bound source")
    return sha256(path.read_bytes()).hexdigest()


def report():
    paper_sha = _hash(PAPER)
    if paper_sha != SOURCE_SHA256:
        raise ValueError("frozen SRGG PDF hash changed")
    checks = []
    for n in (2, 4):
        count = 0
        for u in product((-1, 0, 1), repeat=n):
            for c in product((0, 1), repeat=n):
                check_sample(u, c)
                count += 1
        checks.append({"degree": n, "all_u_in": "{-1,0,1}^n",
                       "all_binary_challenges": True, "checked_pairs": count})
    n = 512
    zero = (0,)*n
    e0 = (1,)+(0,)*(n-1)
    eh = (0,)*(n//2)+(1,)+(0,)*(n//2-1)
    for u, c in ((zero, zero), (zero, e0), (e0, eh), (eh, e0)):
        check_sample(u, c)
    rows = []
    for item in profiles:
        if item.degree != 512 or item.r_stddev != Fraction("1.16") or item.q != 961 or item.Q != 15744063:
            raise ValueError("original Table 4 profile changed")
        rows.append({"name": item.name, "d": item.rank, "n": item.degree,
                     "r_published_approximation": "1.16",
                     "literal_density_shape_if_exact_1_16": str(item.r_stddev**2),
                     "factor1_excess_over_target_in_units_of_r_squared": 1,
                     "factor2_hypothesis_excess_over_target_in_units_of_r_squared": 0})
    return {
        "schema": SCHEMA,
        "paper": {"path": PAPER, "sha256": paper_sha,
                  "locations": "Section 2.2 PDF p.3; Table 3 PDF p.6; Algorithm 7 PDF p.8"},
        "source_sha256": {name: _hash(name) for name in BOUND_SOURCES},
        "original_rows": rows,
        "finite_ring": {"zeta": "1+X^(n/2)", "zeta_star": "1-X^(n/2)",
                        "zeta_star_times_zeta": 2,
                        "zeta_lattice_index": {"base": 2, "exponent": 256},
                        "pushforward_support": "c+zeta*R",
                        "pushforward_density_shape_factor": 2,
                        "normalizer_depends_on_challenge_coset": True},
        "continuous_shape_accounting": {
            "paper_perturbation_factor": 1,
            "paper_output_excess_over_Sigma_bar_in_units_of_r_squared_LLstar": 1,
            "hypothetical_factor2_would_cancel_continuous_shape": True,
            "hypothetical_factor2_is_not_paper_algorithm": True,
            "density_to_physical_covariance_scale_cancels_in_relative_factor": True,
        },
        "finite_exact_checks": checks + [{"degree": n, "checked_sparse_pairs": 4}],
        "routes": [
            "source literal continuous-convolution shape: factor-one mismatch",
            "alternative 1 physical-SD/density conversion: relative factor two persists",
            "alternative 2 exact discrete coset: challenge-dependent normalizer and shape two",
        ],
        "author_intended_resolution": None,
        "full_signature_law_bound": None,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
    }


def main():
    print(json.dumps(report(), ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
