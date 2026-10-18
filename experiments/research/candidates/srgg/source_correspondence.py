"""Reproducible SRGG source checks, not a security or distribution certificate.

All vectors below are public synthetic fixtures.  The ledger is a human source
review; the executable checks establish only the stated exact algebra/arithmetic.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path

from experiments.research.primitive_spec_audit import SRGG_ROWS, srgg_row

from .algebra import (
    Params, PublicRelation, add, constant, matvec, multiply, reconstruct_vector,
    scale, vector, zeta, zeta_star,
)
from .geometry import diagonal, polynomial_operator, product, transpose


PAPER_SHA256 = "258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152"


def zeta_check(degree: int) -> dict:
    """Exact coefficient operator identity for the supported research degrees."""
    p = Params(degree=degree)
    operator = polynomial_operator(p, zeta(p))
    return {
        "degree": degree,
        "zeta_times_star_is_two": multiply(zeta(p), zeta_star(p)) == constant(p, 2),
        "operator_times_transpose_is_two_identity": product(operator, transpose(operator))
        == diagonal((2,) * degree),
        "induced_density_shape_factor": 2,
        "discrete_covariance_claimed": False,
    }


def hnf_check(public, target, raw, error) -> dict:
    """Check the approximate-to-exact relation and export aggregate facts only."""
    p = public.params
    raw = vector(p, raw, p.columns)
    error = vector(p, error, p.rank)
    target = vector(p, target, p.rank, p.modulus)
    if any(not 0 <= e < p.p for row in error for e in row):
        raise ValueError("canonical unsigned extraction error required")
    expected = tuple(add(h, scale(e, -1), p.modulus) for h, e in zip(target, error))
    if matvec(p, public.a, raw, p.modulus) != expected:
        raise ValueError("approximate extraction relation required")
    restored = reconstruct_vector(public, target, raw[p.rank:])
    corrected = tuple(add(row, e) for row, e in zip(raw[:p.rank], error))
    changed = sum(x != y for row, before in zip(restored[:p.rank], corrected)
                  for x, y in zip(row, before))
    raw_norm = sum(x*x for row in raw for x in row)
    restored_norm = sum(x*x for row in restored for x in row)
    coarse = 2*raw_norm + 2*p.rank*p.degree*(p.p-1)**2
    return {
        "exact_relation": matvec(p, public.a, restored, p.modulus) == target,
        "tail_preserved": restored[p.rank:] == raw[p.rank:],
        "centered_reduction_changed_coefficients": changed,
        "integer_head_correction_equals_error": changed == 0,
        "raw_norm_squared": raw_norm,
        "restored_norm_squared": restored_norm,
        "general_coarse_norm_bound_squared": coarse,
        "general_coarse_norm_bound_holds": restored_norm <= coarse,
        "distribution_certified": False,
    }


def _hnf_fixture(*, wrap: bool) -> dict:
    p = Params(degree=2, rank=1, p=5, base=3, digits=1)
    zero = constant(p, 0)
    public = PublicRelation(p, ((zero,),), ((constant(p, p.p),),))
    head, error = ((7, 7), (4, 4)) if wrap else ((1, -1), (1, 1))
    raw = (head,) + (zero,) * (p.columns-1)
    target = (tuple((x+e) % p.modulus for x, e in zip(head, error)),)
    return hnf_check(public, target, raw, (error,))


def source_smoothing_check() -> dict:
    """Exact conservative countercheck for the literal quoted r=1.16.

    pi < 22/7, pi*r^2 < 5, and exp(5) < 3^5=243 imply
    2D*exp(-pi*r^2) > 2D/243.  This is a necessary-condition check,
    not a sufficient smoothing parameter or an interpretation of author intent.
    """
    dimension, r = (2+2)*5*512, Fraction(29, 25)
    epsilon = Fraction(1, 2**24)  # 1/sqrt(2^40 * 256)
    exponent_upper = Fraction(22, 7)*r*r
    lower = Fraction(2*dimension, 243)
    return {
        "source_pages": [3, 6, 9],
        "dimension": dimension,
        "extraction_queries": 2**40,
        "epsilon": str(epsilon),
        "literal_quoted_r": str(r),
        "pi_r_squared_rational_upper": str(exponent_upper),
        "pi_r_squared_less_than_five": exponent_upper < 5,
        "shortest_dual_vectors_mass_strict_lower": str(lower),
        "necessary_smoothing_condition_fails_for_literal_r": lower > epsilon,
        "physical_stddev_interpretation": "plausible normalization explanation; unconfirmed",
        "sufficient_smoothing_certificate": False,
    }


def build_report(paper: Path | None = None) -> dict:
    paper = Path(__file__).resolve().parents[4] / "papers/2025_efficient_ibs_jia.pdf" if paper is None else paper
    digest = hashlib.sha256(paper.read_bytes()).hexdigest()
    rows = [srgg_row(row) for row in SRGG_ROWS]
    for row in rows:
        row["Q_is_odd"] = row["modulus_Q"] % 2 == 1
        row["twice_Q_is_odd"] = (2*row["modulus_Q"]) % 2 == 1
    return {
        "schema": "IBME/SRGG-SOURCE-CORRESPONDENCE/1",
        "paper": {"doi": "10.1049/ise2/6684889", "sha256": digest,
                  "matches_reviewed_version": digest == PAPER_SHA256},
        "scope": "exact synthetic-fixture checks plus manually reviewed source ledger",
        "zeta": [zeta_check(n) for n in (2, 4, 8)],
        "hnf": {"no_wrap_fixture": _hnf_fixture(wrap=False), "wrap_fixture": _hnf_fixture(wrap=True)},
        "source_parameter_rows": rows,
        "source_smoothing": source_smoothing_check(),
        "source_ledger": [
            {"pages": [6, 8], "item": "zeta perturbation", "status": "source-conflict",
             "finding": "Table 3 factor1 versus induced density-shape factor2; Config uses factor2"},
            {"pages": [4, 9], "item": "odd q and norm cutoff", "status": "mapping-incomplete",
             "finding": "conditional q=Q fails q>2gamma in all Table4 rows; 2Q is even"},
            {"pages": [5, 7, 8], "item": "HNF", "status": "algebra-verified-distribution-open",
             "finding": "exact relation and general norm bound do not identify the repaired-key law"},
            {"pages": [4, 8], "item": "strong unforgeability", "status": "premise-unverified",
             "finding": "Theorem1 EUF; Theorem2 assumes sEUF; displayed games use fresh messages"},
            {"pages": [3, 6, 9], "item": "Gaussian normalization", "status": "source-normalization-open",
             "finding": "literal r=1.16 fails shape-width smoothing; physical stddev explanation unconfirmed"},
        ],
        "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False,
        "full_tv_certificate": False, "strong_security_proof_verified": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--paper", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = build_report(args.paper)
    if not report["paper"]["matches_reviewed_version"]:
        parser.error("paper digest differs from reviewed version; a new source review is required")
    encoded = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8", newline="\n")
    print(encoded, end="")


if __name__ == "__main__":
    main()
