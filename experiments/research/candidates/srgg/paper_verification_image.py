"""Exact image/kernel diagnostic for the original SRGG verification matrix.

The paper's Algorithms 7--8 use [2A | Q*zeta*e1 - 2h] modulo 2Q,
where A=[I_d | Ahat | B] and zeta*=1-X^(n/2). This module certifies
only its module image. It makes no distributional or attack-cost claim.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

from .paper_profiles import SOURCE_PDF, SOURCE_SHA256, profiles


SCHEMA = "IBME/SRGG-PAPER-VERIFICATION-IMAGE/1"
ROOT = Path(__file__).resolve().parents[4]
SOURCE_FILES = (
    "experiments/research/candidates/srgg/paper_verification_image.py",
    "experiments/research/candidates/srgg/paper_profiles.py",
    "experiments/research/candidates/srgg/paper_algebra.py",
    "experiments/research/candidates/srgg/structured_execution.py",
)


def image_certificate(*, degree: int, rank: int, columns: int, Q: int) -> dict:
    """Algebraic result given the stated identity block and final column.

    The proof works for every Ahat, B and h, not just uniformly sampled
    entries. It requires even power-of-two n and odd Q. ``columns`` counts
    the columns of A, before the final h-dependent column is appended.
    """
    if (type(degree) is not int or degree < 2 or degree > 512
            or degree & (degree - 1)):
        raise ValueError("bounded even power-of-two degree required")
    if type(rank) is not int or not 1 <= rank <= 4:
        raise ValueError("bounded positive module rank required")
    if type(columns) is not int or not rank <= columns <= 32:
        raise ValueError("bounded A column count including I_d required")
    if type(Q) is not int or not 3 <= Q <= 2**32 or Q % 2 != 1:
        raise ValueError("bounded odd Q required")

    n, d, a_columns = degree, rank, columns
    total_columns = a_columns + 1
    mod2_image_dimension = n // 2
    mod2_kernel_dimension = n * total_columns - mod2_image_dimension
    modq_kernel_exponent = n * (total_columns - d)
    index_exponent = n * d - mod2_image_dimension
    return {
        "input": {"n": n, "d": d, "A_columns": a_columns,
                  "verification_columns": total_columns, "Q": Q,
                  "verification_modulus": 2 * Q},
        "matrix": "[2A | Q*zeta_star*e1-2h] mod 2Q",
        "premises": ["A=[I_d|U] over R_Q", "h is any element of R_Q^d",
                     "zeta_star=1-X^(n/2)", "R_m=(Z/mZ)[X]/(X^n+1)"],
        "coefficient_CRT": "R_(2Q) is isomorphic to R_2 x R_Q because Q is odd",
        "mod_Q": {
            "image": "R_Q^d", "surjective_for_every_U_h": True,
            "reason": "2 is a unit mod Q; A contains I_d",
            "coefficient_image_dimension": n * d,
            "kernel_cardinality": {"base": Q, "exponent": modq_kernel_exponent},
            "kernel_parametrization": "x_head=h*t-U*x_tail mod Q",
        },
        "mod_2": {
            "image": "((X+1)^(n/2) R_2)*e1",
            "other_rows_zero": True,
            "ring_identity": "X^n+1=(X+1)^n; zeta_star=(X+1)^(n/2) in characteristic 2",
            "coefficient_image_dimension": mod2_image_dimension,
            "coefficient_codimension": n * d - mod2_image_dimension,
            "kernel_coefficient_dimension": mod2_kernel_dimension,
            "kernel_parametrization": "x arbitrary; t in ann(zeta_star)=((X+1)^(n/2))",
        },
        "mod_2Q": {
            "image_via_CRT": "R_Q^d x (((X+1)^(n/2)R_2)*e1)",
            "image_cardinality": {"Q_power": n * d, "two_power": mod2_image_dimension},
            "image_index_in_full_codomain": {"base": 2, "exponent": index_exponent},
            "kernel_cardinality": {"Q_power": modq_kernel_exponent,
                                   "two_power": mod2_kernel_dimension},
            "image_independent_of_U_and_h": True,
        },
        "scope": {
            "exact_algebraic_image_and_kernel_only": True,
            "paper_theorem_q_Q_2Q_mapping": None,
            "accepted_Setup_or_seeded_planted_law": None,
            "short_kernel_or_forgery_cost": None,
            "IBS_attack_or_security_inferred": False,
            "security_claim": "none", "backend_admitted": False,
            "parameters_are_formal": False, "nist_security_category": None,
        },
    }


def build_report() -> dict:
    if sha256((ROOT / SOURCE_PDF).read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("frozen SRGG paper checksum differs")
    rows = []
    for item in profiles:
        cert = image_certificate(degree=item.degree, rank=item.rank,
                                 columns=(2 + item.digits) * item.rank, Q=item.Q)
        cert["profile"] = item.name
        cert["source_parameters"] = {"q": item.q, "Q": item.Q,
                                      "p": item.p, "w": item.digits}
        rows.append(cert)
    return {
        "schema": SCHEMA,
        "paper": {"path": SOURCE_PDF, "sha256": SOURCE_SHA256,
                  "locations": "Algorithms 7-8, PDF pp. 7-8"},
        "source_sha256": {name: sha256((ROOT / name).read_bytes()).hexdigest()
                          for name in SOURCE_FILES},
        "proof": [
            "Reduce the verification matrix coefficientwise by CRT modulo Q and modulo 2.",
            "Modulo Q, Q*zeta_star vanishes and 2 is invertible; the I_d block of A makes the image all R_Q^d.",
            "Modulo 2, all 2A and -2h columns vanish; the remaining column is zeta_star*e1.",
            "In R_2=F_2[X]/((X+1)^n), Frobenius gives zeta_star=(X+1)^(n/2); its principal ideal and annihilator each have F_2-dimension n/2.",
            "The CRT product yields the stated image, index and kernel cardinality for every Ahat, B and h.",
        ],
        "rows": rows,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(build_report(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(encoded, end="")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")


if __name__ == "__main__":
    main()
