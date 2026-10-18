"""Map the paper's forgery-CVP discussion to the literal Table 4 verifier.

This reports exact affine-lattice inputs, not a short solution, attack cost,
or the author's Table 5 bit-security estimates.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

from .paper_profiles import SOURCE_PDF, SOURCE_SHA256, profiles
from .paper_verification_image import image_certificate


ROOT = Path(__file__).resolve().parents[4]
SCHEMA = "IBME/SRGG-PAPER-FORGERY-INPUT-MAPPING/1"


def row_certificate(item) -> dict:
    image = image_certificate(
        degree=item.degree, rank=item.rank,
        columns=(2 + item.digits) * item.rank, Q=item.Q,
    )
    n, d, Q = item.degree, item.rank, item.Q
    if image["mod_2Q"]["image_cardinality"] != {
        "Q_power": n * d, "two_power": n // 2,
    }:
        raise ValueError("verification image premise differs")
    gamma_squared_floor = int(item.gamma * item.gamma)
    return {
        "profile": item.name,
        "degree": n,
        "module_rank": d,
        "Q": Q,
        "verification_modulus": 2 * Q,
        "verification_columns_over_ring": (2 + item.digits) * d + 1,
        "integer_response_dimension": ((2 + item.digits) * d + 1) * n,
        "integer_target_dimension": d * n,
        "integer_kernel_determinant": {"Q_power": d * n, "two_power": n // 2},
        "image_index_in_full_target": image["mod_2Q"]["image_index_in_full_codomain"],
        "affine_target": "w + Q*j*c mod 2Q",
        "affine_membership": "w mod 2 lies in (zeta_star*R_2)*e1",
        "zero_commitment_is_reachable_for_every_binary_challenge": True,
        "gamma": str(item.gamma),
        "squared_norm_cap": gamma_squared_floor,
        "author_reported_forgery_bkz": item.author_report.forgery_bkz,
        "actual_short_solution_or_attack_cost": None,
        "author_table5_forgery_bits_reproduced": False,
    }


def build_report() -> dict:
    digest = sha256((ROOT / SOURCE_PDF).read_bytes()).hexdigest()
    if digest != SOURCE_SHA256:
        raise ValueError("frozen SRGG paper checksum differs")
    return {
        "schema": SCHEMA,
        "paper": {"path": SOURCE_PDF, "sha256": digest,
                  "locations": "Algorithms 7-8 p.8; Section 5.2.3 pp.9-10; Tables 4-5 p.10"},
        "premises": [
            "M=[2A|Q*j-2h] mod 2Q with A=[I_d|Ahat|B] and j=zeta_star*e1",
            "verify recovers w=M*z-Q*j*c and checks c=Hbar_P(w,message)",
            "fixed (w,c) solutions form a coset of the integer kernel of M modulo 2Q",
            "M*(h*c,0,...,0,c)=Q*j*c; therefore Q*j*c lies in im(M)",
            "the norm gate is ||z||^2 <= floor(gamma^2)",
        ],
        "rows": [row_certificate(item) for item in profiles],
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
        args.output.write_bytes(encoded.encode("utf-8"))


if __name__ == "__main__":
    main()
