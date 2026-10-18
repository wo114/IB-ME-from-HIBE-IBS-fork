"""Exact public short-kernel cost and limits for the original SRGG rows.

This is not a BKZ estimator or a claim about full IBS forgery probability.
The short vector works for every public A because the verification matrix
contains 2A modulo 2Q. A same-message replacement still needs the altered
response to pass the paper's norm gate.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path

from .paper_hardness_preflight import coefficient_crt, multiplicative_order
from .paper_profiles import SOURCE_PDF, SOURCE_SHA256, profiles


SCHEMA = "IBME/SRGG-PAPER-STRUCTURAL-COST/1"
ROOT = Path(__file__).resolve().parents[4]
SOURCE_FILES = (
    "experiments/research/candidates/srgg/paper_structural_cost.py",
    "experiments/research/candidates/srgg/paper_profiles.py",
    "experiments/research/candidates/srgg/paper_hardness_preflight.py",
    "experiments/research/candidates/srgg/paper_verification_image.py",
    "experiments/research/candidates/srgg/structured_execution.py",
)


def _source_digest(path: str) -> str:
    # Git stores LF while the Windows checkout can materialize CRLF. Only
    # line endings are normalized; every other source-byte change is bound.
    return sha256((ROOT / path).read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def one_shift_norm(*, norm_squared: int, max_abs_a_coordinate: int,
                   modulus: int, norm_cap: int) -> dict:
    """Exact best norm among single +/-Q shifts of the 2A response block.

    The caller supplies the norm of a known valid response and the largest
    absolute coefficient in its first A-columns. No signature or secret is
    sampled or read here. An eligible response yields a distinct valid
    signature for the same identity and message under the unchanged hash.
    """
    for name, value in (("norm_squared", norm_squared),
                        ("max_abs_a_coordinate", max_abs_a_coordinate),
                        ("norm_cap", norm_cap)):
        if type(value) is not int or value < 0:
            raise ValueError(name + " must be an exact nonnegative integer")
    if type(modulus) is not int or modulus < 3 or modulus % 2 == 0:
        raise ValueError("exact odd modulus at least three required")
    if max_abs_a_coordinate**2 > norm_squared:
        raise ValueError("coordinate magnitude exceeds stated vector norm")
    if norm_squared > norm_cap:
        raise ValueError("input must satisfy the original norm gate")
    candidate = norm_squared + modulus**2 - 2 * modulus * max_abs_a_coordinate
    return {"best_single_shift_norm_squared": candidate,
            "accepted_by_norm_gate": candidate <= norm_cap,
            "commitment_unchanged_for_every_public_A": True,
            "same_message_challenge_unchanged": True,
            "scan_integer_operations": "linear in number of A-block coefficients",
            "BKZ_calls": 0,
            "scope": "conditional on an already valid source signature"}


def subring_projection_obstruction(*, degree: int, subring_degree: int = 8) -> dict:
    """A concrete counterexample to treating sparse subring projection as a map.

    P keeps only coefficients indexed by multiples of stride=n/subring_degree.
    P(X)=P(X^(stride-1))=0, whereas P(X*X^(stride-1))=Y. This says
    nothing about a true quotient-field CRT projection, which is a ring map.
    """
    if (type(degree) is not int or type(subring_degree) is not int
            or degree < 4 or degree > 512 or degree & (degree - 1)
            or subring_degree < 2 or subring_degree >= degree
            or degree % subring_degree):
        raise ValueError("bounded power-of-two degree and proper subring required")
    stride = degree // subring_degree
    if stride < 2:
        raise ValueError("stride at least two required")
    return {"ambient_ring": f"Z_Q[X]/(X^{degree}+1)",
            "sparse_subring": f"Z_Q[Y]/(Y^{subring_degree}+1), Y=X^{stride}",
            "embedding_preserves_coefficient_l2_norm": True,
            "naive_coefficient_projection_is_ring_homomorphism": False,
            "counterexample": {"a": "X", "s": f"X^{stride-1}",
                               "P_a": "0", "P_s": "0", "P_a_times_s": "Y"},
            "subfield_or_subring_attack_cost_inferred": False}


def row_certificate(source) -> dict:
    n, d, w, Q = source.degree, source.rank, source.digits, source.Q
    gamma = Fraction(source.gamma)
    norm_cap = (gamma**2).numerator // (gamma**2).denominator
    columns_a = (2 + w) * d
    response_coefficients = (columns_a + 1) * n
    a_coefficients = columns_a * n
    scalar_kernel_bound = 2 * gamma
    if not (Q < scalar_kernel_bound and Q < gamma):
        raise AssertionError("published Table 4 row no longer has the audited short vector")
    components = coefficient_crt(Q)
    crt = []
    for item in components:
        prime = item["prime"]
        factor_degree = multiplicative_order(prime, 2 * n)
        crt.append({"prime": prime, "prime_power": item["prime_power"],
                    "residue_factor_degree": factor_degree,
                    "residue_factor_count": n // factor_degree,
                    "Qe0_is_zero_in_component": Q % item["prime_power"] == 0,
                    "factor_degree_is_attack_cost": False})
    return {
        "profile": source.name,
        "original_inputs": {"n": n, "d": d, "w": w, "Q": Q,
                            "gamma_published_decimal": str(source.gamma),
                            "gamma_exact_rational": str(gamma),
                            "signature_norm_squared_cap": norm_cap,
                            "A_module_columns": columns_a,
                            "response_coefficient_count": response_coefficients},
        "Q_MSIS_short_kernel": {
            "witness": "Q times one coefficient basis vector in an identity-block column",
            "nonzero_over_integers": True, "zero_mod_Q_for_every_public_matrix": True,
            "euclidean_norm": Q, "strictly_below_2gamma": Q < scalar_kernel_bound,
            "one_coordinate_identity_block_minimal_nonzero_scalar_kernel_norm": Q,
            "sparse_output_nonzero_coefficients": 1,
            "sparse_construction_public_matrix_reads": 0,
            "sparse_construction_BKZ_calls": 0,
            "dense_output_coefficients": response_coefficients,
            "scope": "search for any nonzero integer kernel vector with bound 2gamma; not target preimage or master-secret recovery"},
        "actual_2Q_verification": {
            "matrix": "[2A | Q*zeta_star*e1-2h] mod 2Q",
            "universal_kernel_witness": "Q times one coefficient basis vector in any of the first A columns",
            "identity": "2*A*(Q*e_i)=0 mod 2Q for every A,h",
            "eligible_shift_coordinates": a_coefficients,
            "zero_mod_2Q_for_every_public_A_h": True,
            "witness_inside_original_signature_norm_ball": Q**2 <= norm_cap,
            "sufficient_original_norm_for_any_single_Q_shift": str(gamma - Q),
            "best_shift_test": "S+Q^2-2Q*max_abs_A <= floor(gamma^2)",
            "best_shift_example_zero_response": one_shift_norm(
                norm_squared=0, max_abs_a_coordinate=0,
                modulus=Q, norm_cap=norm_cap),
            "valid_signature_replacement_probability": None,
            "known_valid_signature_required": True,
            "native_strong_game_implication": "A successful norm-eligible same-message replacement conflicts with sEUF; eligibility is not universal"},
        "CRT": crt,
        "subring_degree8": subring_projection_obstruction(degree=n),
        "author_report": {"key_recovery_classical_core_SVP_bits": source.author_report.key_recovery_classical_bits,
                          "forgery_classical_core_SVP_bits": source.author_report.forgery_classical_bits,
                          "author_targets_are_not_this_kernel_search": True,
                          "author_BKZ_costs_reproduced": False},
        "actual_full_ring_HNF_or_structural_CVP_cost": None,
        "actual_CRT_or_subfield_attack_cost": None,
        "actual_accepted_setup_root_attack_success": None,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
    }


def build_report() -> dict:
    if sha256((ROOT / SOURCE_PDF).read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("frozen source PDF checksum differs")
    rows = [row_certificate(item) for item in profiles]
    return {"schema": SCHEMA,
            "paper": {"path": SOURCE_PDF, "sha256": SOURCE_SHA256,
                      "locations": "Theorem 1 PDF p.4; Algorithms 7-8 PDF pp.7-8; sections 5.2.1-5.2.3 and Tables 4-5 PDF pp.9-10"},
            "source_sha256": {path: _source_digest(path)
                              for path in SOURCE_FILES},
            "source_hash_line_endings": "CRLF normalized to LF only",
            "proof_scope": "universal Q-kernel construction, exact one-coordinate norm test and a counterexample to naive sparse-subring projection",
            "rows": rows,
            "real_signature_trials": 0, "BKZ_executions": 0,
            "formal_security_bits": None,
            "security_claim": "none", "backend_admitted": False,
            "parameters_are_formal": False, "nist_security_category": None}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("--output already exists")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(build_report(), indent=2, sort_keys=True) + "\n",
                           encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
