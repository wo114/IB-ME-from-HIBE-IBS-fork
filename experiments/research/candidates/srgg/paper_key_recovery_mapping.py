"""Recompute generic key-recovery inputs for frozen SRGG Table 4 rows.

The beta calculation is the paper's approximate Core-SVP model, not an
independent attack estimate or security admission. No secret is sampled.
"""
from __future__ import annotations

from hashlib import sha256
from math import exp, log, pi, sqrt
from pathlib import Path

from .paper_profiles import SOURCE_PDF, SOURCE_SHA256, profiles


ROOT = Path(__file__).resolve().parents[4]


def log_delta(beta: int) -> float:
    """Section 5.2.1's approximate root-Hermite factor, in natural logs."""
    if type(beta) is not int or beta <= 50:
        raise ValueError("the printed approximation requires integer beta > 50")
    return (log(beta) + log(pi * beta) / beta - log(2 * pi) - 1) / (2 * (beta - 1))


def log_margin(*, m: int, dimension: int, modulus: int,
               beta: int, witness_norm: float) -> float:
    """Log(RHS/LHS) of Section 5.2.2's displayed success condition."""
    if (type(m) is not int or type(dimension) is not int or type(modulus) is not int
            or m <= 0 or dimension != 2 * m + 1 or modulus <= 1
            or not 50 < beta <= dimension or witness_norm <= 0):
        raise ValueError("bounded printed key-recovery inputs required")
    return ((2 * beta - dimension - 1) * log_delta(beta)
            + m / dimension * log(modulus)
            - log(witness_norm) - 0.5 * log(beta / dimension))


def first_beta(*, m: int, dimension: int, modulus: int,
               witness_norm: float) -> int | None:
    """Smallest integer satisfying the paper's *approximate* inequality."""
    return next((beta for beta in range(51, dimension + 1)
                 if log_margin(m=m, dimension=dimension, modulus=modulus,
                               beta=beta, witness_norm=witness_norm) >= 0), None)


def row(profile) -> dict:
    n, rank, modulus = profile.degree, profile.rank, profile.Q
    m, columns = rank * n, rank * profile.digits
    dimension = 2 * m + 1
    beta = profile.author_report.key_recovery_bkz
    support_norm = sqrt(dimension)  # 2m CBD1 entries plus the final -1.
    rms_norm = sqrt(m + 1)         # E[||R_j||²]=2m*(1/2)=m, before filtering.
    common = {"m": m, "dimension": dimension, "modulus": modulus}
    log_max_norm = ((2 * beta - dimension - 1) * log_delta(beta)
                    + m / dimension * log(modulus)
                    - 0.5 * log(beta / dimension))
    return {
        "profile": profile.name, "n": n, "rank": rank, "Q": modulus,
        "gadget_columns": columns, "coefficient_rows_m": m,
        "q_ary_kernel_dimension_D": dimension,
        "q_ary_kernel_determinant": f"{modulus}^{m}",
        "honest_unfiltered_coefficient_support": [-1, 0, 1],
        "honest_unfiltered_nonzero_probability": "1/2",
        "squared_norm_min_including_minus_one": 1,
        "squared_norm_max_including_minus_one": dimension,
        "squared_norm_expectation_before_setup_filter": m + 1,
        "author_reported_key_recovery_beta": beta,
        "author_reported_classical_core_svp_bits":
            profile.author_report.key_recovery_classical_bits,
        "author_reported_quantum_core_svp_bits":
            profile.author_report.key_recovery_quantum_bits,
        "max_witness_norm_at_author_beta_approx": exp(log_max_norm),
        "unfiltered_rms_norm_surrogate": rms_norm,
        "full_support_norm_upper": support_norm,
        "log_margin_at_author_beta_rms_surrogate": log_margin(
            **common, beta=beta, witness_norm=rms_norm),
        "log_margin_at_author_beta_support_upper": log_margin(
            **common, beta=beta, witness_norm=support_norm),
        "first_beta_using_rms_surrogate_approx": first_beta(
            **common, witness_norm=rms_norm),
        "first_beta_using_support_upper_approx": first_beta(
            **common, witness_norm=support_norm),
        "accepted_root_norm_distribution_known": False,
    }


def report() -> dict:
    if sha256((ROOT / SOURCE_PDF).read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("frozen Jia paper checksum mismatch")
    return {
        "schema": "IBME/SRGG-PAPER-KEY-RECOVERY-MAPPING/1",
        "paper_sha256": SOURCE_SHA256,
        "paper_locations": "Algorithm 1 p.7; Section 5.2.1-2 p.9; Tables 4-5 p.10",
        "rows": [row(profile) for profile in profiles],
        "interpretation": "one public B column gives Ahat*s+e=F_j-B_j; beta values are model sensitivity only",
        "author_table5_security_bits_reproduced": None,
        "actual_primal_attack_cost_bits": None,
        "complete_ring_hnf_crt_subfield_attack_cost": None,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(report(), indent=2, sort_keys=True))
