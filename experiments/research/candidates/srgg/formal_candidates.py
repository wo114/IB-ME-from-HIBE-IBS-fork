"""Large-dimension, conditional SRGG arithmetic and resource screen.

This module does not instantiate Config, dense matrices, keys or samplers.  Its
integer inequalities are sufficient engineering geometry conditions under the
explicit density-shape convention exp(-pi*x^T*Sigma^-1*x).  They do not repair
the source's normalization, strong-security or q/Q mapping gaps.  A candidate
passing this screen remains conditional and has no admitted security level.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from fractions import Fraction
import json
from math import gcd, isqrt
from pathlib import Path

from experiments.research.primitive_spec_audit import SRGG_ROWS, srgg_row


SCHEMA = "IBME/SRGG-CONDITIONAL-CANDIDATES/1"
PAPER_SHA256 = "258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152"


def _integer(value, name, low=1, high=None):
    if type(value) is not int or value < low or (high is not None and value > high):
        raise ValueError("bounded exact integer required: " + name)
    if value.bit_length() > 4096:
        raise ValueError("candidate integer resource limit exceeded: " + name)
    return value


@dataclass(frozen=True)
class Candidate:
    """Arithmetic study input, deliberately separate from the executable Config.

    All squared widths below use the density-shape convention, not physical
    standard deviations. raw_norm_squared_cap is an assumed acceptance cap for
    the approximate extracted vector. No probability of satisfying it is given.
    """

    name: str
    degree: int
    rank: int
    p: int
    base: int
    digits: int
    r_squared: int
    master_first_squared: int
    master_second_squared: int
    signature_first_squared: int
    signature_second_squared: int
    raw_norm_squared_cap: int
    user_norm_squared_cap: int
    signature_norm_squared_cap: int
    smoothing_epsilon_bits: int = 80
    sign_max_attempts: int = 16

    def __post_init__(self):
        if not isinstance(self.name, str) or not 1 <= len(self.name) <= 128:
            raise ValueError("bounded public candidate name required")
        _integer(self.degree, "degree", 2, 2**16)
        if self.degree & (self.degree-1):
            raise ValueError("power-of-two polynomial degree required")
        for name, maximum in (("rank", 32), ("p", 2**32-1),
                              ("base", 2**16-1), ("digits", 32),
                              ("r_squared", 4096), ("smoothing_epsilon_bits", 256),
                              ("sign_max_attempts", 2**16)):
            _integer(getattr(self, name), name, high=maximum)
        for name in ("master_first_squared", "master_second_squared",
                     "signature_first_squared", "signature_second_squared",
                     "raw_norm_squared_cap", "user_norm_squared_cap",
                     "signature_norm_squared_cap"):
            _integer(getattr(self, name), name)

    @property
    def columns(self):
        return (2+self.digits)*self.rank

    @property
    def modulus(self):
        return self.p*self.base**self.digits


def smoothing_certificate(dimension: int, r_squared: int, epsilon_bits: int) -> dict:
    """Elementary exact sufficient bound on rho_(1/r) over nonzero Z^D.

    Since pi > 2*ln(2), a=2^(-2*r^2) bounds exp(-pi*r^2). The inequalities
    k^2 >= 1+3(k-1) and binomial(D,k) <= D^k give theta(r)^D-1 <=
    D*t/(1-D*t), t=2*a/(1-a^3), when D*t<1. This is only a Z^D
    smoothing certificate; it is not a certificate for SampleF's full law.
    """

    _integer(dimension, "dimension", high=2**32)
    _integer(r_squared, "r_squared", high=4096)
    _integer(epsilon_bits, "epsilon_bits", high=256)
    a = Fraction(1, 2**(2*r_squared))
    t = 2*a/(1-a**3)
    x = dimension*t
    bound = x/(1-x) if x < 1 else None
    epsilon = Fraction(1, 2**epsilon_bits)
    return {
        "lattice": "Z^dimension with Euclidean norm",
        "dimension": dimension,
        "density_shape_r_squared": r_squared,
        "epsilon": str(epsilon),
        "dual_gaussian_mass_upper": None if bound is None else str(bound),
        "sufficient_smoothing_condition_passes": bound is not None and bound <= epsilon,
        "method": "exact rational geometric-series bound using pi>2*ln(2)",
        "scope": "rounding lattice only; excludes convolution, finite arithmetic and composition errors",
    }


def geometry_bounds(candidate: Candidate) -> dict:
    """Conservative all-witness sufficient positivity, without dense operators.

    CBD1 support gives ||M(R)||_F^2 <= 2*d^2*w*n^2. For the signing column,
    ||M(y)||_F^2 = n*||y||^2 <= n*U. Stacking identity adds one to the
    squared spectral bound. A minimum target eigenvalue greater than
    noise_squared*bound+r_squared ensures strict positive residual shape.
    """

    c = candidate
    root = 2*c.rank*c.rank*c.digits*c.degree*c.degree+1
    user = c.degree*c.user_norm_squared_cap+1
    master_minimum_exclusive = c.base**2*c.r_squared*root+c.r_squared
    signing_minimum_exclusive = 2*c.r_squared*user+c.r_squared
    corrected_norm_cap = 2*c.raw_norm_squared_cap+2*c.rank*c.degree*(c.p-1)**2
    gates = {
        "odd_p_and_base_at_least_three": c.p >= 3 and c.base >= 3 and c.p % 2 == c.base % 2 == 1,
        "coprime_p_and_gadget_base": gcd(c.p, c.base) == 1,
        "master_residual_strictly_positive_sufficient": min(
            c.master_first_squared, c.master_second_squared) > master_minimum_exclusive,
        "signature_residual_strictly_positive_sufficient": min(
            c.signature_first_squared, c.signature_second_squared) > signing_minimum_exclusive,
        "hnf_user_cap_covers_assumed_raw_cap": c.user_norm_squared_cap >= corrected_norm_cap,
        "conditional_Q_gt_2_gamma_exact": c.modulus**2 > 4*c.signature_norm_squared_cap,
        "Q_odd": c.modulus % 2 == 1,
    }
    return {
        "gates": gates,
        "all_arithmetic_gates_pass": all(gates.values()),
        "master_stacked_operator_spectral_squared_upper": root,
        "signing_stacked_operator_spectral_squared_upper": user,
        "master_minimum_width_squared_exclusive": master_minimum_exclusive,
        "signing_minimum_width_squared_exclusive": signing_minimum_exclusive,
        "hnf_corrected_norm_squared_cap": corrected_norm_cap,
        "signature_target_trace": c.degree*(2*c.rank*c.signature_first_squared
                                               +(c.rank*c.digits+1)*c.signature_second_squared),
        "density_shape_noise_factor": 2,
        "norm_cap_satisfaction_probability": None,
        "assumed_raw_norm_cap_enforced_by_current_backend": False,
        "hnf_key_distribution_certified": False,
        "q_mapping_assumption": "Theorem 1 odd q is provisionally identified with Q, not even 2Q",
        "q_mapping_verified": False,
        "theorem1_s1_eta_condition_verified": False,
        "full_source_theorem_conditions_checked": False,
    }


def _ldl_updates(dimension):
    # Exactly sum_{i=0}^{D-1} (D-i-1)*(D-i)/2 in positive_pivots().
    return dimension*(dimension-1)*(dimension+1)//6


def resource_model(candidate: Candidate) -> dict:
    """Count actual matrix shapes and modeled arithmetic, without allocating them.

    Memory scenarios describe one matrix's entry payload at an assumed byte
    count. They exclude Python/Sage objects, containers, temporaries and
    rational numerator/denominator growth. They are not peak-memory estimates.
    """

    c = candidate
    n, d, w, columns = c.degree, c.rank, c.digits, c.columns
    extraction, signing = columns*n, (columns+1)*n
    extraction_lower, extraction_upper = w*d*n, 2*d*n
    signing_lower, signing_upper = n, columns*n

    def matrix_model(total, upper, lower):
        entries = total**2
        return {
            "coefficient_dimension": total,
            "single_dense_square_entries": entries,
            "single_dense_matrix_payload_scenarios_bytes": {
                str(bytes_per_entry): entries*bytes_per_entry for bytes_per_entry in (16, 64, 2048)
            },
            "initial_stacked_gram_scalar_multiplications": entries*lower,
            "full_shape_ldl_rational_updates": _ldl_updates(total),
            "shifted_schur_ldl_rational_updates": _ldl_updates(upper),
            "upper_shape_dimension": upper,
            "lower_scalar_block_dimension": lower,
            "module_square_polynomial_count": (total//n)**2,
            "module_square_coefficient_count": (total//n)**2*n,
            "dense_to_module_coefficient_ratio": n,
        }

    public_b = d*d*w*n
    root_r = 2*d*d*w*n
    tail = (columns-d)*n
    response = signing
    public_bits = (c.modulus-1).bit_length()
    # Explicit hypothetical offset encoding of each signed coefficient.
    tail_bits = (2*isqrt(c.user_norm_squared_cap)).bit_length()
    response_bits = (2*isqrt(c.signature_norm_squared_cap)).bit_length()
    return {
        "master_geometry": matrix_model(extraction, extraction_upper, extraction_lower),
        "signature_geometry": matrix_model(signing, signing_upper, signing_lower),
        "materialization": {
            "public_b_coefficients": public_b,
            "root_r_coefficients": root_r,
            "signing_tail_coefficients": tail,
            "signing_full_vector_coefficients": extraction,
            "response_coefficients": response,
            "structured_signature_witness_coefficients": extraction,
        },
        "hypothetical_fixed_width_component_payload_bytes": {
            "encoding_status": "counting model only; encoder, framing and snapshots not implemented here",
            "public_b_plus_seed": (public_b*public_bits+7)//8+32,
            "root_r_cbd1_two_bits_per_coefficient": (2*root_r+7)//8,
            "signing_tail_offset_encoding": (tail*tail_bits+7)//8,
            "response_context_and_binary_challenge": (response*response_bits+7)//8+32+(n+7)//8,
            "public_coefficient_bits": public_bits,
            "tail_signed_offset_bits": tail_bits,
            "response_signed_offset_bits": response_bits,
        },
        "online_logical_draws": {
            "extraction_gaussian_scalars": extraction,
            "extraction_gadget_digit_draws": w*d*n,
            "extraction_continuous_tickets": 2*d*n,
            "sign_attempt_gaussian_scalars": signing+n,
            "sign_attempt_continuous_tickets": columns*n,
            "sign_operation_max_gaussian_scalars": c.sign_max_attempts*(signing+n),
        },
        "schoolbook_ring_arithmetic": {
            "coefficient_products_per_negacyclic_product": n*n,
            "public_A_times_vector_ring_products": d*columns,
            "public_A_times_vector_coefficient_products": d*columns*n*n,
            "signature_commitment_ring_products": d*(columns+1),
            "signature_commitment_coefficient_products": d*(columns+1)*n*n,
            "response_update_ring_products": columns+2,
            "response_relation_check_ring_products": d*(columns+1),
            "response_total_ring_products": columns+2+d*(columns+1),
            "response_total_coefficient_products": (columns+2+d*(columns+1))*n*n,
            "response_count_scope": "current response_from_values including signing_relation; excludes caller's other work",
        },
        "runtime_observations": {
            "dense_geometry_dimension_limit": 128,
            "current_scalar_squared_width_limit": 10**12,
            "within_dense_geometry_dimension_limit": signing <= 128,
            "within_current_scalar_width_limit": max(
                c.master_second_squared-c.base**2*c.r_squared,
                c.signature_second_squared-2*c.r_squared, c.r_squared) <= 10**12,
            "current_backend_executable": False,
            "reason": "candidate is not a Config; Params, objects, wire and dense sampler admission remain separate",
        },
        "timing_measurement": None,
        "peak_memory_measurement": None,
        "rational_bit_growth_bound": None,
        "memory_model_scope": "single matrix payload scenarios; no object overhead or simultaneous workspaces",
        "arithmetic_model_scope": "current dense Gram and exact LDL loops; excludes all other work",
    }


def screen_candidate(candidate: Candidate) -> dict:
    if not isinstance(candidate, Candidate):
        raise TypeError("explicit conditional Candidate required")
    geometry = geometry_bounds(candidate)
    smoothing = smoothing_certificate((candidate.columns+1)*candidate.degree,
                                       candidate.r_squared, candidate.smoothing_epsilon_bits)
    return {
        "name": candidate.name,
        "parameters": asdict(candidate),
        "density_convention": "exp(-pi*x^T*Sigma^-1*x); continuous physical covariance Sigma/(2*pi)",
        "Q": candidate.modulus,
        "geometry": geometry,
        "rounding_lattice_smoothing": smoothing,
        "conditional_arithmetic_candidate": geometry["all_arithmetic_gates_pass"] and smoothing[
            "sufficient_smoothing_condition_passes"],
        "resources": resource_model(candidate),
        "generic_recovery_projection": {
            "equations_and_secret_dimension": candidate.rank*candidate.degree,
            "secret_plus_error_lattice_dimension": 2*candidate.rank*candidate.degree+1,
            "public_root_right_hand_sides": candidate.rank*candidate.digits,
            "interpretation": "source Section 5.2 per-column generic LWE projection; shared matrix across columns",
            "classical_attack_bits": None,
            "quantum_attack_bits": None,
            "estimator_validated": False,
        },
        "unclosed_conditions": [
            "source physical-standard-deviation versus density-shape normalization",
            "source Table 3 versus zeta-induced factor2 and exact theorem q/Q correspondence",
            "raw and reconstructed user-key law, Gaussian tail probability and fixed-service query losses",
            "full finite SampleF, convolution and gadget-to-key total-TV and abort budget",
            "underlying strong-unforgeability premise and required composition security model",
            "validated generic and structure-specific attack estimates with reduction losses",
            "structured implementation, wire lifecycle, measurements and HIBE composition",
        ],
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
        "nist_security_category": None,
    }


def conditional_candidate(*, degree=512, rank=2, digits=8, raw_norm_multiplier=16) -> Candidate:
    """Build an explicit algebraically sufficient study point, not a secure preset.

    The raw norm cap is an engineering input (multiplier times target trace).
    The extraction law and its tail are unproved, so the multiplier carries no
    acceptance-probability claim. HNF's deterministic coarse bound propagates
    this assumed cap to the user cap. Q and all widths are then screened.
    """

    _integer(degree, "degree", 2, 2**16)
    _integer(rank, "rank", high=32)
    _integer(digits, "digits", high=32)
    _integer(raw_norm_multiplier, "raw_norm_multiplier", high=2**16)
    p, base, r_squared = 2**14-1, 31, 64
    columns = (2+digits)*rank
    root_bound = 2*rank*rank*digits*degree*degree+1
    master_squared = base**2*r_squared*root_bound+r_squared+1
    raw_cap = raw_norm_multiplier*columns*degree*master_squared
    user_cap = 2*raw_cap+2*rank*degree*(p-1)**2
    signature_squared = 2*r_squared*(degree*user_cap+1)+r_squared+1
    signature_cap = (columns+1)*degree*signature_squared
    return Candidate(f"conditional-n{degree}-d{rank}-w{digits}", degree, rank, p, base, digits,
                     r_squared, master_squared, master_squared, signature_squared, signature_squared,
                     raw_cap, user_cap, signature_cap)


def source_rows() -> list[dict]:
    """Published arithmetic, kept separate from the density-shape candidates."""

    result = []
    for row in SRGG_ROWS:
        checked = srgg_row(row)
        result.append({
            "name": row["name"],
            "degree": checked["polynomial_degree"],
            "rank": row["rank"],
            "digits": checked["gadget_dimension"],
            "p": checked["p"],
            "Q": checked["modulus_Q"],
            "gamma_squared_exact_decimal_reading": str(Fraction(row["gamma"])**2),
            "literal_Q_gt_2_gamma": checked["literal_Q_gt_2gamma"],
            "literal_even_2Q_gt_2_gamma": checked["literal_2Q_gt_2gamma"],
            "normalization_verified": False,
            "strong_signature_premise_verified": False,
            "parameters_are_formal": False,
            "source_pages": [4, 9, 10],
        })
    return result


def search_gadget_digits(*, degree=512, rank=2, maximum_digits=8) -> dict:
    """Finite search under the builder's explicit cap/width assumptions only."""

    _integer(maximum_digits, "maximum_digits", 2, 32)
    trials = []
    for digits in range(2, maximum_digits+1):
        candidate = conditional_candidate(degree=degree, rank=rank, digits=digits)
        screened = screen_candidate(candidate)
        trials.append({
            "digits": digits,
            "Q": candidate.modulus,
            "signature_coefficient_dimension": (candidate.columns+1)*candidate.degree,
            "arithmetic_passes": screened["conditional_arithmetic_candidate"],
            "failed_gates": [name for name, passes in screened["geometry"]["gates"].items() if not passes],
        })
    return {
        "degree": degree, "rank": rank, "trials": trials,
        "first_passing_digits": next((trial["digits"] for trial in trials if trial["arithmetic_passes"]), None),
        "interpretation": "first arithmetic pass within this finite search; no security or performance optimum",
    }


def build_report() -> dict:
    return {
        "schema": SCHEMA,
        "scope": "HIBE-independent conditional arithmetic and resource counting; no cryptographic execution",
        "paper": {"doi": "10.1049/ise2/6684889", "reviewed_sha256": PAPER_SHA256},
        "source_rows": source_rows(),
        "conditional_candidates": [screen_candidate(conditional_candidate(rank=d)) for d in (2, 3, 4)],
        "gadget_digit_search": [search_gadget_digits(rank=d) for d in (2, 3, 4)],
        "kyber_nist_comparison": {
            "reference": "NIST FIPS 203 ML-KEM; resource and independently estimated security targets only",
            "source": "https://doi.org/10.6028/NIST.FIPS.203",
            "nist_category_inferred": False,
            "reason": "KEM and IBS are different primitives; candidate attack and reduction estimates are unvalidated",
        },
        "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(build_report(), ensure_ascii=False, indent=2, sort_keys=True)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8", newline="\n")
    print(encoded, end="")


if __name__ == "__main__":
    main()
