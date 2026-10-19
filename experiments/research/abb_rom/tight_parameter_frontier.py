"""Tighter public ABB-ROM parameter frontier with explicit research premises.

This probe changes two projection choices without changing the ABB algorithms:

* choose the smallest AP09 random block that satisfies the checked LHL and
  strict ``m > 6*n*ceil(log2(q))`` conditions instead of fixing ``d=2*n*k``;
* replace the deterministic ``m^2*radius^2`` operator-norm square bound for an
  unconditioned finite SampleR matrix by a rectangular matrix-Bernstein bound.

The Bernstein calculation applies to independent, bounded, exactly symmetric
finite scalar outputs before conditioning the whole matrix on invertibility.
A separate max-atom/column-span certificate proves that the finite matrix is
invertible with probability greater than one half, so the operator event loses
at most one bit under that conditioning.  This still does not complete ABB's
finite-sampler proof mapping.  The output is therefore a numerical research
frontier, never a formal parameter or backend admission.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
from math import isfinite, isqrt
import os
from pathlib import Path
import platform
import resource
import sys
import time

from sage.all import QQ, ZZ, previous_prime

from ibme.lattice.chkp.joint_parameters import smoothing_factor
from ibme.lattice.chkp.noise_budget import RoundedNoiseParams
from ibme.lattice.chkp.rounded_noise import build_rounded_noise
from ibme.lattice.matrix_sampling import MatrixFiniteGaussian, MatrixFiniteOptions

from .noise_tradeoff_probe import (
    ANCHOR_Q,
    CIPHERTEXT_REQUIRED_ESTIMATES,
    COMPARISON_BITS,
    FINITE_SCALED_WIDTH,
    Q208,
    ROOT_REQUIRED_ESTIMATES,
)
from .scaled_parameter_screen import (
    _abb_root_trapdoor_role,
    _ciphertext_role,
    conditional_noise,
    maximum_abb_scaled_width,
    run_estimators,
    strict_noise_width,
)


SCHEMA = "A/ABB-TIGHT-PARAMETER-FRONTIER/1"
RUNTIME_SCHEMA = "A/ABB-TIGHT-PARAMETER-FRONTIER-RUNTIME/1"
BASELINE_SCHEMA = "A/ABB-NOISE-TRADEOFF/3"
BITS = 128
LHL_TARGET_BITS = 130
SAMPLE_R_SCALAR_BITS = 224
MATRIX_ORACLE_CALLS = 2**20
PAYLOAD_BITS = 256
SERVICE_STATISTICAL_TARGET_BITS = 128
OPERATOR_SERVICE_BUDGET_BITS = SERVICE_STATISTICAL_TARGET_BITS + 1
SAMPLE_R_RANK_SERVICE_BUDGET_BITS = SERVICE_STATISTICAL_TARGET_BITS + 2
OPERATOR_CONDITIONAL_TAIL_BITS = (
    OPERATOR_SERVICE_BUDGET_BITS + (MATRIX_ORACLE_CALLS.bit_length() - 1)
)
OPERATOR_UNCONDITIONED_TAIL_BITS = OPERATOR_CONDITIONAL_TAIL_BITS + 1
CIPHERTEXT_EVENT_SERVICE_BUDGET_BITS = SERVICE_STATISTICAL_TARGET_BITS + 2
CIPHERTEXT_BIT_EVENTS = MATRIX_ORACLE_CALLS * PAYLOAD_BITS
CIPHERTEXT_PER_BIT_EVENT_BITS = (
    CIPHERTEXT_EVENT_SERVICE_BUDGET_BITS + (CIPHERTEXT_BIT_EVENTS.bit_length() - 1)
)
CIPHERTEXT_NOISE_TAIL_BITS = 224
CIPHERTEXT_NOISE_MASS_BITS = 320
CIPHERTEXT_NOISE_PRECISION_BITS = 384
CIPHERTEXT_NOISE_MAX_RADIUS = 16384
PRIVATE_ENTRY_WIRE_FLOOR = 6
TESTED_ROWS = ((8192, 179), (8192, 180), (8224, 180), (8704, 180))
RECOMMENDED_ID = "abb-rom-tight-n8224-q180-chi721"
BASELINE_CANDIDATE_ID = "abb-rom-n9600-q208-chi721"
BASELINE_DIMENSION = 15_974_400
BASELINE_BASIS_BYTES = 1_531_088_732_160_000
BASELINE_CIPHERTEXT_BYTES = 106_325_613_056


def _integer(value, name, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} requires an exact integer in {minimum}..{maximum}")
    return value


def _ceil_div(numerator, denominator):
    return (numerator + denominator - 1) // denominator


def _ceil_sqrt(value):
    value = _integer(value, "square-root input", 0, 2**8192)
    root = isqrt(value)
    return root + int(root * root < value)


def _ceil_sqrt_fraction(value):
    value = Fraction(value)
    if value < 0:
        raise ValueError("nonnegative rational square-root input required")
    root = isqrt(value.numerator // value.denominator)
    return root + int(Fraction(root * root) < value)


def _as_fraction(value):
    value = QQ(value)
    return Fraction(int(value.numerator()), int(value.denominator()))


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def matrix_sampler_options():
    """Finite scalar profile whose declared 2^20-matrix TV budget stays <2^-128."""
    return MatrixFiniteOptions(
        tail_bits=SAMPLE_R_SCALAR_BITS,
        mass_bits=320,
        precision_bits=384,
        gaussian_abort_bits=SAMPLE_R_SCALAR_BITS,
        max_uniform_trials=320,
        max_gaussian_trials=1_000_000,
    )


def build_frontier_finite_noise_certificate():
    """Build the stronger q*alpha=721 CDF used by this service frontier."""
    started = time.monotonic()
    params = RoundedNoiseParams(
        ANCHOR_Q,
        Fraction(FINITE_SCALED_WIDTH, ANCHOR_Q),
        tail_bits=CIPHERTEXT_NOISE_TAIL_BITS,
        mass_bits=CIPHERTEXT_NOISE_MASS_BITS,
        precision_bits=CIPHERTEXT_NOISE_PRECISION_BITS,
        max_radius=CIPHERTEXT_NOISE_MAX_RADIUS,
    )
    table = build_rounded_noise(params)
    certificate = table.certificate()
    return {
        "built": True,
        "build_seconds": time.monotonic() - started,
        "anchor_modulus": ANCHOR_Q,
        "anchor_modulus_used_for_ciphertext": False,
        "scaled_width": FINITE_SCALED_WIDTH,
        "target": "round(continuous Gaussian of width q*alpha)",
        "radius": table.radius,
        "support_count": len(table.thresholds),
        "draw_bytes": table.draw_bytes,
        "tv_upper_for_service_accounting": certificate["tv_upper_including_abort"],
        "certificate": certificate,
    }


def frontier_finite_noise_projection():
    """Metadata-only upper bound for public tests that do not build the CDF."""
    square = FINITE_SCALED_WIDTH**2 * (CIPHERTEXT_NOISE_TAIL_BITS + 1)
    radius = isqrt(square) + int(isqrt(square) ** 2 < square)
    tv_upper = Fraction(1, 2**CIPHERTEXT_NOISE_TAIL_BITS) + Fraction(
        8 * radius, 2**CIPHERTEXT_NOISE_MASS_BITS
    )
    return {
        "built": False,
        "build_seconds": None,
        "anchor_modulus": ANCHOR_Q,
        "anchor_modulus_used_for_ciphertext": False,
        "scaled_width": FINITE_SCALED_WIDTH,
        "target": "round(continuous Gaussian of width q*alpha)",
        "radius": radius,
        "support_count": 2 * radius + 1,
        "draw_bytes": (CIPHERTEXT_NOISE_MASS_BITS + 7) // 8,
        "tv_upper_for_service_accounting": str(tv_upper),
        "certificate": None,
    }


def ap09_dimension_conditions(n, q_bits, random_rows):
    """Return the exact public conditions used to select AP09's random block."""
    n = _integer(n, "n", 2, 16384)
    q_bits = _integer(q_bits, "q_bits", 3, 256)
    random_rows = _integer(random_rows, "random_rows", 1, 2**26)
    nk = n * q_bits
    m2 = 2 * nk + 2 * random_rows
    dimension = random_rows + m2
    lhl_exponent = (m2 - 1).bit_length() + (nk - random_rows + 1) // 2
    return {
        "random_rows_exceeds_nk": random_rows > nk,
        "strict_setup_dimension": dimension > 6 * nk,
        "lhl_target": lhl_exponent <= -LHL_TARGET_BITS,
        "lhl_dyadic_exponent": lhl_exponent,
        "m1": random_rows,
        "m2": m2,
        "dimension": dimension,
    }


def minimum_ap09_random_rows(n, q_bits):
    """Smallest ``d`` satisfying all checked AP09 dimension/LHL conditions."""
    n = _integer(n, "n", 2, 16384)
    q_bits = _integer(q_bits, "q_bits", 3, 256)
    nk = n * q_bits
    random_rows = max(nk + 1, 4 * nk // 3 + 1)
    while True:
        conditions = ap09_dimension_conditions(n, q_bits, random_rows)
        if all(
            conditions[name]
            for name in ("random_rows_exceeds_nk", "strict_setup_dimension", "lhl_target")
        ):
            return conditions
        random_rows += 1
        if random_rows > 2 * nk + 4 * LHL_TARGET_BITS:
            raise ArithmeticError("bounded AP09 random-row search did not converge")


def matrix_bernstein_operator_bound(dimension, radius, *, tail_bits):
    """Exact sufficient rectangular matrix-Bernstein singular-value bound.

    Write the matrix as a sum of independent one-entry matrices.  Each summand
    has norm at most ``radius`` and the rectangular variance statistic is at
    most ``dimension*radius^2``.  Tropp's rectangular Bernstein inequality is
    inverted using an integer natural-exponent budget ``u``.  Since
    ``exp(-u) <= 2^-u``, the returned bound gives failure at most 2^-tail_bits.
    """
    dimension = _integer(dimension, "matrix dimension", 2, 2**26)
    radius = _integer(radius, "finite scalar radius", 1, 2**112)
    tail_bits = _integer(tail_bits, "operator tail bits", 8, 1024)
    dimension_factor_bits = (2 * dimension - 1).bit_length()
    natural_exponent_budget = tail_bits + dimension_factor_bits
    variance_upper = dimension * radius**2
    square_root_term = _ceil_sqrt(2 * variance_upper * natural_exponent_budget)
    linear_term = _ceil_div(2 * radius * natural_exponent_budget, 3)
    norm_upper = square_root_term + linear_term
    return {
        "source": "Tropp 2012, Theorem 1.6 rectangular matrix Bernstein",
        "source_url": "https://tropp.caltech.edu/papers/Tro11-User-Friendly-preprint.pdf",
        "independent_zero_mean_bounded_summands": True,
        "variance_upper": variance_upper,
        "summand_norm_upper": radius,
        "dimension_factor": 2 * dimension,
        "dimension_factor_bits": dimension_factor_bits,
        "natural_exponent_budget": natural_exponent_budget,
        "square_root_term": square_root_term,
        "linear_term": linear_term,
        "operator_norm_upper": norm_upper,
        "operator_norm_squared_upper": norm_upper**2,
        "unconditioned_failure_upper": f"2^-{tail_bits}",
        "deterministic_support_frobenius_squared_upper": dimension**2 * radius**2,
    }


def finite_matrix_invertibility_certificate(scalar, dimension, q):
    """Prove a greater-than-one-half finite-matrix invertibility probability.

    Conditioned on a scalar rejection sampler returning, its maximum point
    probability is at most the reciprocal of the certified acceptance mass.
    For any proper subspace over F_q, condition on all but a pivot coordinate
    of a nonzero annihilating linear form; membership then fixes that coordinate
    and has probability at most the maximum atom.  Applying this at each of the
    ``dimension`` sequential columns gives the union bound below.
    """
    dimension = _integer(dimension, "matrix dimension", 2, 2**26)
    q = _integer(q, "matrix modulus", 3, 2**256 - 1)
    acceptance_mass_lower = _as_fraction(scalar.acceptance_mass_lower)
    if acceptance_mass_lower <= 1:
        raise ArithmeticError("finite scalar acceptance mass cannot bound an atom")
    support_injective = q > 2 * scalar.radius
    maximum_atom_upper = Fraction(1, 1) / acceptance_mass_lower
    singular_upper = min(Fraction(1), dimension * maximum_atom_upper)
    invertible_lower = 1 - singular_upper
    attempts = 1
    while (
        MATRIX_ORACLE_CALLS * singular_upper**attempts
        >= Fraction(1, 2**SAMPLE_R_RANK_SERVICE_BUDGET_BITS)
    ):
        attempts += 1
        if attempts > 1024:
            raise ArithmeticError("bounded SampleR rank retry search did not converge")
    call_abort_upper = singular_upper**attempts
    service_abort_upper = MATRIX_ORACLE_CALLS * call_abort_upper
    return {
        "proof": "sequential-column proper-subspace hit union bound",
        "scalar_distribution_scope": "finite output conditioned on scalar success",
        "independent_coordinates_after_scalar_success": True,
        "support_mod_q_injective": support_injective,
        "scalar_acceptance_mass_lower": str(acceptance_mass_lower),
        "maximum_residue_atom_upper": str(maximum_atom_upper),
        "proper_subspace_hit_upper": str(maximum_atom_upper),
        "column_events_in_union": dimension,
        "singular_probability_upper": str(singular_upper),
        "invertibility_probability_lower": str(invertible_lower),
        "invertibility_probability_exceeds_one_half": bool(
            support_injective and invertible_lower > Fraction(1, 2)
        ),
        "whole_matrix_attempts": attempts,
        "per_call_rank_abort_upper": str(call_abort_upper),
        "declared_matrix_oracle_calls": MATRIX_ORACLE_CALLS,
        "service_rank_abort_union_upper": str(service_abort_upper),
        "service_rank_abort_below_2^-130": (
            service_abort_upper
            < Fraction(1, 2**SAMPLE_R_RANK_SERVICE_BUDGET_BITS)
        ),
    }


def _finite_sampler_accounting(scalar, dimension, invertibility):
    scalar_tv = _as_fraction(scalar.tv_upper)
    matrix_tv = min(Fraction(1), dimension**2 * scalar_tv)
    if matrix_tv >= Fraction(1, 2):
        raise ArithmeticError("finite SampleR scalar-success conditioning is vacuous")
    if not invertibility["invertibility_probability_exceeds_one_half"]:
        raise ArithmeticError("finite SampleR invertibility certificate failed")
    # Conservatively reserve a factor four first for conditioning the finite
    # fixed-tape samplers on no scalar abort, and another factor four for whole-
    # matrix invertibility.  ABB supplies the ideal matrix's >1/2 premise; the
    # finite side has the explicit certificate above.
    attempts = invertibility["whole_matrix_attempts"]
    call_tv = min(Fraction(1), 16 * attempts * matrix_tv)
    service_tv = min(Fraction(1), MATRIX_ORACLE_CALLS * call_tv)
    return {
        "scalar_tv_upper": str(scalar_tv),
        "scalar_draws_per_matrix": dimension**2,
        "matrix_tv_union_upper": str(matrix_tv),
        "whole_matrix_attempts": attempts,
        "scalar_success_conditioning_tv_amplification_upper": 4,
        "invertibility_conditioning_tv_amplification_upper": 4,
        "total_conditioning_tv_amplification_upper": 16,
        "conditioned_sample_R_call_tv_upper": str(call_tv),
        "declared_matrix_oracle_calls": MATRIX_ORACLE_CALLS,
        "service_tv_union_upper": str(service_tv),
        "service_tv_below_2^-128": service_tv < Fraction(1, 2**128),
        "public_fixed_tape_bytes_per_scalar": scalar.random_tape_bytes,
        "whole_matrix_attempt_fixed_tape_bytes": dimension**2 * scalar.random_tape_bytes,
        "sample_R_call_fixed_tape_bytes": (
            attempts * dimension**2 * scalar.random_tape_bytes
        ),
        "declared_service_fixed_tape_bytes": (
            MATRIX_ORACLE_CALLS * attempts * dimension**2 * scalar.random_tape_bytes
        ),
        "conditioning_on_scalar_success_preserves_exact_symmetry": True,
        "symmetry_reason": (
            "center-zero support is symmetric and integer_weight depends on x^2; "
            "each scalar uses an independent fixed-length tape"
        ),
    }


def _ciphertext_noise_service_accounting(row, finite_noise):
    scalar_tv = Fraction(finite_noise["tv_upper_for_service_accounting"])
    scalar_draws = (
        MATRIX_ORACLE_CALLS * PAYLOAD_BITS * (row["leaf_dimension"] + 1)
    )
    coupling = min(Fraction(1), scalar_draws * scalar_tv)
    ideal_text = row["noise"]["conditional_ideal_noise_lifetime_upper"]
    ideal = None if ideal_text is None else Fraction(ideal_text)
    combined = Fraction(1) if ideal is None else min(Fraction(1), ideal + coupling)
    return {
        "fresh_error_vectors_per_service": MATRIX_ORACLE_CALLS * PAYLOAD_BITS,
        "scalar_noise_draws_per_error_vector": row["leaf_dimension"] + 1,
        "scalar_noise_draws_per_service": scalar_draws,
        "scalar_finite_tv_upper": str(scalar_tv),
        "finite_noise_service_coupling_upper": str(coupling),
        "conditional_ideal_event_service_upper": (
            None if ideal is None else str(ideal)
        ),
        "combined_ciphertext_noise_service_upper": str(combined),
        "combined_ciphertext_noise_service_below_2^-129": (
            ideal is not None and combined < Fraction(1, 2**129)
        ),
        "actual_finite_cdf_built": finite_noise["built"],
    }


def _wire_accounting(n, q_bits, dimension):
    residue_bytes = (q_bits + 7) // 8
    basis_bytes = PRIVATE_ENTRY_WIRE_FLOOR * dimension**2
    return {
        "public_root_residues": n * dimension * residue_bytes,
        "root_full_basis": basis_bytes,
        "parent_stored_full_basis": basis_bytes,
        "leaf_material": basis_bytes,
        "capsule_coefficients": PAYLOAD_BITS * (dimension + 1) * residue_bytes,
    }


def build_frontier_row(n, q_bits):
    """Build one public projection; no matrix, key or private entropy is created."""
    n = _integer(n, "n", 2, 16384)
    q_bits = _integer(q_bits, "q_bits", 3, 256)
    q = int(previous_prime(ZZ(2) ** q_bits))
    if q.bit_length() != q_bits or not ZZ(q).is_prime(proof=True):
        raise ArithmeticError("canonical near-power-of-two prime selection failed")
    dimensions = minimum_ap09_random_rows(n, q_bits)
    d, m2, dimension = (
        dimensions["m1"],
        dimensions["m2"],
        dimensions["dimension"],
    )
    hadamard_width = 1 << ((2 * d).bit_length() - 1)
    if hadamard_width < d:
        raise ArithmeticError("AP09 Hadamard block cannot cover random rows")
    hadamard_scale = _ceil_sqrt_fraction(Fraction(4 * d * m2, hadamard_width))
    root_gs_squared = max((hadamard_scale + 3) ** 2 * d + 5, 8 * n * q_bits + 2)
    smoothing = smoothing_factor(dimension, BITS)
    matrix_r_squared = 4 * root_gs_squared * smoothing
    scalar = MatrixFiniteGaussian(
        matrix_r_squared,
        matrix_r_squared,
        options=matrix_sampler_options(),
    )
    invertibility = finite_matrix_invertibility_certificate(scalar, dimension, q)
    sampler_accounting = _finite_sampler_accounting(
        scalar, dimension, invertibility
    )
    operator = matrix_bernstein_operator_bound(
        dimension,
        scalar.radius,
        tail_bits=OPERATOR_UNCONDITIONED_TAIL_BITS,
    )
    operator.update(
        {
            "finite_invertibility_probability_lower": invertibility[
                "invertibility_probability_lower"
            ],
            "conditional_failure_upper": (
                f"2^-{OPERATOR_CONDITIONAL_TAIL_BITS}"
            ),
            "declared_matrix_oracle_calls": MATRIX_ORACLE_CALLS,
            "service_conditional_failure_union_upper": (
                f"2^-{OPERATOR_SERVICE_BUDGET_BITS}"
            ),
            "conditioning_basis": (
                "finite max-atom/column-span certificate proves probability above 1/2; "
                "ABB10 Definition 7 states fewer than two expected ideal attempts"
            ),
            "finite_sampler_conditioning_transfer_verified": True,
        }
    )
    service_operator_failure = Fraction(1, 2**OPERATOR_SERVICE_BUDGET_BITS)
    service_sampler_tv = Fraction(sampler_accounting["service_tv_union_upper"])
    service_rank_abort = Fraction(invertibility["service_rank_abort_union_upper"])
    combined_service_failure = (
        service_operator_failure + service_sampler_tv + service_rank_abort
    )
    operator["service_event_plus_sampler_tv_and_rank_abort_upper"] = str(
        combined_service_failure
    )
    operator["total_service_statistical_budget_below_2^-128"] = (
        combined_service_failure < Fraction(1, 2**SERVICE_STATISTICAL_TARGET_BITS)
    )
    operator_squared = operator["operator_norm_squared_upper"]
    parent_width_squared = 4 * root_gs_squared * operator_squared * smoothing
    parent_gs_squared = parent_width_squared * dimension
    leaf_width_squared = 4 * parent_gs_squared * operator_squared * smoothing
    leaf_gs_squared = leaf_width_squared * dimension
    decrypt_width_squared = 4 * leaf_gs_squared * smoothing
    noise = conditional_noise(
        q,
        dimension,
        decrypt_width_squared,
        FINITE_SCALED_WIDTH,
        abb=True,
        error_bits=CIPHERTEXT_PER_BIT_EVENT_BITS,
    )
    noise["strict_Regev_noise_prerequisite"] = FINITE_SCALED_WIDTH**2 > 4 * n
    noise["minimum_strict_Regev_scaled_width"] = strict_noise_width(n)
    noise["maximum_conditional_correctness_scaled_width"] = maximum_abb_scaled_width(
        q,
        dimension,
        decrypt_width_squared,
        error_bits=CIPHERTEXT_PER_BIT_EVENT_BITS,
    )
    noise["scaled_width_selection"] = "explicit-service-budgeted"
    wire = _wire_accounting(n, q_bits, dimension)
    candidate_id = f"abb-rom-tight-n{n}-q{q_bits}-chi{FINITE_SCALED_WIDTH}"
    return {
        "candidate_id": candidate_id,
        "family": "abb-rom",
        "projection_variant": "minimal-ap09-d-plus-bounded-matrix-bernstein-v1",
        "n": n,
        "q": q,
        "q_bits": q_bits,
        "q_selection": "largest prime below 2^q_bits",
        "scaled_noise_width": FINITE_SCALED_WIDTH,
        "random_rows": d,
        "m1": d,
        "m2": m2,
        "root_dimension": dimension,
        "parent_dimension": dimension,
        "leaf_dimension": dimension,
        "ap09_dimension_conditions": dimensions,
        "historical_8nk_dimension": 8 * n * q_bits,
        "hadamard_width": hadamard_width,
        "hadamard_scale": hadamard_scale,
        "root_gs_squared_bound": str(root_gs_squared),
        "smoothing_factor": str(smoothing),
        "matrix_R_width_squared": str(matrix_r_squared),
        "sample_R_max_matrices": invertibility["whole_matrix_attempts"],
        "matrix_R_finite_scalar_certificate": scalar.certificate(),
        "matrix_R_finite_invertibility_certificate": invertibility,
        "matrix_R_finite_sampler_accounting": sampler_accounting,
        "transformation_operator_bound": operator,
        "parent_width_squared": str(parent_width_squared),
        "parent_gs_squared_bound": str(parent_gs_squared),
        "leaf_width_squared": str(leaf_width_squared),
        "leaf_gs_squared_bound": str(leaf_gs_squared),
        "decrypt_width_squared": str(decrypt_width_squared),
        "root_trapdoor_recovery": _abb_root_trapdoor_role(n, q, d, m2),
        "root_lwe": None,
        "ciphertext_lwe": _ciphertext_role(
            n, q, dimension, FINITE_SCALED_WIDTH, abb=True
        ),
        "noise": noise,
        "minimum_wire_bytes": wire,
        "estimator_results": {},
        "root_trapdoor_comparison_status": "unassessed",
        "root_trapdoor_comparison_gate": False,
        "ciphertext_comparison_gate": False,
        "comparison_model_gate": False,
        "implementation_research_gate": False,
        "runtime_admitted": False,
        "runtime_blockers": [
            "complete basis remains hundreds of terabytes",
            "current BasisDel/RandBasis/SamplePre consumers materialize complete bases",
            "raw 32-byte ciphertext remains tens of gigabytes",
            "literal finite SampleR fixed tapes and m^2 scalar draws are prohibitive",
            "complete finite SampleR-to-ABB proof/reduction mapping is not reviewed",
            "root trapdoor-recovery comparison remains unresolved",
        ],
        "projection_only": True,
        "root_or_key_generated": False,
        "ciphertext_generated": False,
        "private_entropy_bytes": 0,
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
    }


def _validate_baseline(card):
    if not isinstance(card, dict) or card.get("schema") != BASELINE_SCHEMA:
        raise ValueError("current ABB /3 baseline card required")
    if (
        card.get("security_claim") != "none"
        or card.get("backend_admitted") is not False
        or card.get("parameters_are_formal") is not False
    ):
        raise ValueError("baseline must retain none/false/false metadata")
    rows = card.get("rows")
    if not isinstance(rows, list):
        raise ValueError("baseline rows required")
    matches = [row for row in rows if isinstance(row, dict) and row.get("n") == 9600]
    if len(matches) != 1:
        raise ValueError("unique n9600 baseline row required")
    row = matches[0]
    noise = row.get("noise")
    wire = row.get("minimum_wire_bytes")
    if (
        row.get("candidate_id") != BASELINE_CANDIDATE_ID
        or row.get("q") != Q208
        or row.get("q_bits") != 208
        or row.get("root_dimension") != BASELINE_DIMENSION
        or not isinstance(noise, dict)
        or noise.get("scaled_continuous_width") != FINITE_SCALED_WIDTH
        or not isinstance(wire, dict)
        or wire.get("parent_stored_full_basis") != BASELINE_BASIS_BYTES
        or wire.get("capsule_coefficients") != BASELINE_CIPHERTEXT_BYTES
    ):
        raise ValueError("exact n9600/q208/chi721 baseline required")
    return row


def build_frontier_report(baseline_card_path, *, build_cdf=True):
    """Build the fixed public frontier and bind it to the conservative /3 card."""
    started = time.monotonic()
    baseline_card_path = Path(baseline_card_path)
    baseline_raw = baseline_card_path.read_bytes()
    try:
        baseline_card = json.loads(baseline_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("valid UTF-8 JSON ABB baseline required") from exc
    baseline_row = _validate_baseline(baseline_card)
    rows = [build_frontier_row(n, q_bits) for n, q_bits in TESTED_ROWS]
    finite_noise = (
        build_frontier_finite_noise_certificate()
        if build_cdf
        else frontier_finite_noise_projection()
    )
    for row in rows:
        row["finite_noise_table_built"] = finite_noise["built"]
        ciphertext_accounting = _ciphertext_noise_service_accounting(
            row, finite_noise
        )
        row["ciphertext_noise_service_accounting"] = ciphertext_accounting
        sample_r_upper = Fraction(
            row["transformation_operator_bound"][
                "service_event_plus_sampler_tv_and_rank_abort_upper"
            ]
        )
        ciphertext_upper = Fraction(
            ciphertext_accounting["combined_ciphertext_noise_service_upper"]
        )
        local_union = min(Fraction(1), sample_r_upper + ciphertext_upper)
        row["local_service_statistical_accounting"] = {
            "sample_R_norm_TV_and_rank_upper": str(sample_r_upper),
            "ciphertext_noise_upper": str(ciphertext_upper),
            "union_upper": str(local_union),
            "union_below_2^-128": local_union < Fraction(1, 2**128),
            "omits_downstream_basis_and_preimage_sampler_events": True,
        }
    root = Path(__file__).resolve().parents[3]
    sources = (
        "experiments/research/abb_rom/tight_parameter_frontier.py",
        "experiments/research/abb_rom/scaled_parameter_screen.py",
        "experiments/research/abb_rom/noise_tradeoff_probe.py",
        "src/ibme/hibe/abb_rom/trapgen.py",
        "src/ibme/lattice/chkp/joint_parameters.py",
        "src/ibme/lattice/chkp/noise_budget.py",
        "src/ibme/lattice/chkp/rounded_noise.py",
        "src/ibme/lattice/matrix_sampling/scalar.py",
        "papers/2010_lattice_basis_delegation_agrawal.pdf",
    )
    baseline_wire = baseline_row["minimum_wire_bytes"]
    report = {
        "schema": SCHEMA,
        "fixed_inputs": {
            "comparison_threshold_bits": COMPARISON_BITS,
            "lhl_target_bits": LHL_TARGET_BITS,
            "service_statistical_target_bits": SERVICE_STATISTICAL_TARGET_BITS,
            "operator_service_budget_bits": OPERATOR_SERVICE_BUDGET_BITS,
            "sample_R_rank_service_budget_bits": SAMPLE_R_RANK_SERVICE_BUDGET_BITS,
            "operator_conditional_tail_bits": OPERATOR_CONDITIONAL_TAIL_BITS,
            "operator_unconditioned_tail_bits": OPERATOR_UNCONDITIONED_TAIL_BITS,
            "sample_R_scalar_bits": SAMPLE_R_SCALAR_BITS,
            "ciphertext_event_service_budget_bits": (
                CIPHERTEXT_EVENT_SERVICE_BUDGET_BITS
            ),
            "ciphertext_per_bit_event_bits": CIPHERTEXT_PER_BIT_EVENT_BITS,
            "ciphertext_noise_tail_bits": CIPHERTEXT_NOISE_TAIL_BITS,
            "ciphertext_noise_mass_bits": CIPHERTEXT_NOISE_MASS_BITS,
            "ciphertext_noise_precision_bits": CIPHERTEXT_NOISE_PRECISION_BITS,
            "matrix_oracle_calls": MATRIX_ORACLE_CALLS,
            "scaled_noise_width": FINITE_SCALED_WIDTH,
            "identity_bytes_per_level": 86,
            "seed_bytes": 32,
            "independently_encrypted_bits": PAYLOAD_BITS,
        },
        "paper_and_bound_contract": {
            "ABB10": {
                "source": "Agrawal-Boneh-Boyen, CRYPTO 2010, fixed local PDF",
                "TrapGen": "Theorem 1 m=ceil(6*n*log(q)); finite AP09 construction checked separately",
                "SampleR": "Definition 7 independent D_Z^m columns conditioned invertible mod q",
                "BasisDel": "Theorem 3 uses the random transformation norm at fixed dimension",
            },
            "matrix_Bernstein": {
                "source": "Joel A. Tropp, User-Friendly Tail Bounds for Sums of Random Matrices",
                "theorem": "Theorem 1.6, rectangular case",
                "url": "https://tropp.caltech.edu/papers/Tro11-User-Friendly-preprint.pdf",
            },
            "finite_sample_R_invertibility_lower_bound_verified": True,
            "finite_operator_event_conditioning_transfer_verified": True,
            "finite_conditioned_TV_amplification_accounted": True,
            "formal_ABB_distribution_mapping_complete": False,
        },
        "finite_ciphertext_noise": finite_noise,
        "baseline": {
            "path": str(baseline_card_path),
            "schema": baseline_card["schema"],
            "sha256": hashlib.sha256(baseline_raw).hexdigest(),
            "candidate_id": baseline_row["candidate_id"],
            "n": baseline_row["n"],
            "q": baseline_row["q"],
            "q_bits": baseline_row["q_bits"],
            "dimension": baseline_row["root_dimension"],
            "complete_basis_minimum_bytes": baseline_wire["parent_stored_full_basis"],
            "raw_32_byte_ciphertext_minimum_bytes": baseline_wire["capsule_coefficients"],
        },
        "rows": rows,
        "estimator": None,
        "root_trapdoor_comparison_candidates": [],
        "ciphertext_comparison_candidates": [],
        "comparison_model_candidates": [],
        "implementation_research_candidates": [],
        "smallest_tested_implementation_research_candidate": None,
        "recommended_implementation_research_candidate": None,
        "complete_runtime_candidates": [],
        "recommended_vs_baseline": None,
        "secure_candidate_selected": False,
        "research_tier_policy": {
            "name": "tight-public-projection-with-verified-finite-conditioning",
            "formal_comparison_gate_changed": False,
            "allows_explicit_root_no_finite_estimate": True,
            "uses_verified_finite_invertibility_lower_bound": True,
            "grants_security_or_runtime_admission": False,
        },
        "root_or_key_generations": 0,
        "ciphertext_generations": 0,
        "private_entropy_bytes": 0,
        "environment": {
            "python": sys.version.split()[0],
            "sage": __import__("sage.version", fromlist=["version"]).version,
            "platform": platform.platform(),
            "logical_cpus": os.cpu_count(),
        },
        "source_sha256": {name: _sha256(root / name) for name in sources},
        "measurements": {
            "finite_cdf_build_seconds": finite_noise["build_seconds"],
            "total_seconds": None,
            "process_max_rss_kib": None,
        },
        "unresolved": [
            "complete finite SampleR certificate mapping into the ABB security reduction",
            "literal finite SampleR fixed-tape entropy and m^2 scalar-draw execution",
            "exact planted-R and complete root-trapdoor recovery cost",
            "all relevant ciphertext attacks, multi-target/query and HIBE reduction losses",
            "finite BasisDel/RandBasis/SamplePre total TV, abort and distribution mapping",
            "matrix random-oracle and ROM/QROM instantiation",
            "hundreds-of-terabytes complete-basis representation and current consumers",
        ],
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
    }
    report["measurements"]["total_seconds"] = time.monotonic() - started
    report["measurements"]["process_max_rss_kib"] = resource.getrusage(
        resource.RUSAGE_SELF
    ).ru_maxrss
    return report


def _finite_minimum(results, required):
    values = []
    for name in required:
        result = results.get(name)
        value = result.get("rop_log2") if isinstance(result, dict) else None
        if (
            not isinstance(result, dict)
            or result.get("status") != "finite_estimate"
            or type(value) not in (int, float)
        ):
            return False, None
        try:
            value = float(value)
        except OverflowError:
            return False, None
        if not isfinite(value) or value < 0:
            return False, None
        values.append(value)
    return True, min(values)


def _explicitly_unresolved(results, required):
    return all(
        isinstance(results.get(name), dict)
        and results[name].get("status") == "no_finite_estimate"
        and results[name].get("rop_log2") is None
        for name in required
    )


def finalize_frontier(report):
    """Classify numerical research candidates without granting formal admission."""
    root_candidates = []
    ciphertext_candidates = []
    joint_candidates = []
    research_candidates = []
    for row in report["rows"]:
        all_results = row.get("estimator_results", {})
        root_results = all_results.get("root_trapdoor_recovery", {})
        ciphertext_results = all_results.get("ciphertext_lwe", {})
        root_complete, root_minimum = _finite_minimum(
            root_results, ROOT_REQUIRED_ESTIMATES
        )
        ciphertext_complete, ciphertext_minimum = _finite_minimum(
            ciphertext_results, CIPHERTEXT_REQUIRED_ESTIMATES
        )
        root_gate = bool(root_complete and root_minimum >= COMPARISON_BITS)
        ciphertext_gate = bool(
            ciphertext_complete and ciphertext_minimum >= COMPARISON_BITS
        )
        root_unknown = _explicitly_unresolved(root_results, ROOT_REQUIRED_ESTIMATES)
        if root_gate:
            root_status = "meets_target"
        elif root_complete:
            root_status = "finite_below_target"
        elif root_unknown:
            root_status = "explicitly_unresolved"
        else:
            root_status = "invalid_or_incomplete"
        public_projection_gate = bool(
            row["ap09_dimension_conditions"]["lhl_target"]
            and row["ap09_dimension_conditions"]["strict_setup_dimension"]
            and row["ap09_dimension_conditions"]["random_rows_exceeds_nk"]
            and row["matrix_R_finite_invertibility_certificate"][
                "support_mod_q_injective"
            ]
            and row["matrix_R_finite_invertibility_certificate"][
                "invertibility_probability_exceeds_one_half"
            ]
            and row["matrix_R_finite_invertibility_certificate"][
                "service_rank_abort_below_2^-130"
            ]
            and row["matrix_R_finite_sampler_accounting"]["service_tv_below_2^-128"]
            and row["transformation_operator_bound"][
                "total_service_statistical_budget_below_2^-128"
            ]
            and row["ciphertext_noise_service_accounting"][
                "combined_ciphertext_noise_service_below_2^-129"
            ]
            and row["local_service_statistical_accounting"]["union_below_2^-128"]
            and row["noise"]["conditional_noise_sufficient"]
            and row["noise"]["strict_Regev_noise_prerequisite"]
            and row["finite_noise_table_built"]
            and row["ciphertext_noise_service_accounting"][
                "actual_finite_cdf_built"
            ]
        )
        research_gate = bool(
            public_projection_gate
            and ciphertext_gate
            and root_status in ("meets_target", "explicitly_unresolved")
        )
        # This gate is only the fixed comparison model.  Even if it passes,
        # report-level security/formal/backend metadata stays none/false/false.
        formal_gate = bool(
            public_projection_gate
            and root_gate
            and ciphertext_gate
            and row["transformation_operator_bound"][
                "finite_sampler_conditioning_transfer_verified"
            ]
        )
        row["root_trapdoor_comparison_estimates_complete"] = root_complete
        row["root_trapdoor_comparison_minimum_log2_rop"] = root_minimum
        row["root_trapdoor_comparison_status"] = root_status
        row["root_trapdoor_comparison_gate"] = root_gate
        row["ciphertext_comparison_estimates_complete"] = ciphertext_complete
        row["ciphertext_comparison_minimum_log2_rop"] = ciphertext_minimum
        row["ciphertext_comparison_gate"] = ciphertext_gate
        comparison_complete = root_complete and ciphertext_complete
        row["comparison_estimates_complete"] = comparison_complete
        row["comparison_minimum_log2_rop"] = (
            min(root_minimum, ciphertext_minimum) if comparison_complete else None
        )
        row["comparison_model_gate"] = formal_gate
        row["implementation_research_gate"] = research_gate
        row["runtime_admitted"] = False
        if root_gate:
            root_candidates.append(row)
        if ciphertext_gate:
            ciphertext_candidates.append(row)
        if formal_gate:
            joint_candidates.append(row)
        if research_gate:
            research_candidates.append(row)
    report["root_trapdoor_comparison_candidates"] = [
        row["candidate_id"] for row in root_candidates
    ]
    report["ciphertext_comparison_candidates"] = [
        row["candidate_id"] for row in ciphertext_candidates
    ]
    report["comparison_model_candidates"] = [
        row["candidate_id"] for row in joint_candidates
    ]
    report["implementation_research_candidates"] = [
        row["candidate_id"] for row in research_candidates
    ]
    report["complete_runtime_candidates"] = []
    if research_candidates:
        smallest = min(research_candidates, key=lambda row: row["n"])
        report["smallest_tested_implementation_research_candidate"] = smallest[
            "candidate_id"
        ]
    else:
        report["smallest_tested_implementation_research_candidate"] = None
    recommended = next(
        (row for row in research_candidates if row["candidate_id"] == RECOMMENDED_ID),
        None,
    )
    report["recommended_implementation_research_candidate"] = (
        recommended["candidate_id"] if recommended is not None else None
    )
    if recommended is not None:
        baseline = report["baseline"]
        basis = recommended["minimum_wire_bytes"]["parent_stored_full_basis"]
        ciphertext = recommended["minimum_wire_bytes"]["capsule_coefficients"]
        report["recommended_vs_baseline"] = {
            "baseline_candidate_id": baseline["candidate_id"],
            "dimension_ratio": str(Fraction(recommended["root_dimension"], baseline["dimension"])),
            "complete_basis_byte_ratio": str(
                Fraction(basis, baseline["complete_basis_minimum_bytes"])
            ),
            "raw_32_byte_ciphertext_byte_ratio": str(
                Fraction(ciphertext, baseline["raw_32_byte_ciphertext_minimum_bytes"])
            ),
            "new_dimension": recommended["root_dimension"],
            "new_complete_basis_minimum_bytes": basis,
            "new_raw_32_byte_ciphertext_minimum_bytes": ciphertext,
            "ciphertext_minimum_log2_rop": recommended[
                "ciphertext_comparison_minimum_log2_rop"
            ],
        }
    else:
        report["recommended_vs_baseline"] = None
    report["secure_candidate_selected"] = False
    return report


def runtime_summary(report):
    return {
        "schema": RUNTIME_SCHEMA,
        "source_schema": report["schema"],
        "measurements": report["measurements"],
        "environment": report["environment"],
        "row_count": len(report["rows"]),
        "repetitions": 1,
        "rng": "none; public arithmetic/CDF/estimator run",
        "actual_finite_ciphertext_noise_CDF_built": report[
            "finite_ciphertext_noise"
        ]["built"],
        "root_or_key_generations": 0,
        "ciphertext_generations": 0,
        "private_entropy_bytes": 0,
        "root_trapdoor_comparison_candidates": report[
            "root_trapdoor_comparison_candidates"
        ],
        "ciphertext_comparison_candidates": report["ciphertext_comparison_candidates"],
        "comparison_model_candidates": report["comparison_model_candidates"],
        "implementation_research_candidates": report[
            "implementation_research_candidates"
        ],
        "recommended_implementation_research_candidate": report[
            "recommended_implementation_research_candidate"
        ],
        "complete_runtime_candidates": [],
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
        "limitations": report["unresolved"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-card", type=Path, required=True)
    parser.add_argument("--estimator-path", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runtime-output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.resolve() == args.runtime_output.resolve():
        raise ValueError("distinct report and runtime output paths required")
    if args.output.exists() or args.runtime_output.exists():
        raise FileExistsError("report outputs must not already exist")
    for path in (args.output, args.runtime_output):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as stream:
            stream.write('{"status":"public-probe-started"}\n')
    started = time.monotonic()
    report = build_frontier_report(args.baseline_card, build_cdf=True)

    def save_report():
        args.output.write_text(
            json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8"
        )

    save_report()
    run_estimators(report, args.estimator_path, checkpoint=save_report)
    finalize_frontier(report)
    report["measurements"]["total_seconds"] = time.monotonic() - started
    report["measurements"]["process_max_rss_kib"] = resource.getrusage(
        resource.RUSAGE_SELF
    ).ru_maxrss
    save_report()
    args.runtime_output.write_text(
        json.dumps(runtime_summary(report), indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    print(
        f"{len(report['rows'])} public frontier rows; "
        f"{len(report['implementation_research_candidates'])} implementation research candidates; "
        "zero keys; zero runtime admissions"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
