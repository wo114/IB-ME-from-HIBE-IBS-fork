"""Fixed-root ideal sequential-vs-joint discrete Gaussian normalizer bound.

This concerns mathematical kernels with exact Schur covariances. It does not
bound the finite Box--Muller/FFT/SampleZ implementation or Setup root selection.
"""
from __future__ import annotations

from fractions import Fraction

from .paper_rounding_budget import theta_certificate
from .paper_schur_numerical import SchurNumericalAudit


SCHEMA = "IBME/SRGG-SCHUR-IDEAL-NORMALIZER/1"


def _dyadic_upper(value):
    if type(value) is not Fraction or not 0 < value < 1:
        raise ValueError("positive exact subunit probability required")
    numerator, denominator = value.numerator, value.denominator
    bits = max(0, denominator.bit_length() - numerator.bit_length())
    while bits and numerator << bits > denominator:
        bits -= 1
    while numerator << (bits + 1) <= denominator:
        bits += 1
    return bits


def ideal_normalizer_bias(*, dimension, stages, relative_normalizer_error):
    """Bound the tilt caused by history-dependent sequential normalizers.

    If each leaf's exact lattice normalizer is K_i(1±eps), its product W is in
    [A*K,B*K] with A=(1-eps)^stages and B=(1+eps)^stages. The exact joint
    discrete Gaussian is the sequential law tilted by W. The likelihood
    ratio lies in [A/B,B/A], giving TV <= (B-A)/(B+A).
    """
    if (type(dimension) is not int or not 1 <= dimension <= 512
            or type(stages) is not int or not 1 <= stages <= 16
            or type(relative_normalizer_error) is not Fraction
            or not 0 < relative_normalizer_error < 1):
        raise ValueError("bounded exact normalizer inputs required")
    epsilon = relative_normalizer_error
    low, high = (1-epsilon)**stages, (1+epsilon)**stages
    tv = (high-low)/(high+low)
    bits = _dyadic_upper(tv)
    return {"dimension_per_leaf": dimension, "upper_leaf_count": stages,
            "relative_leaf_normalizer_error_dyadic_upper":
                "2^-"+str(_dyadic_upper(epsilon)),
            "ideal_sequential_vs_joint_integer_tv_dyadic_upper": "2^-"+str(bits),
            "ideal_sequential_vs_joint_integer_tv_dyadic_bits": bits,
            "normalizer_product_range": "[(1-eps)^stages,(1+eps)^stages] times constant",
            "comparison": "fixed-root ideal Algorithm 3 sequential discrete chain vs full joint discrete Gaussian",
            "lower_block_included": "same independent lower-block discrete Gaussian; its fixed normalizer cancels",
            "uniform_in_all_adaptive_leaf_centers": True}


def fixed_root_normalizer_certificate(audit):
    """Use independently replayed ideal pivot eigenvalues, coarsened to 64."""
    if type(audit) is not SchurNumericalAudit:
        raise TypeError("independent fixed-root SchurNumericalAudit required")
    public = audit.public_certificate()
    if not public["all_ideal_schur_pivot_eigenvalues_at_least_64"]:
        return {"schema": SCHEMA, "ideal_pivot_density_shape_lower": None,
                "ideal_sequential_vs_joint_integer_tv_dyadic_upper": None,
                "source_schur_finite_output_tv_upper": None,
                "receipt_generated_on_fixed_roots": True,
                "fixed_roots_are_witnesses": True,
                "bound_scope": "every_plan_passing_complete_gate_set",
                "guard_built_into_backend": True,
                "all_gate_passing_setup_roots_covered": True,
                "accepted_setup_root_distribution_bound": None,
                "accepted_setup_root_distribution_reason":
                    r"the gate-set mass P(A\B), P(B\G) and the accepted-root distribution "
                    r"relative to mu_A remain unbounded; beta_bad remains null",
                "security_claim": "none"}
    theta = theta_certificate(dimension=public["degree"],
                              density_shape=Fraction(64), precision_bits=512)
    epsilon_text = theta["relative_normalizer_error_upper_exact"]
    if epsilon_text is None:
        raise AssertionError("shape 64 did not produce a nontrivial theta bound")
    result = ideal_normalizer_bias(dimension=public["degree"],
        stages=public["upper_polynomials"],
        relative_normalizer_error=Fraction(epsilon_text))
    return {"schema": SCHEMA, "ideal_pivot_density_shape_lower": 64,
            **result,
            "receipt_generated_on_fixed_roots": True,
            "fixed_roots_are_witnesses": True,
            "bound_scope": "every_plan_passing_complete_gate_set",
            "guard_built_into_backend": True,
            "all_gate_passing_setup_roots_covered": True,
            "accepted_setup_root_distribution_bound": None,
            "accepted_setup_root_distribution_reason":
                r"the gate-set mass P(A\B), P(B\G) and the accepted-root distribution "
                r"relative to mu_A remain unbounded; beta_bad remains null",
            "source_schur_finite_output_tv_upper": None,
            "HNF_key_or_signature_law_certified": False,
            "security_claim": "none", "backend_admitted": False,
            "parameters_are_formal": False, "nist_security_category": None}
