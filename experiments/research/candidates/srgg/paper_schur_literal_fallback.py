"""Literal-density Algorithm 4 normalizer: one bounded fallback route.

This is an all-center mathematical comparison for a *single* exact Schur
leaf, and its adaptive-chain union bound.  It uses the scalar Poisson theta
bound even when the existing whole-vector relative-error prerequisite fails.
It does not inspect a finite sampler, an accepted Setup root, or an IBS law.

For R=r^2 I and scalar Poisson remainder t<1, the integer Gaussian
normalizer factors coordinatewise.  Hence, for every y in R^n,

    (1-t)^n <= Z_R(y)/r^n <= (1+t)^n.

As in the exact Gaussian-convolution bridge, the ideal joint law is the
actual continuous-plus-discrete joint law tilted by Z_R(y).  A likelihood
ratio comparison gives single-leaf TV <= 1-((1-t)/(1+t))^n.  The bound is
mathematical, not a measurement of the actual TV.  The displayed bound is
rounded *up* to a fixed dyadic precision, preserving its rigorous direction.
"""

from __future__ import annotations

from fractions import Fraction

from .paper_rounding_budget import theta_certificate


SCHEMA = "IBME/SRGG-SCHUR-LITERAL-PRODUCT-FALLBACK/1"


def coordinate_product_tilt_bound(*, dimension: int, scalar_theta_upper: Fraction,
                                  dyadic_bits: int = 256) -> tuple[Fraction, Fraction]:
    """Return a lower dyadic complement and upper dyadic single-leaf TV.

    The exact ratio is formed before downward dyadic rounding.  This avoids
    emitting an unwieldy 512-fold rational in a reviewable certificate.
    """
    if (type(dimension) is not int or not 1 <= dimension <= 512
            or type(scalar_theta_upper) is not Fraction
            or not 0 <= scalar_theta_upper < 1
            or type(dyadic_bits) is not int or not 64 <= dyadic_bits <= 1024):
        raise ValueError("bounded exact scalar theta and dimension required")
    if max(scalar_theta_upper.numerator.bit_length(),
           scalar_theta_upper.denominator.bit_length()) > 4096:
        raise ValueError("scalar theta rational exceeds resource gate")

    exact_complement = ((1-scalar_theta_upper)/(1+scalar_theta_upper))**dimension
    scale = 1 << dyadic_bits
    complement_lower = Fraction(
        (exact_complement.numerator*scale)//exact_complement.denominator, scale)
    return complement_lower, 1-complement_lower


def literal_product_certificate(*, degree: int, upper_polynomials: int,
                                rounding_squared: Fraction,
                                precision_bits: int = 512,
                                dyadic_bits: int = 256) -> dict:
    """Certify the product-normalizer route, without claiming security.

    The caller must separately authenticate every Schur pivot F>r^2 I for
    the root/history in question.  This function deliberately does not take
    a purported pivot number, since it proves only the all-center Z_R bound.
    """
    if (type(degree) is not int or not 1 <= degree <= 512
            or type(upper_polynomials) is not int or not 1 <= upper_polynomials <= 16
            or type(rounding_squared) is not Fraction or rounding_squared <= 0
            or type(precision_bits) is not int or not 128 <= precision_bits <= 2048
            or type(dyadic_bits) is not int or not 64 <= dyadic_bits <= 1024):
        raise ValueError("bounded exact product-normalizer inputs required")
    if max(rounding_squared.numerator.bit_length(), rounding_squared.denominator.bit_length()) > 4096:
        raise ValueError("rounding shape rational exceeds resource gate")

    scalar = theta_certificate(dimension=1, density_shape=rounding_squared,
                               precision_bits=precision_bits)
    t = Fraction(scalar["scalar_nonzero_theta_upper_exact"])
    result = {
        "schema": SCHEMA,
        "degree_per_leaf": degree,
        "upper_polynomials": upper_polynomials,
        "rounding_squared_exact": str(rounding_squared),
        "scalar_theta_upper_exact": str(t),
        "scalar_theta_certificate": scalar,
        "dyadic_bits": dyadic_bits,
        "single_leaf_tv_complement_lower_dyadic_exact": None,
        "mathematical_single_leaf_tv_upper_dyadic_exact": None,
        "mathematical_algorithm34_to_ideal_sequential_discrete_tv_upper_exact": None,
        "whole_chain_bound_nontrivial": False,
        "all_leaf_centers": True,
        "pivot_positivity_authenticated_here": False,
        "finite_to_mathematical_algorithm34_tv_upper": None,
        "ideal_sequential_vs_joint_integer_tv_upper": None,
        "receipt_generated_on_fixed_roots": True,
        "fixed_roots_are_witnesses": True,
        "bound_scope": "every_plan_passing_complete_gate_set",
        "guard_built_into_backend": True,
        "all_gate_passing_setup_roots_covered": True,
        "accepted_setup_root_distribution_bound": None,
        "accepted_setup_root_distribution_reason":
            r"the gate-set mass P(A\B), P(B\G) and the accepted-root distribution "
            r"relative to mu_A remain unbounded; beta_bad remains null",
        "full_ibs_tv_upper": None,
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
        "nist_security_category": None,
        "method": "scalar Poisson product interval; exact Gaussian convolution; likelihood-ratio TV; adaptive union bound",
    }
    if t >= 1:
        result["blocker"] = "scalar theta upper does not give a positive product-normalizer lower bound"
        return result
    complement, leaf = coordinate_product_tilt_bound(
        dimension=degree, scalar_theta_upper=t, dyadic_bits=dyadic_bits)
    chain = min(Fraction(1), upper_polynomials*leaf)
    result["single_leaf_tv_complement_lower_dyadic_exact"] = str(complement)
    result["mathematical_single_leaf_tv_upper_dyadic_exact"] = str(leaf)
    result["mathematical_algorithm34_to_ideal_sequential_discrete_tv_upper_exact"] = str(chain)
    result["whole_chain_bound_nontrivial"] = chain < 1
    if chain == 1:
        result["blocker"] = (
            "product-normalizer chain TV upper is the trivial value 1; "
            "actual TV remains unknown")
    return result
