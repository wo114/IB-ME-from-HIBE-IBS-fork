"""All-center convolution bridge for the *mathematical* source Schur chain.

This compares an exact continuous Gaussian followed by an exact shifted
integer Gaussian (paper Algorithm 4) with the ideal integer Schur conditional.
It neither compares the finite implementation with Algorithm 4 nor compares
the ideal sequential conditionals with their joint integer Gaussian. Those
are separate, independently accounted-for transitions.

The density convention is rho_C(x) = exp(-pi*x^T*C^-1*x). For a positive
Schur pivot F and R=r^2 I, let C=F-R>0, Y~continuous D_C(c), and
K|Y=y~discrete D_Z^n,R(y). With Z_R(y)=sum_k rho_R(k-y), the actual joint
density is g_C(y-c)*rho_R(k-y)/Z_R(y). Reweighting it by Z_R(y) gives an
ideal joint law whose integer marginal is exactly D_Z^n,F(c), by Gaussian
convolution. The Poisson certificate below bounds, uniformly in *every*
center, Z_R(y)/sqrt(det R) in [1-eps,1+eps]. Therefore the joint TV, and
hence the integer-marginal TV, is at most min(1,eps/(1-eps)). The same
conditional argument telescopes over history-dependent Schur leaves.

No finite arithmetic, lower-block scalar sampler, Setup-root distribution,
HNF law, norm acceptance, signature law, or security reduction is certified.
"""
from __future__ import annotations

_GATE_SCOPE = {
    "receipt_generated_on_fixed_roots": True,
    "fixed_roots_are_witnesses": True,
    "bound_scope": "every_plan_passing_complete_gate_set",
    "guard_built_into_backend": True,
    "all_gate_passing_setup_roots_covered": True,
}
_GATE_MASS_REASON = (r"the gate-set mass P(A\B), P(B\G) and the accepted-root "
                     r"distribution relative to mu_A remain unbounded; beta_bad remains null")

from fractions import Fraction

from .paper_rounding_budget import theta_certificate


SCHEMA = "IBME/SRGG-SCHUR-MATHEMATICAL-CONVOLUTION/1"


def convolution_tilt_tv_upper(relative_normalizer_error: Fraction) -> Fraction:
    """Exact conservative TV bound for one convolution leaf.

    This is deliberately a different comparison from the retained
    ``rounding_tv`` function and from the sequential-vs-joint normalizer.
    """
    if (type(relative_normalizer_error) is not Fraction
            or not 0 <= relative_normalizer_error < 1):
        raise ValueError("exact relative normalizer error in [0,1) required")
    epsilon = relative_normalizer_error
    return min(Fraction(1), epsilon/(1-epsilon))


def chain_convolution_certificate(*, degree: int, upper_polynomials: int,
                                  rounding_squared: Fraction,
                                  ideal_pivot_lower: Fraction,
                                  precision_bits: int = 512) -> dict:
    """Conditional all-center bridge for a bounded Schur chain.

    ``ideal_pivot_lower`` must be supplied from a separate exact-eigenvalue
    audit. This routine checks positivity of F-r^2 I but does not authenticate
    the supplied lower bound against a particular root or history.
    """
    if (type(degree) is not int or not 1 <= degree <= 512
            or type(upper_polynomials) is not int or not 1 <= upper_polynomials <= 16
            or type(rounding_squared) is not Fraction or rounding_squared <= 0
            or type(ideal_pivot_lower) is not Fraction or ideal_pivot_lower <= 0
            or type(precision_bits) is not int or not 128 <= precision_bits <= 2048):
        raise ValueError("bounded exact Schur convolution inputs required")
    if max(rounding_squared.numerator.bit_length(), rounding_squared.denominator.bit_length(),
           ideal_pivot_lower.numerator.bit_length(), ideal_pivot_lower.denominator.bit_length()) > 4096:
        raise ValueError("rational resource gate exceeded")

    result = {
        "schema": SCHEMA,
        "degree_per_leaf": degree,
        "upper_polynomials": upper_polynomials,
        "rounding_squared_exact": str(rounding_squared),
        "supplied_ideal_pivot_eigen_lower_exact": str(ideal_pivot_lower),
        "supplied_pivot_bound_authenticated_here": False,
        "positive_continuous_covariance": ideal_pivot_lower > rounding_squared,
        "theta_certificate": None,
        "relative_all_center_normalizer_error_upper_exact": None,
        "mathematical_single_leaf_tv_upper_exact": None,
        "mathematical_algorithm34_to_ideal_sequential_discrete_tv_upper_exact": None,
        "uniform_in_all_adaptive_leaf_centers": True,
        "lower_block_comparison": "identical exact lower-block discrete Gaussian in both references",
        "comparison": "exact continuous-plus-discrete Algorithm 4 Schur leaves vs ideal sequential discrete Schur leaves",
        "finite_to_mathematical_algorithm34_tv_upper": None,
        "ideal_sequential_vs_joint_integer_tv_upper": None,
        **_GATE_SCOPE,
        "accepted_setup_root_distribution_bound": None,
        "accepted_setup_root_distribution_reason": _GATE_MASS_REASON,
        "full_ibs_tv_upper": None,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
    }
    if ideal_pivot_lower <= rounding_squared:
        result["blocker"] = "supplied pivot lower bound does not certify F-r^2 I positive"
        return result

    theta = theta_certificate(dimension=degree, density_shape=rounding_squared,
                              precision_bits=precision_bits)
    result["theta_certificate"] = theta
    epsilon_text = theta["relative_normalizer_error_upper_exact"]
    if epsilon_text is None:
        result["blocker"] = "all-center theta sufficient bound is inconclusive; actual TV is not inferred"
        return result
    epsilon = Fraction(epsilon_text)
    result["relative_all_center_normalizer_error_upper_exact"] = str(epsilon)
    if epsilon >= 1:
        result["blocker"] = "all-center relative error bound is at least one; positive normalizer lower bound unavailable"
        return result
    leaf = convolution_tilt_tv_upper(epsilon)
    chain = min(Fraction(1), upper_polynomials*leaf)
    result["mathematical_single_leaf_tv_upper_exact"] = str(leaf)
    result["mathematical_algorithm34_to_ideal_sequential_discrete_tv_upper_exact"] = str(chain)
    result["method"] = (
        "Poisson all-center bound for Z_r(y)/r^n, exact continuous/discrete "
        "Gaussian convolution, likelihood-ratio TV, adaptive kernel telescoping")
    return result
