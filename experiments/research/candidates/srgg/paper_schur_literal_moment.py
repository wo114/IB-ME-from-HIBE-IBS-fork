"""Fourier second-moment bridge for the literal-density SRGG Schur leaf.

This is the second, distribution-aware route after the uniform product-
normalizer route.  It compares an *exact* Algorithm 4 continuous Gaussian
followed by an exact shifted integer Gaussian with the ideal integer Schur
conditional.  It does not compare finite arithmetic, Setup-root laws, HNF
keys, complete IBS histories, or native-strong games.

Write R=r^2 I, C=F-R, Y~D_cont,C(c), and W(Y)=Z_R(Y)/r^n.  The Fourier
series is W(y)=sum_z exp(-pi*r^2*||z||^2) exp(2*pi*i*<z,y>).  If F>=f I,
C>=(f-r^2)I, so with a(s)=exp(-pi*s) and t(s)=2*a(s)/(1-a(s)^3),

  |E W-1| <= delta := (1+t(f))^n-1,
  E(W-1)^2 <= M := (1+t(2*r^2))^n-1
                       +a(f-r^2)*((1+t(r^2))^n-1)^2.

The z+w=0 Fourier terms give the first part of M; every remaining integer
z+w is nonzero and contributes at most a(f-r^2) in absolute value.  Since
the ideal joint law is the Algorithm 4 joint law tilted by W, Cauchy-Schwarz
gives single-leaf TV <= sqrt(M)/(2*(1-delta)).  Uniformity in the adaptive
center permits sequential maximal coupling, yielding an L-leaf TV bound
1-(1-epsilon)^L when epsilon<1.  These are mathematical sufficient bounds,
not measurements of actual TV or security margins.

All transcendental operations use Sage MPFR real intervals.  Exact binary
upper endpoints are converted with exact_rational(), never QQ(RealNumber).
The final TV bounds are exact Fractions rounded only upward.
"""

from __future__ import annotations

from fractions import Fraction

from sage.all import QQ, RealIntervalField


SCHEMA = "IBME/SRGG-SCHUR-LITERAL-FOURIER-MOMENT/1"


def _upper(value) -> Fraction:
    rational = value.upper().exact_rational()
    return Fraction(int(rational.numerator()), int(rational.denominator()))


def _field_rational(field, value: Fraction):
    return field(QQ(value.numerator)/value.denominator)


def moment_chain_certificate(*, degree: int, upper_polynomials: int,
                             rounding_squared: Fraction,
                             ideal_pivot_lower: Fraction,
                             precision_bits: int = 512) -> dict:
    """Return a directed, exact-rational conditional TV certificate.

    ``ideal_pivot_lower`` is an external premise.  A separate fixed-root
    exact-eigenvalue audit must authenticate it for every leaf used here.
    """
    if (type(degree) is not int or not 1 <= degree <= 512
            or type(upper_polynomials) is not int or not 1 <= upper_polynomials <= 16
            or type(rounding_squared) is not Fraction or not 1 <= rounding_squared <= 16
            or type(ideal_pivot_lower) is not Fraction or ideal_pivot_lower <= 0
            or type(precision_bits) is not int or not 256 <= precision_bits <= 2048):
        raise ValueError("bounded exact Schur Fourier moment inputs required")
    if max(rounding_squared.numerator.bit_length(), rounding_squared.denominator.bit_length(),
           ideal_pivot_lower.numerator.bit_length(),
           ideal_pivot_lower.denominator.bit_length()) > 4096:
        raise ValueError("input rational exceeds resource gate")

    continuous_lower = ideal_pivot_lower-rounding_squared
    result = {
        "schema": SCHEMA,
        "degree_per_leaf": degree,
        "upper_polynomials": upper_polynomials,
        "rounding_squared_exact": str(rounding_squared),
        "supplied_ideal_pivot_eigen_lower_exact": str(ideal_pivot_lower),
        "continuous_covariance_eigen_lower_exact": str(continuous_lower),
        "fixed_root_pivot_floor_authenticated_here": False,
        "positive_continuous_covariance": continuous_lower > 0,
        "precision_bits": precision_bits,
        "scalar_theta_rounding_upper_exact": None,
        "scalar_theta_squared_rounding_upper_exact": None,
        "scalar_theta_pivot_floor_upper_exact": None,
        "exp_minus_pi_continuous_floor_upper_exact": None,
        "mean_offset_upper_exact": None,
        "moment_second_upper_exact": None,
        "mathematical_single_leaf_tv_upper_exact": None,
        "mathematical_algorithm34_to_ideal_sequential_discrete_tv_upper_exact": None,
        "uniform_in_all_adaptive_leaf_centers": True,
        "lower_block_comparison": "identical exact lower-block discrete Gaussian in both references",
        "comparison": "exact continuous-plus-discrete Algorithm 4 Schur leaves vs ideal sequential discrete Schur leaves",
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
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
        "method": "Poisson Fourier second moment; MPFR directed intervals; exact endpoint rational; adaptive maximal coupling",
    }
    if continuous_lower <= 0:
        result["blocker"] = "supplied pivot floor does not certify F-r^2 I positive"
        return result

    field = RealIntervalField(precision_bits)
    pi = field.pi()

    def a(shape: Fraction):
        return (-pi*_field_rational(field, shape)).exp()

    def t(shape: Fraction):
        weight = a(shape)
        return 2*weight/(1-weight**3)

    theta_rounding = t(rounding_squared)
    theta_squared = t(2*rounding_squared)
    theta_floor = t(ideal_pivot_lower)
    continuous_characteristic = a(continuous_lower)
    theta_rounding_sum = (1+theta_rounding)**degree-1
    mean_offset_interval = (1+theta_floor)**degree-1
    moment_interval = ((1+theta_squared)**degree-1
                       +continuous_characteristic*theta_rounding_sum**2)
    delta, moment = _upper(mean_offset_interval), _upper(moment_interval)

    result.update({
        "scalar_theta_rounding_upper_exact": str(_upper(theta_rounding)),
        "scalar_theta_squared_rounding_upper_exact": str(_upper(theta_squared)),
        "scalar_theta_pivot_floor_upper_exact": str(_upper(theta_floor)),
        "exp_minus_pi_continuous_floor_upper_exact": str(_upper(continuous_characteristic)),
        "mean_offset_upper_exact": str(delta),
        "moment_second_upper_exact": str(moment),
    })
    if not 0 <= delta < 1 or moment < 0:
        result["blocker"] = "directed mean or second-moment bound cannot certify a positive mean"
        return result

    # Re-embed exact outward endpoints, then preserve the upward endpoint of
    # sqrt(M)/(2*(1-delta)) as an exact rational.
    leaf_interval = _field_rational(field, moment).sqrt() / (
        2*(1-_field_rational(field, delta)))
    leaf = min(Fraction(1), _upper(leaf_interval))
    chain = 1-(1-leaf)**upper_polynomials
    result["mathematical_single_leaf_tv_upper_exact"] = str(leaf)
    result["mathematical_algorithm34_to_ideal_sequential_discrete_tv_upper_exact"] = str(chain)
    result["single_leaf_strictly_below_one_quarter"] = leaf < Fraction(1, 4)
    result["whole_chain_bound_nontrivial"] = chain < 1
    if chain == 1:
        result["blocker"] = "moment/coupling chain bound is trivial; actual TV remains unknown"
    return result
