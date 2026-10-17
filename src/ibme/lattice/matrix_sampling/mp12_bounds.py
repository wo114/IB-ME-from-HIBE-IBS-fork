"""Concrete statistical terms for the structured MP12 research sampler.

This is probability accounting, not a security reduction. MP12 Theorem 5.5
is expanded using its two shifted-lattice normalizers. Finite proposals,
Bernoulli rounding, bounded rejection and the gadget oracle are coupled
separately. Bounds assume independent uniform bytes and admitted arithmetic.
They say nothing about faulty entropy, OS failures, SHAKE or LWE hardness.
"""

from fractions import Fraction
import re


def _integer(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} requires an exact bounded integer")
    return value


def _probability(value, name):
    if type(value) not in (int, str, Fraction):
        raise ValueError(f"{name} requires an exact probability")
    if isinstance(value, str) and (len(value) > 8192 or
            not re.fullmatch(r"[+-]?[0-9]+(?:/[0-9]+)?", value)):
        raise ValueError(f"{name} bounded integer/fraction probability required")
    try:
        value = Fraction(value)
    except (ValueError, ZeroDivisionError) as exc:
        raise ValueError(f"invalid {name}") from exc
    if not 0 <= value <= 1:
        raise ValueError(f"{name} outside [0,1]")
    return value


def convolution_tv_upper(epsilon_bits):
    """Explicit conservative constant from MP12 proof (5.1), PDF pp.28-29.

    Put t=(1+eps)/(1-eps). The unnormalized output/target density ratio
    lies in [1/t,t] up to a common constant. Normalization makes the ratio
    lie in [1/t**2,t**2]. Hence TV <= (t**2-1)/2. Both smoothing premises
    of Theorem 5.5 must have been checked by the caller.
    """
    bits = _integer(epsilon_bits, "epsilon bits", 2, 4096)
    eps = Fraction(1, 2**bits)
    return min(Fraction(1), 2*eps/(1-eps)**2)


def coset_norm_tail_upper(dimension, epsilon_bits):
    """Pr[||X||^2 > D*s^2] for a smoothed spherical Gaussian coset.

    Exponential Markov with exponent pi/(2*s^2), followed by Poisson
    normalizer bounds, gives (sqrt(2)*exp(-pi/2))**D*(1+eps)/(1-eps).
    The rational factor 3/10 is an upper bound on sqrt(2)*exp(-pi/2).
    This sharper form avoids mistaking the coarser 2**(-D) lemma for a
    sufficient 128-bit budget on an 88-dimensional delegated column.
    """
    dimension = _integer(dimension, "dimension", 1, 8192)
    bits = _integer(epsilon_bits, "epsilon bits", 2, 4096)
    eps = Fraction(1, 2**bits)
    bound = min(Fraction(1), Fraction(3, 10)**dimension*(1+eps)/(1-eps))
    # An outward dyadic bound also keeps the largest profile's JSON integers
    # within Python's decimal-conversion limit; do not disable that limit.
    exponent = (bound.denominator//bound.numerator).bit_length()-1
    return Fraction(1, 2**exponent)


def sample_distribution_budget(*, dimension, epsilon_bits, max_trials,
                               proposal_scalar_tv, bernoulli_weight_error,
                               gadget_tv_total, target_smoothing_verified):
    """Count each actual random mechanism once, uniformly in the syndrome.

    A scalar TV term already includes its own bounded-rejection abort.
    Perturbation exhaustion is a separate event. Gadget TV includes its
    finite scalar and GPV geometry terms. No independence is needed to add
    these bounds across adaptive calls or after a deterministic norm test.
    """
    dimension = _integer(dimension, "dimension", 1, 8192)
    trials = _integer(max_trials, "perturbation trials", 1, 4096)
    scalar = _probability(proposal_scalar_tv, "proposal scalar TV")
    weight = _probability(bernoulli_weight_error, "Bernoulli error")
    gadget = _probability(gadget_tv_total, "gadget TV")
    if type(target_smoothing_verified) is not bool:
        raise ValueError("target smoothing flag must be boolean")
    convolution = convolution_tv_upper(epsilon_bits)
    finite = min(Fraction(1), trials*(dimension*scalar+weight))
    exhaustion = Fraction(3, 4)**trials
    total = min(Fraction(1), finite+exhaustion+gadget+convolution)
    return dict(
        schema="MP12-STRUCTURED-DISTRIBUTION-BUDGET/1",
        convolution_tv_upper=str(convolution),
        finite_perturbation_coupling_upper=str(finite),
        ideal_perturbation_exhaustion_upper=str(exhaustion),
        gadget_coupling_upper=str(gadget),
        modeled_sample_TV_including_abort_upper=str(total),
        ideal_coset_norm_abort_upper=(str(coset_norm_tail_upper(dimension, epsilon_bits))
                                     if target_smoothing_verified else None),
        target_smoothing_verified=target_smoothing_verified,
        comparison="uncut ideal spherical discrete Gaussian on the requested coset",
        assumptions=["independent uniform source bytes", "ideal perturbation acceptance >=1/4",
                     "both MP12 Theorem5.5 smoothing conditions", "admitted exact arithmetic paths",
                     "the finite scalar/GPV directed-rounding contract"],
        excluded=["OS/allocation failures", "faulty entropy providers", "side channels",
                  "SHAKE versus a random oracle", "root pseudorandomness", "LWE hardness"],
        security_claim="none", backend_admitted=False, parameters_are_formal=False)
