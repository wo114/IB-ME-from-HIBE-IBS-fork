"""Exact public CHKP width and rounded-noise conditions, not security admission."""
from fractions import Fraction
from math import isqrt
import re

def integer(value, name, low=1, high=65536):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an exact integer in {low}..{high}")
    return value

def rational(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, str, Fraction)):
        raise ValueError(f"{name} requires an exact rational")
    if isinstance(value, str):
        if len(value) > 2400 or not re.fullmatch(r"[+-]?[0-9]+(?:/[0-9]+)?", value):
            raise ValueError(f"{name} requires bounded integer/fraction text")
    try:
        value = Fraction(value)
    except (ValueError, ZeroDivisionError) as exc:
        raise ValueError(f"invalid {name}") from exc
    if max(abs(value.numerator).bit_length(), value.denominator.bit_length()) > 4096:
        raise ValueError(f"{name} exceeds rational bit budget")
    return value

def ceil_sqrt(value):
    value = rational(value, "square")
    if value < 0:
        raise ValueError("square must be nonnegative")
    root = isqrt(value.numerator // value.denominator)
    return root + int(root * root < value)

def smoothing_factor(dimension, epsilon_bits):
    return (2 * dimension * (1 + 2**epsilon_bits) - 1).bit_length()

def evaluate_noise(*, q, dimension, width_squared, alpha, error_bits=64,
                   seed_bits=256, encapsulations=1):
    """Exact sufficient decode budget, conditional on ||x||^2<=s^2*D.

    c0-x^T*c1 = bit*floor(q/2) + rounded-error-combination modulo q.
    Rounding contributes <=(||x||_1+1)/2. Its continuous part is Gaussian
    of squared width q^2*alpha^2*(||x||^2+1). Chernoff gives
    Pr[|Z|>sqrt(b+1)*width] <= 2*exp(-pi*(b+1)) <= 2^-b.
    A union bound covers shared-preamble bits without assuming independence.
    """
    q = integer(q, "q", low=2, high=2**61-1)
    dim = integer(dimension, "dimension")
    bits = integer(error_bits, "error_bits", low=2, high=4096)
    count = integer(seed_bits, "seed_bits")
    calls = integer(encapsulations, "encapsulations", high=2**32)
    width, rate = rational(width_squared, "width_squared"), rational(alpha, "alpha")
    if width <= 0 or not 0 < rate < 1:
        raise ValueError("need positive width_squared and 0<alpha<1")
    norm_squared = width * dim
    l1_upper = ceil_sqrt(dim * norm_squared)
    rounding = Fraction(l1_upper + 1, 2)
    # Strict nearest-centre distance, including odd q and ties going to one.
    phase_radius = (q // 2 - 1) // 2
    margin = phase_radius - rounding
    continuous_squared = q*q*rate*rate*(norm_squared + 1)*(bits + 1)
    noise_ok = margin > 0 and continuous_squared <= margin*margin
    return dict(q=q,dimension=dim,width_squared=str(width),alpha=str(rate),
                assumed_preimage_norm_squared_upper=str(norm_squared),
                preimage_norm_measured_or_certified=False,
                l1_integer_upper=l1_upper,rounding_error_upper=str(rounding),
                integer_phase_radius=phase_radius,continuous_margin=str(margin),
                continuous_squared_upper=str(continuous_squared),
                conditional_noise_sufficient=noise_ok,error_bits=bits,
                conditional_per_bit_failure_upper=str(Fraction(1,2**bits)) if noise_ok else None,
                conditional_lifetime_failure_upper=str(min(1,Fraction(count*calls,2**bits))) if noise_ok else None,
                seed_bits=count,encapsulations=calls,q_times_alpha=str(q*rate),
                shared_preamble_independence_required=False,
                noise_definition="CHKP section 2.3.1: round(q*continuous Gaussian width alpha) mod q",
                noise_implementation_verified=False,lwe_hardness_or_reduction_verified=False,
                excluded=["key norm bad event", "sampler TV and abort", "basis/resource failures",
                          "finite continuous-noise implementation", "security estimation"],
                backend_admitted=False,security_claim="none")
