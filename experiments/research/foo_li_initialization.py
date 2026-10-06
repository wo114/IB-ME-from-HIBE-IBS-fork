"""Correctness-only initialization certificates; not public-key regularity.

MP12 Lemmas 5.3, 4.3 and 2.3 give a sufficient smoothing condition for
every valid binary G-trapdoor in a public Frobenius quality class. Probability
bounds assume independent uniform bytes and the existing scalar certificate.
No Lean refinement or security claim is made by these numerical checks.
"""

from math import isqrt

from sage.all import GF, QQ, ZZ, RealIntervalField, identity_matrix, matrix

from .online_gaussian_reference import (
    capped_exp_minus_pi, exact_integer, exact_rational, interval_upper,
)
from .online_mp12_reference import OnlineGaussianGenTrap, modular_matrix, exact_matrix


def smoothing_from_quality(dimension, quality_squared, width_squared, epsilon):
    """Certify s^2 >= 10(Q+1) ln(2m(1+1/epsilon))/pi, outward rounded.

The factor 10 is conservative: 5(sqrt(Q)+1)^2 <= 10(Q+1).
Failure to certify is inconclusive, NOT a proof that actual C2 is false.
"""
    m = exact_integer(dimension, "dimension", minimum=1, maximum=128)
    quality = exact_integer(quality_squared, "quality", maximum=10**12)
    width = exact_rational(width_squared, "width squared")
    epsilon = exact_rational(epsilon, "epsilon0")
    if width <= 0 or not 0 < epsilon <= QQ(1)/4:
        raise ValueError("Need positive width and 0 < epsilon0 <= 1/4")
    field = RealIntervalField(192)
    basis_bound = 10*(quality+1)
    threshold = interval_upper(field(basis_bound)*field(2*m*(1+1/epsilon)).log()/field.pi())
    return {
        "method": "MP12 Lemmas 5.3, 4.3, 2.3; binary G; valid identity tag",
        "dimension": m, "quality_squared": quality,
        "width_squared": str(width), "epsilon0": str(epsilon),
        "basis_GS_squared_upper": basis_bound,
        "required_width_squared_upper": str(threshold),
        "C2_for_all_valid_quality_qualified_trapdoors": bool(width >= threshold),
        "not_MP12_internal_epsilon": True, "security_claim": "none",
    }


def initialization_budget(generator, quality_squared, width_squared, epsilon):
    """Unfiltered GenTrap failure budget, including abort exactly once.

TV from the ideal (uniform Abar, iid infinite Gaussian R0) JOINT law is
bounded by base-uniform abort + d*scalar-TV. This is not TV(public A, U).
The quality tail uses a coordinate union bound and rho_v(Z) >= 1.
"""
    if not isinstance(generator, OnlineGaussianGenTrap):
        raise ValueError("Need the actual online Gaussian generator")
    quality = exact_integer(quality_squared, "quality", maximum=10**12)
    m = generator.m_bar+generator.w
    d = generator.m_bar*generator.w
    smooth = smoothing_from_quality(m, quality, width_squared, epsilon)
    field = RealIntervalField(192)
    first_bad_coordinate = isqrt(quality//d)+1
    # If every coordinate is < a in absolute value then ||R||_F^2 <= Q.
    a = first_bad_coordinate
    v = generator.width_squared
    numerator = capped_exp_minus_pi(QQ(a*a)/v, field, 512)
    ratio = capped_exp_minus_pi(QQ(2*a+1)/v, field, 512)
    if (1-ratio).lower() <= 0:
        quality_tail = QQ(1)
    else:
        quality_tail = min(QQ(1), interval_upper(2*d*numerator/(1-ratio)))
    coordinate_tail = quality_tail
    # MP12 Lemma 2.6, zero-center clause: no smoothing hypothesis needed.
    radial_tail = QQ(1)/2**d if quality >= d*v else None
    if radial_tail is not None:
        quality_tail = min(quality_tail, radial_tail)
    uniform_abort = QQ(generator.n*generator.m_bar)/2**generator.scalar.options.max_uniform_trials
    gaussian_tv = d*generator.scalar.tv_upper
    joint_tv = min(QQ(1), interval_upper(field(uniform_abort+gaussian_tv)))
    delta = min(QQ(1), interval_upper(field(joint_tv+quality_tail)))
    certified = smooth["C2_for_all_valid_quality_qualified_trapdoors"]
    return {
        "smoothing": smooth, "master_entries": d,
        "first_bad_coordinate_absolute": a,
        "ideal_coordinate_union_tail_upper": str(coordinate_tail),
        "ideal_zero_center_radial_tail_upper": str(radial_tail) if radial_tail is not None else None,
        "ideal_master_quality_failure_upper": str(quality_tail),
        "base_uniform_abort_upper": str(uniform_abort),
        "master_scalar_joint_tv_including_abort_upper": str(gaussian_tv),
        "joint_generation_tv_including_abort_upper": str(joint_tv),
        "delta_init_upper": str(delta) if certified else None,
        "status": "conditional_uniform_byte_certificate" if certified else "C2_sufficient_condition_not_certified",
        "public_A_to_uniform_tv_upper": None,
        "OS_CSPRNG_information_theoretic_bound": None,
        "probability_model": "independent uniform bytes; unfiltered one-shot generator",
        "generator_public_tape_bytes": generator.random_tape_bytes,
        "scalar_certificate": generator.scalar.certificate(),
        "security_claim": "none",
    }


def check_initialized_state(generator, generated, quality_squared, width_squared, epsilon):
    """Validate an actual state separately from its population probability.

Malformed shapes/types raise ValueError. Algebraic/quality failures are recorded.
The caller must not condition away rejected generation attempts.
"""
    if generated.q != generator.q:
        raise ValueError("Generated modulus differs from configuration")
    q, n, w, r = generator.q, generator.n, generator.w, generator.m_bar
    base = modular_matrix(generated.a_bar, q, (n, r), "generated base")
    public = modular_matrix(generated.public, q, (n, r+w), "generated public")
    trapdoor = exact_matrix(generated.trapdoor, "master trapdoor")
    if trapdoor.dimensions() != (r, w) or any(x.denominator() != 1 for x in trapdoor.list()):
        raise ValueError("Master trapdoor dimensions or signed integers invalid")
    trapdoor = matrix(ZZ, trapdoor)
    identity_tag = generated.tag == identity_matrix(ZZ, n)
    gadget_matches = generated.gadget == generator.gadget
    base_matches = public[:, :r] == base
    relation = (public*trapdoor.stack(identity_matrix(ZZ, w))-generator.gadget).apply_map(lambda x: x % q).is_zero()
    rank = int(matrix(GF(q), public).rank())
    norm = sum(int(x)**2 for x in trapdoor.list())
    smooth = smoothing_from_quality(r+w, quality_squared, width_squared, epsilon)
    conditions = {
        "identity_tag": bool(identity_tag), "gadget_matches": bool(gadget_matches),
        "base_matches": bool(base_matches), "master_relation": bool(relation),
        "full_row_rank": rank == n, "master_quality": norm <= quality_squared,
        "C2_uniform_quality_certificate": smooth["C2_for_all_valid_quality_qualified_trapdoors"],
    }
    return {"conditions": conditions, "norm_squared": norm, "rank": rank,
        "InitGood_this_state": all(conditions.values()),
        "smoothing": smooth, "population_probability_inferred_from_one_state": False,
        "security_claim": "none"}
