"""Uniform error bounds for the existing finite SRGG perturbation sampler.

This certifies final integer outputs against an explicitly specified Gaussian
reference, under the directed-interval/MPFR assumptions in the accompanying
derivation. It does not identify the extracted/HNF key or signature law.
No secret shape, factor, center, random tape, or sample is exported.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
from math import isqrt
import json
from pathlib import Path

from sage.all import QQ, RealIntervalField

from experiments.research.online_gaussian_reference import OnlineScalarGaussian
from .config import Config
from .runtime import options as runtime_options
from .sampling import GadgetSampler, TableOptions


CERTIFICATE_BITS = 384


def _upper(value):
    """Outward dyadic rounding controls certificate size, never rounds down."""
    value = QQ(value)
    return min(QQ(1), QQ((value*2**CERTIFICATE_BITS).ceil())/2**CERTIFICATE_BITS)


def _sqrt_ceiling(value):
    value = QQ(value)
    if value < 0:
        raise ValueError("nonnegative squared bound required")
    whole = int(value.ceil())
    root = isqrt(whole)
    return root + int(root*root < whole)


def _pow2(exponent):
    return Fraction(2)**exponent


def numerical_rounding_bound(dimension, residual_diagonal_upper, opts, *, bad_bits=None):
    """Finite tickets and MPFR arithmetic, after ideal integer rounding.

    Input shape must have exact LDL and diagonal bounded by the supplied PUBLIC
    bound. Every rounding width must be >=1. Means remain exact rationals.
    The bound is uniform in mean, private shape and every adaptive history.
    """
    if type(dimension) is not int or not 1 <= dimension <= opts.max_dimension:
        raise ValueError("bounded coefficient dimension required")
    if QQ(residual_diagonal_upper) <= 0:
        raise ValueError("positive public residual diagonal bound required")
    b, precision = opts.ticket_bits, opts.precision_bits
    # This is a proof parameter, not a change to the sampling distribution.
    # Optimize the union/Lipschitz tradeoff over its finite exact domain.
    root = _sqrt_ceiling(residual_diagonal_upper)
    if bad_bits is None:
        def cost(exponent):
            grid = _pow2((2+exponent-b)//2) + 8*_pow2(-b-1)*2*(b+1)
            return ((dimension+1)//2)*_pow2(-exponent) + 240*dimension**2*root*grid
        t = min(range(1, b+1), key=cost)
    else:
        t = bad_bits
    if type(t) is not int or not 1 <= t <= b:
        raise ValueError("bad-event exponent must lie in [1,ticket_bits]")
    if precision < b+2:
        raise ValueError("midpoint tickets must convert exactly")
    d, pairs = dimension, (dimension+1)//2
    unit = _pow2(2-precision)
    if d*unit >= Fraction(1, 1024):
        raise ValueError("MPFR operation-count roundoff class is too large")
    radius = 2*(b+1)
    # delta=2^(-b-1), a=2^-t, so sqrt(4delta/a)<=2^ceil((1+t-b)/2).
    grid = _pow2((2+t-b)//2) + 8*_pow2(-b-1)*radius
    diagonal_root = root
    center_error = d*diagonal_root*grid + 1024*d*d*diagonal_root*radius*unit
    bad = pairs*_pow2(-t)
    final = min(Fraction(1), bad+240*d*center_error)
    return {
        "dimension": d, "public_residual_diagonal_upper": str(residual_diagonal_upper),
        "bad_event_exponent": t, "bad_event_upper": str(_upper(bad)),
        "uniform_center_error_per_coordinate_upper": str(QQ(center_error)),
        "center_kernel_tv_lipschitz_constant": 240,
        "numerical_to_ideal_rounding_tv_upper": str(_upper(final)),
        "reference": "exact continuous Gaussian followed by ideal D_Z,r integer rounding",
        "continuous_intermediate_tv": "1 (finite support versus continuous density)",
        "ticket_bits": b, "precision_bits": precision,
        "scope_certified_under_assumptions": True,
        "assumptions": [
            "independent uniform bytes and round-to-nearest MPFR elementary operations",
            "correctly rounded rational conversion, log, sqrt, pi, sin and cos",
            "no MPFR exponent overflow or underflow; exact rational LDL, means and Schur updates",
            "width r>=1; exact shape-r^2 I positive definite; public diagonal envelope valid",
            "all-path rational/output/tape preflight in full_sampling succeeds",
        ],
    }


def smoothing_epsilon(dimension, width_squared):
    """Poisson/dual-Z^d bound, using enclosing interval exponentials."""
    if type(dimension) is not int or not 1 <= dimension <= 100000:
        raise ValueError("positive bounded lattice dimension required")
    width = QQ(width_squared)
    if width < 1:
        raise ValueError("squared rounding width must be at least one")
    # Beyond this point the result is already below our outward dyadic floor.
    # Monotonicity permits the weaker width=128 envelope and prevents MPFR
    # underflow or an enormous exact rational conversion at very large widths.
    width = min(width, QQ(128))
    field = RealIntervalField(max(512, CERTIFICATE_BITS+64))
    term = (-field.pi()*field(width)).exp()
    theta = 2*term/(1-term**3)
    epsilon = (1+theta)**dimension-1
    return _upper(QQ(epsilon.upper()))


def _scalar(width_squared, opts):
    return OnlineScalarGaussian(width_squared, width_squared, options=opts.online_options())


def sample_f_class(dimension, public_diagonal_upper, width_squared, opts):
    scalar = _scalar(width_squared, opts)
    numerical = numerical_rounding_bound(dimension, public_diagonal_upper, opts)
    epsilon = smoothing_epsilon(dimension, width_squared)
    finite = _upper(QQ(numerical["numerical_to_ideal_rounding_tv_upper"])
                    + dimension*scalar.tv_upper)
    ideal = min(QQ(1), 8*epsilon) if epsilon <= QQ(1)/2 else QQ(1)
    return {
        "numerical": numerical,
        "rounding_scalar_tv_upper_including_abort": str(_upper(scalar.tv_upper)),
        "rounding_scalar_abort_upper": str(_upper(scalar.abort_upper)),
        "finite_to_ideal_continuous_rounding_tv_upper_including_abort": str(finite),
        "smoothing_epsilon_upper": str(epsilon),
        "peikert_theorem_3_1_continuous_part_applicable": epsilon <= QQ(1)/2,
        "ideal_rounding_to_target_discrete_gaussian_tv_upper": str(_upper(ideal)),
        "target_tv_upper_including_abort": str(_upper(finite+ideal)),
        "target": "D_Z^dimension,sqrt(Sigma),center, uniformly in exact center",
    }


def sample_p_class(dimension, block_size, public_diagonal_upper, width_squared, opts):
    if type(dimension) is not int or not 1 <= dimension <= opts.max_dimension:
        raise ValueError("bounded Schur dimension required")
    if type(block_size) is not int or not 1 <= block_size <= dimension or dimension % block_size:
        raise ValueError("block size must partition dimension")
    leaf = sample_f_class(block_size, public_diagonal_upper, width_squared, opts)
    blocks = dimension//block_size
    epsilon = QQ(leaf["smoothing_epsilon_upper"])
    # A reverse Schur Gaussian chain has the right numerator, but its varying
    # lattice normalizers must still be accounted for. No exact-joint claim.
    ratio = ((1+epsilon)/(1-epsilon))**blocks if epsilon < 1 else None
    bias = _upper((ratio-1)/2) if ratio is not None else QQ(1)
    total = _upper(blocks*QQ(leaf["target_tv_upper_including_abort"])+bias)
    return {
        "dimension": dimension, "block_size": block_size, "blocks": blocks,
        "leaf_certificate": leaf,
        "ideal_schur_chain_partition_bias_tv_upper": str(bias),
        "target_tv_upper_including_abort": str(total),
        "target": "joint discrete Gaussian with exact input Schur shape and mean",
        "requires_each_leaf_minus_rounding_width_identity_positive_definite": True,
    }


def geometry_class(upper_count, lower_count, degree, public_diagonal_upper,
                   lower_width_squared, rounding_width_squared, opts):
    upper = sample_p_class(upper_count, degree, public_diagonal_upper, rounding_width_squared, opts)
    lower = _scalar(lower_width_squared, opts)
    epsilon = smoothing_epsilon(upper_count, rounding_width_squared)
    bias = _upper(epsilon/(1-epsilon)) if epsilon < 1 else QQ(1)
    total = _upper(QQ(upper["target_tv_upper_including_abort"])
                   + lower_count*lower.tv_upper+bias)
    return {
        "upper": upper, "lower_count": lower_count,
        "lower_scalar_certificate": lower.certificate(),
        "lower_marginal_partition_bias_tv_upper": str(bias),
        "perturbation_target_tv_upper_including_abort": str(total),
        "target": "D_Z^D,sqrt(Sigma_p),0 on the actual admitted perturbation shape",
    }


def build_report(config=None):
    c = Config() if config is None else config
    if not isinstance(c, Config):
        raise TypeError("complete SRGG Config required")
    p, opts = c.algebra, runtime_options(c)
    master = geometry_class(2*p.rank*p.degree, p.rank*p.digits*p.degree, p.degree,
                            max(c.master_first_squared, c.master_second_squared),
                            c.master_second_squared-c.gadget_width_squared, c.r_squared, opts)
    signing = geometry_class(p.columns*p.degree, p.degree, p.degree,
                             max(c.signature_first_squared, c.signature_second_squared),
                             c.signature_second_squared-2*c.r_squared, c.r_squared, opts)
    gadget_full = GadgetSampler(p, c.gadget_width_squared, TableOptions(
        tail_bits=c.gadget_tail_bits, mass_bits=c.scalar_mass_bits,
        precision_bits=c.precision_bits, max_radius=128)).certificate(blocks=p.rank*p.degree)
    # Per-residue scalar tables are public, but unnecessary for this ledger.
    # Keep aggregate probabilities outward-rounded and avoid huge fractions.
    gadget = {name: str(_upper(QQ(gadget_full[name]))) for name in (
        "ideal_recurrence_to_spherical_fiber_tv_upper", "finite_sampling_tv_upper_including_abort",
        "abort_upper", "total_fiber_tv_upper_including_abort")}
    gadget.update({"blocks": gadget_full["blocks"], "scalar_draws": gadget_full["scalar_draws"],
                   "scope": gadget_full["scope"], "assumptions": gadget_full["assumptions"]})
    u = _scalar(c.r_squared, opts)
    extraction = _upper(QQ(master["perturbation_target_tv_upper_including_abort"])
                        + QQ(gadget["total_fiber_tv_upper_including_abort"]))
    sign_attempt = _upper(QQ(signing["perturbation_target_tv_upper_including_abort"])
                          + p.degree*u.tv_upper)
    master_abort = _upper(2*p.rank*p.degree*QQ(master["upper"]["leaf_certificate"][
        "rounding_scalar_abort_upper"])+p.rank*p.digits*p.degree*QQ(master[
        "lower_scalar_certificate"]["abort_upper"])+QQ(gadget["abort_upper"]))
    sign_abort = _upper(p.columns*p.degree*QQ(signing["upper"]["leaf_certificate"][
        "rounding_scalar_abort_upper"])+p.degree*QQ(signing[
        "lower_scalar_certificate"]["abort_upper"])+p.degree*u.abort_upper)
    return {
        "schema": "IBME/SRGG-FINAL-INTEGER-SAMPLING-ERROR/1",
        "parameters": c.record(), "certificate_dyadic_bits": CERTIFICATE_BITS,
        "master_perturbation": master, "signing_perturbation": signing,
        "gadget": gadget,
        "extraction_vs_sequential_ideal_sampler_tv_upper_including_abort": str(extraction),
        "sign_attempt_vs_sequential_ideal_sampler_tv_upper_including_abort": str(sign_attempt),
        "max_sign_attempt_sequence_tv_upper_including_abort": str(_upper(c.sign_max_attempts*sign_attempt)),
        "issuance_internal_sampling_abort_upper": str(master_abort),
        "sign_attempt_internal_sampling_abort_upper": str(sign_abort),
        "query_budgets": [{
            "new_identities": c.max_users, "signing_queries": queries,
            "sampling_only_transcript_tv_upper_including_abort": str(_upper(
                c.max_users*extraction+queries*c.sign_max_attempts*sign_attempt)),
            "sampling_only_service_abort_union_upper": str(_upper(
                c.max_users*master_abort+queries*c.sign_max_attempts*sign_abort)),
            "norm_reject_and_infrastructure_abort_included": False,
        } for queries in (1, 2**20, 2**40)],
        "full_service_abort_upper": None,
        "reference": "same sequential algorithm with ideal perturbation Gaussians, ideal gadget fiber and ideal u; same hashes, HNF and norm gates",
        "raw_extraction_convolution_identified": False,
        "hnf_exact_preimage_distribution_identified": False,
        "signature_output_gaussian_identified": False,
        "strong_unforgeability_established": False,
        "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False,
        "limits": ["roundoff assumptions are explicit mathematical hypotheses, not external MPFR verification",
                   "internal abort included; external entropy-provider failures have no probabilistic model",
                   "key/sign norm aborts and successful-output conditioning require separate analysis"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--profile", choices=("baseline-n8", "density-width3-n8"), default="baseline-n8")
    args = parser.parse_args()
    from .qualification_audit import profiles
    encoded = json.dumps(build_report(profiles()[args.profile]), ensure_ascii=False, indent=2)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8", newline="\n")
    print(encoded, end="")


if __name__ == "__main__":
    main()
