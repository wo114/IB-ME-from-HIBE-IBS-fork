"""Complete-group target projections, two LWE roles and hard resource gaps.

The 192-bit finite recipe below is an ANALYSIS PROPOSAL, not an executable
HIBE profile. Only small public scalar/gadget/CDF objects are constructed.
No large matrices, roots, secret Schur inverses, keys or samples are made.
Existing runtime/codec limits are reported, never overridden.
"""

import argparse
from dataclasses import asdict
from fractions import Fraction
from hashlib import sha256
import json
from math import isqrt
from pathlib import Path

from ibme.lattice.chkp.joint_parameters import ceil_sqrt, smoothing_factor


ALLOCATION = dict(epsilon_bits=192, scalar_tail_bits=192, scalar_abort_bits=192,
    scalar_mass_bits=320, precision_bits=384, scalar_uniform_trials=256,
    perturbation_trials=512, noise_tail_bits=192, decode_error_bits=160,
    root_uniform_trials=256, ciphertext_uniform_trials=192, oracle_uniform_trials=192,
    target_lifetime_bits=128, encapsulations=2**20, H_queries=2**20, G_paths=2**20,
    receivers=2, children_each=2, identity_bytes=86, seed_bytes=32)


def _integer(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} requires an exact bounded integer")
    return value


def width_group(n, q_bits):
    n = _integer(n, "projection n", 2, 16384)
    k = _integer(q_bits, "projection modulus bits", 2, 256)
    w, m = n*k, n*(k+2)
    root_r_squared = 4*n+1
    root_bound = 2*n*w*root_r_squared
    r_squared = 4*smoothing_factor(w, ALLOCATION["epsilon_bits"])
    def width(bound): return max(7*r_squared*(1+bound), 10*r_squared*(w+bound))
    parent_squared = width(root_bound)
    parent_dimension = 2*m-w
    parent_bound = parent_dimension*w*parent_squared
    return dict(n=n, q_bits=k, w=w, m=m, root_r_squared=root_r_squared,
        root_R_bound=root_bound, r_squared=r_squared,
        parent_sample_dimension=parent_dimension, parent_width_squared=parent_squared,
        parent_R_bound=parent_bound, leaf_dimension=3*m,
        leaf_width_squared=width(parent_bound), q_alpha=isqrt(4*n)+1)


def noise_condition(q, dimension, squared_width, chi, *, error_bits=160):
    """The current integer decoder inequality, without runtime shape caps."""
    _integer(q, "projection q", 3, 2**256-1)
    _integer(dimension, "projection dimension", 1, 2**26)
    _integer(squared_width, "projection squared width", 1, 2**256)
    _integer(chi, "scaled noise", 1, 16384)
    _integer(error_bits, "decoder error bits", 8, 4096)
    norm = dimension*squared_width
    rounding = Fraction(ceil_sqrt(dimension*norm)+1, 2)
    continuous = chi**2*(norm+1)*(error_bits+1)
    phase = (q//2-1)//2
    margin = phase-rounding
    return dict(conditional_noise_sufficient=margin > 0 and continuous <= margin*margin,
        assumed_preimage_norm_squared_upper=str(norm), rounding_error_upper=str(rounding),
        continuous_squared_upper=str(continuous), integer_phase_radius=phase,
        continuous_margin=str(margin), error_bits=error_bits)


def select_group(n):
    """Smallest proven prime for this fixed recipe, including odd-q rounding."""
    from sage.all import next_prime
    for k in range(2, 257):
        group = width_group(n, k)
        candidate = noise_condition(2**k-1, group["leaf_dimension"],
            group["leaf_width_squared"], group["q_alpha"])
        if not candidate["conditional_noise_sufficient"]:
            continue
        rounding = Fraction(candidate["rounding_error_upper"])
        continuous = Fraction(candidate["continuous_squared_upper"])
        phase = int(rounding.__ceil__())+ceil_sqrt(continuous)
        while phase-1 > rounding and (phase-1-rounding)**2 >= continuous:
            phase -= 1
        # For odd q the decoder radius is floor((q-3)/4).
        minimum = max(2**(k-1)+1, 4*phase+3)
        q = int(next_prime(minimum-1, proof=True))
        if q >= 2**k:
            continue
        budget = noise_condition(q, group["leaf_dimension"],
            group["leaf_width_squared"], group["q_alpha"])
        assert budget["conditional_noise_sufficient"]
        return dict(group, q=q, q_prime_proved=True, noise=budget)
    raise ValueError("no complete group found within the analysis modulus domain")


def resource_projection(group):
    n, k, w, m = (group[x] for x in ("n", "q_bits", "w", "m"))
    parent = group["parent_sample_dimension"]
    leaf = group["leaf_dimension"]
    word = (k+7)//8
    counts = dict(root_R_entries=2*n*w, parent_R_entries=parent*w,
        parent_sampler_Schur_entries=(4*n)**2, leaf_sampler_Schur_entries=(leaf-w)**2,
        fixed_leaf_integers=256*leaf, complete_root_columns=m,
        parent_sample_columns=parent, complete_parent_columns=2*m,
        complete_leaf_columns=leaf, complete_leaf_prefix=leaf-w)
    # Each JSON integer costs at least a digit and a separator (brackets only
    # increase this); each current signed leaf scalar costs >=1+4+1 bytes.
    minimum = dict(root_R_JSON_bytes=2*counts["root_R_entries"],
        parent_R_JSON_bytes=2*counts["parent_R_entries"],
        public_root_residue_bytes=n*m*word,
        single_fixed_leaf_wire_bytes=6*counts["fixed_leaf_integers"],
        capsule_residue_bytes=(leaf+256)*word)
    gates = dict(n_within_128=n <= 128, modulus_within_61_bits=k <= 61,
        q_fits_existing_uint64_headers=group["q"] < 2**64,
        complete_HG_prefix_within_512=leaf-w <= 512,
        complete_columns_within_8192=leaf <= 8192,
        parent_R_entries_within_2pow22=counts["parent_R_entries"] <= 2**22,
        root_JSON_not_excluded_by_32MiB=minimum["root_R_JSON_bytes"] <= 32*2**20,
        parent_JSON_not_excluded_by_32MiB=minimum["parent_R_JSON_bytes"] <= 32*2**20,
        public_oracle_not_excluded_by_2MiB=minimum["public_root_residue_bytes"] <= 2*2**20,
        fixed_leaf_not_excluded_by_16MiB=minimum["single_fixed_leaf_wire_bytes"] <= 16*2**20,
        raw_capsule_not_excluded_by_2MiB=minimum["capsule_residue_bytes"] <= 2*2**20,
        Hybrid_capsule_not_excluded_by_4MiB=minimum["capsule_residue_bytes"] <= 4*2**20,
        squared_width_within_2pow192=group["leaf_width_squared"] <= 2**192)
    return dict(counts=counts, codec_minimum_bytes=minimum, current_gates=gates,
        first_geometry_or_wire_obstruction=next((key for key,value in gates.items() if not value), None),
        minimum_bytes_do_not_prove_passing_inputs_fit=True,
        process_peak_RSS=None, stage_seconds=None, full_kernel_basis_entries_allocated=0)


def analysis_gadget(q):
    """Only a public k-dimensional kernel; does not extend the runtime q cap."""
    from ibme.lattice.matrix_sampling.prime_gadget import prime_gadget_kernel
    return prime_gadget_kernel(q)


def projected_distribution_budget(group):
    """Concrete finite-profile projection, conditional on future resources.

    The large dimensions are counts only. The exact rational/Schur paths of
    private keys and whole-call entropy wrappers have NOT been admitted.
    """
    from sage.all import QQ, RealBallField
    from ibme.lattice.matrix_sampling.scalar import MatrixFiniteOptions, MatrixFiniteGaussian
    from ibme.lattice.matrix_sampling.gpv import MatrixFiniteGPV
    from ibme.lattice.matrix_sampling.mp12_bounds import convolution_tv_upper
    from ibme.lattice.chkp.rounded_noise import cdf_integer_interval
    opts = MatrixFiniteOptions(tail_bits=192, gaussian_abort_bits=192, mass_bits=320,
                              precision_bits=384, max_uniform_trials=256)
    n, w = group["n"], group["w"]
    gadget = MatrixFiniteGPV(analysis_gadget(group["q"]), 5*group["r_squared"],
                           epsilon_bits=192, options=opts)
    eps = Fraction(1, 2**192)
    phases = {}
    for phase, dimension, bound, squared in (
        ("parent", group["parent_sample_dimension"], group["root_R_bound"], group["parent_width_squared"]),
        ("leaf", group["leaf_dimension"], group["parent_R_bound"], group["leaf_width_squared"])):
        scalar = MatrixFiniteGaussian(squared, squared, options=opts)
        assert dimension*scalar.theta <= QQ(1)/2
        assert squared >= 10*(bound+1)*smoothing_factor(dimension, 192)
        delta = min(Fraction(1), 512*(dimension*Fraction(str(scalar.tv_upper))+
            Fraction(str(scalar.weight_width))+Fraction(1, 2**320)) + Fraction(3, 4)**512 +
            n*Fraction(str(gadget.tv_upper))+convolution_tv_upper(192))
        tape = 512*(dimension*scalar.random_tape_bytes+40)+n*gadget.random_tape_bytes
        # Coarsen huge norm exponents before integer allocation/serialization.
        norm = Fraction(1, 2**min(dimension, 256))*(1+eps)/(1-eps)
        phases[phase] = dict(dimension=dimension, scalar=scalar.certificate(),
            modeled_sample_TV_including_abort_upper=str(delta),
            ideal_norm_abort_upper=str(norm), worst_request_tape_bytes=tape)
    root = MatrixFiniteGaussian(group["root_r_squared"], group["root_r_squared"], options=opts)
    root_entries = 2*n*w
    parents, leaves = 2*w, 4*256
    terms = dict(root_uniform_abort=Fraction(n*n, 2**256),
        root_scalar_coupling=root_entries*Fraction(str(root.tv_upper)),
        ideal_root_norm_abort=Fraction(1, 2**min(root_entries, 256)),
        parent_sample_coupling=parents*Fraction(phases["parent"]["modeled_sample_TV_including_abort_upper"]),
        ideal_parent_norm_abort=parents*Fraction(phases["parent"]["ideal_norm_abort_upper"]),
        leaf_sample_coupling=leaves*Fraction(phases["leaf"]["modeled_sample_TV_including_abort_upper"]),
        ideal_leaf_norm_abort=leaves*Fraction(phases["leaf"]["ideal_norm_abort_upper"]))
    chi = group["q_alpha"]
    radius = ceil_sqrt(chi*chi*193)
    if radius > 8192: raise ValueError("analysis noise radius budget")
    f, total, previous, units = RealBallField(384), 2**320, 0, 0
    cdf_digest = sha256()
    for value in range(-radius, radius):
        lower, upper = cdf_integer_interval(f, QQ(chi), 2*value+1, total)
        cutoff = max(previous, lower)
        if cutoff > upper or upper-lower > 4: raise ValueError("analysis noise CDF precision")
        units += upper-cutoff
        cdf_digest.update(cutoff.to_bytes(41, "big"))
        previous = cutoff
    cdf_digest.update(total.to_bytes(41, "big"))
    noise_delta = Fraction(1, 2**192)+Fraction(units, 2**320)
    terms["finite_noise_coupling"] = 2**20*(group["leaf_dimension"]+256)*noise_delta
    terms["ciphertext_uniform_abort"] = Fraction(2**20*n, 2**192)
    terms["ideal_decode_failure_if_norm_good"] = Fraction(256*2**20, 2**160)
    terms["ideal_RO_uniform_abort"] = Fraction(n*(group["m"]+256)*2**20, 2**192)
    bound = min(Fraction(1), sum(terms.values(), Fraction(0)))
    return dict(phases=phases, finite_options=asdict(opts),
        root_scalar=root.certificate(), gadget_geometry_tv=str(gadget.geometry_tv),
        gadget_scalar_tv=str(gadget.scalar_tv),
        noise=dict(scaled_width=chi, radius=radius, tail_bits=192, mass_bits=320,
            precision_bits=384, cdf_interval_error_units=units, cdf_sha256=cdf_digest.hexdigest(),
            scalar_TV_upper=str(noise_delta), modulus_independent_integer_CDF=True),
        terms={key:str(min(Fraction(1), value)) for key,value in terms.items()},
        modeled_lifetime_upper=str(bound), probability_dyadic_exponent=(bound.denominator//bound.numerator).bit_length()-1,
        target_128_met_in_resource_conditional_projection=bound <= Fraction(1, 2**128),
        whole_parent_worst_request_bytes=w*phases["parent"]["worst_request_tape_bytes"],
        whole_leaf_worst_request_bytes=256*phases["leaf"]["worst_request_tape_bytes"],
        actual_private_precision_or_whole_call_resource_admitted=False,
        noise_CDF_constructed_without_mod_q_or_any_entropy=True,
        norm_exponents_conservatively_capped_at_256=True,
        current_HIBE_recipe_implemented=False, security_claim="none", backend_admitted=False)


def target_row(n):
    group = select_group(n)
    common = dict(n=n, q=group["q"], secret="small-Gaussian",
        multi_target_or_reduction_loss_applied=False)
    return dict(family="mp12-structured-hg-target-projection", n=n, q_bits=group["q_bits"],
        complete_group=group, allocation_proposal=ALLOCATION,
        root_lwe=dict(common, m=n, squared_width=group["root_r_squared"],
            independent_columns=group["w"], attack_goal="one root-column search or decision, not full trapdoor recovery",
            distribution="ideal discrete Gaussian root secret and error; finite root coupling separate"),
        ciphertext_lwe=dict(common, m=2*group["m"], squared_width=group["q_alpha"]**2,
            attack_goal="recover minus leading rounded errors using the two public H blocks; then recover encryption secret",
            distribution="finite rounded-continuous secret/error; discrete Gaussian comparator ONLY",
            estimator_distribution_is_literal=False,
            equation="b_H = c_H - H^T*c_I = H^T*(-e_I) + e_H mod q",
            available_H_samples=2*group["m"], all_available_H_samples_supplied=True,
            root_other_columns_and_256_terminals_used=False),
        resources=resource_projection(group), finite_projection=projected_distribution_budget(group),
        estimator_results={}, actual_full_HIBE_execution=False,
        root_or_key_generations=0, entropy_reads=0, sampler_calls=0,
        secure_candidate_selected=False, security_claim="none", backend_admitted=False,
        parameters_are_formal=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dimensions", type=int, nargs="+", default=[128, 512, 2048, 4096])
    parser.add_argument("--estimator-path", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if len(set(args.dimensions)) != len(args.dimensions): raise ValueError("distinct analysis dimensions required")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream: stream.write('{"status":"started"}\n')
    report = dict(schema="STRUCTURED-HG-TARGET-GROUP-SCREEN/1", rows=[],
        allocation_is_analysis_only_and_unregistered=True,
        current_backend_and_wire_limits_unchanged=True, security_claim="none",
        backend_admitted=False, parameters_are_formal=False)
    def save(): args.output.write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    for n in args.dimensions:
        row = target_row(n)
        report["rows"].append(row)
        save()
        print(json.dumps(dict(n=n, q_bits=row["q_bits"],
            modeled_probability_exponent=row["finite_projection"]["probability_dyadic_exponent"],
            first_current_obstruction=row["resources"]["first_geometry_or_wire_obstruction"])), flush=True)
    if args.estimator_path:
        from experiments.research.abb_rom.scaled_parameter_screen import run_estimators
        run_estimators(report, args.estimator_path, checkpoint=save)
    report["status"] = "completed_public_projection"
    save()


if __name__ == "__main__": main()
