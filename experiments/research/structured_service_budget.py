"""No-secret complete-group Gaussian/abort ledger for structured H/G.

The arithmetic model and the ideal-RO comparison are explicit and separate.
This constructs only public scalar, gadget and rounded-noise profiles. It
does not construct a trapdoor, invert a secret Schur matrix or draw entropy.
"""

import argparse
from fractions import Fraction
import json
from pathlib import Path

from sage.all import QQ

from ibme.hibe.mp12_structured.params import StructuredHIBEParams, output_width
from ibme.lattice.chkp.joint_parameters import evaluate_noise, smoothing_factor
from ibme.lattice.chkp.noise_budget import RoundedNoiseParams, attach_finite_noise_budget
from ibme.lattice.chkp.rounded_noise import build_rounded_noise
from ibme.lattice.matrix_sampling.gpv import MatrixFiniteGPV
from ibme.lattice.matrix_sampling.mp12_bounds import sample_distribution_budget
from ibme.lattice.matrix_sampling.mp12_structured import gadget_block
from ibme.lattice.matrix_sampling.scalar import MatrixFiniteGaussian, MatrixFiniteOptions


def _count(value, name, maximum=2**32):
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(f"{name} requires a positive bounded integer")
    return value


def dyadic_exponent(bound):
    """Largest b with bound <= 2^-b; a probability exponent, not security."""
    value = Fraction(bound)
    if not 0 < value <= 1:
        raise ValueError("nonzero probability in (0,1] required")
    return (value.denominator//value.numerator).bit_length()-1


def public_profile(params, dimension, bound):
    """Distribution/tape projection, without claiming secret-path admission."""
    opts = params.sampling_options() if isinstance(params, StructuredHIBEParams) else MatrixFiniteOptions()
    epsilon = getattr(params, "sampler_epsilon_bits", 128)
    r_squared = 4*smoothing_factor(params.w, epsilon)
    squared = output_width(params.w, bound, epsilon_bits=epsilon)
    scalar = MatrixFiniteGaussian(squared, squared, options=opts)
    gadget = MatrixFiniteGPV(gadget_block(params.q), 5*r_squared,
                           epsilon_bits=epsilon, options=opts)
    if dimension*scalar.theta > QQ(1)/2:
        raise ValueError("spherical normalizer premise unverified")
    tape = 512*(dimension*scalar.random_tape_bytes+(opts.mass_bits+7)//8)+params.n*gadget.random_tape_bytes
    if tape > opts.max_tape_bytes:
        raise ValueError("public single-SampleD tape limit")
    smoothing = squared >= 10*(bound+1)*smoothing_factor(dimension, epsilon)
    budget = sample_distribution_budget(dimension=dimension, epsilon_bits=epsilon,
        max_trials=512, proposal_scalar_tv=str(scalar.tv_upper),
        bernoulli_weight_error=str(scalar.weight_width+QQ(1)/2**opts.mass_bits),
        gadget_tv_total=str(min(1, params.n*gadget.tv_upper)),
        target_smoothing_verified=bool(smoothing))
    return dict(dimension=dimension, declared_R_bound=str(bound), r_squared=r_squared,
        output_squared=str(squared), scalar=scalar.certificate(),
        gadget_geometry_tv=str(gadget.geometry_tv), gadget_scalar_tv=str(gadget.scalar_tv),
        distribution=budget, worst_request_tape_bytes=tape,
        actual_trapdoor_precision_gate_checked=False,
        no_trapdoor_or_samples_constructed=True)


def _reported_probability(value, params):
    """v2 rounds OUTWARD to a bounded dyadic denominator, never to zero.

    This also prevents exact tiny residue-rejection fractions from producing
    unbounded JSON integer text. V1 receipts retain their original fractions.
    """
    value = min(Fraction(1), Fraction(value))
    bits = params.probability_reporting_bits
    if bits is None or value == 0:
        return value
    units = (value.numerator*2**bits+value.denominator-1)//value.denominator
    return Fraction(units, 2**bits)


def service_budget(params, *, encapsulations=2**20, h_queries=2**20,
                   g_paths=2**20, target_bits=128):
    if not isinstance(params, StructuredHIBEParams):
        raise ValueError("complete structured H/G parameters required")
    enc = _count(encapsulations, "encapsulations")
    hq, gp = _count(h_queries, "distinct H queries"), _count(g_paths, "distinct G paths")
    target = _count(target_bits, "target probability exponent", 4096)
    minimum_paths = params.max_receivers*params.max_children
    if hq < params.max_receivers+minimum_paths or gp < minimum_paths:
        raise ValueError("oracle query budget must cover the declared fixed key tree")
    parent = public_profile(params, params.parent_sample_dimension, params.root_bound)
    leaf = public_profile(params, params.leaf_dimension, params.parent_bound)
    if not all(p["distribution"]["target_smoothing_verified"] for p in (parent, leaf)):
        raise ValueError("coset norm-tail smoothing condition is not established")
    if (params.w*parent["worst_request_tape_bytes"] > 2**44
            or 256*leaf["worst_request_tape_bytes"] > 2**48):
        raise ValueError("whole parent/leaf random-request budget")
    opts = params.sampling_options()
    root = MatrixFiniteGaussian(params.root_r_squared, params.root_r_squared, options=opts)
    root_entries = 2*params.n*params.w
    parent_calls = params.max_receivers*params.w
    leaf_calls = minimum_paths*256
    rejection = Fraction(2**((params.q-1).bit_length())-params.q,
                         2**((params.q-1).bit_length()))
    terms = dict(
        root_uniform_abort=min(Fraction(1), params.n**2*rejection**opts.max_uniform_trials),
        root_scalar_coupling=min(Fraction(1), root_entries*Fraction(str(root.tv_upper))),
        ideal_root_norm_abort=Fraction(1, 2**root_entries),
        parent_sample_coupling=min(Fraction(1), parent_calls*Fraction(
            parent["distribution"]["modeled_sample_TV_including_abort_upper"])),
        ideal_parent_column_norm_abort=min(Fraction(1), parent_calls*Fraction(
            parent["distribution"]["ideal_coset_norm_abort_upper"])),
        leaf_sample_coupling=min(Fraction(1), leaf_calls*Fraction(
            leaf["distribution"]["modeled_sample_TV_including_abort_upper"])),
        ideal_leaf_norm_abort=min(Fraction(1), leaf_calls*Fraction(
            leaf["distribution"]["ideal_coset_norm_abort_upper"])))
    terms = {key:_reported_probability(value, params) for key,value in terms.items()}
    tree = min(Fraction(1), sum(terms.values(), Fraction(0)))
    noise = build_rounded_noise(RoundedNoiseParams(params.q, params.alpha, **params.noise_options()))
    ideal = evaluate_noise(q=params.q, dimension=params.leaf_dimension,
        width_squared=params.leaf_width_squared, alpha=params.alpha,
        error_bits=params.decode_error_bits, seed_bits=256, encapsulations=enc)
    finite_noise = attach_finite_noise_budget(ideal, noise.certificate())
    terms["ciphertext_secret_uniform_abort"] = min(Fraction(1), enc*params.n*rejection**128)
    terms["finite_ciphertext_noise_coupling"] = Fraction(finite_noise["joint_noise_coupling_upper"])
    terms["ideal_honest_decode_failure_if_norm_good"] = Fraction(ideal["conditional_lifetime_failure_upper"])
    terms = {key:_reported_probability(value, params) for key,value in terms.items()}
    oracle_residues = params.n*(params.m*hq+256*gp)
    ro_abort = _reported_probability(oracle_residues*rejection**128, params)
    honest = min(Fraction(1), sum(terms.values(), Fraction(0)))
    ro_model = min(Fraction(1), honest+ro_abort)
    return dict(schema="STRUCTURED-HG-SERVICE-STATISTICAL-BUDGET/1",
        parameters=params.record(), measured=False, root_scalar=root.certificate(),
        parent=parent, leaf=leaf, finite_noise=finite_noise,
        counts=dict(root_setups=1, root_R_scalar_draws=root_entries,
            root_uniform_draws=params.n**2, distinct_receivers=params.max_receivers,
            distinct_leaf_keys=minimum_paths, parent_SampleD_calls=parent_calls,
            leaf_SampleD_calls=leaf_calls, fixed_key_reuse_additional_SampleD_calls=0,
            encapsulations=enc, ciphertext_noise_draws=enc*(params.leaf_dimension+256),
            ciphertext_secret_uniform_draws=enc*params.n,
            max_distinct_H_queries=hq, max_distinct_G_paths=gp,
            max_distinct_G_position_queries=256*gp, ideal_RO_residue_draws=oracle_residues),
        terms={key:str(value) for key,value in terms.items()},
        tree_to_uncut_Gaussian_reference_TV_including_abort_upper=str(tree),
        modeled_joint_deviation_or_honest_failure_upper=str(honest),
        ideal_RO_bounded_residue_abort_upper=str(ro_abort),
        ideal_RO_model_joint_upper=str(ro_model),
        modeled_probability_dyadic_exponent=dyadic_exponent(ro_model),
        target_probability_exponent=target,
        meets_target_in_stated_model=ro_model <= Fraction(1, 2**target),
        oracle_model="independent uniform random streams at distinct canonical H/G addresses; repeat queries fixed",
        oracle_budget_covers_adversarial_queries_only_up_to_declared_counts=True,
        actual_SHAKE_indifferentiability_verified=False,
        key_comparison="same computational [I|Ahat] root construction, ideal unbounded Gaussians; not uniform public roots",
        finite_sampler_assumptions=parent["distribution"]["assumptions"],
        actual_all_key_precision_or_workspace_verified=False,
        full_implementation_or_security_failure_upper=None,
        root_or_key_generations=0, entropy_reads=0, sampler_calls=0,
        tape_upper_is_not_allocated_memory=True,
        excluded=["OS/allocation or faulty-source failures", "side channels and rollback",
                  "actual SHAKE versus random oracles", "computational root/LWE security",
                  "ROM construction reduction and IBS/Hybrid/BYTEAUTH security"],
        security_claim="none", backend_admitted=False, parameters_are_formal=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--params-file", type=Path)
    parser.add_argument("--encapsulations", type=int, default=2**20)
    parser.add_argument("--h-queries", type=int, default=2**20)
    parser.add_argument("--g-paths", type=int, default=2**20)
    parser.add_argument("--target-bits", type=int, default=128)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("use a new public budget receipt")
    from ibme.hibe.mp12_structured.params import load_structured_parameters
    params = (StructuredHIBEParams() if args.params_file is None else
              load_structured_parameters(args.params_file.read_bytes()))
    report = service_budget(params, encapsulations=args.encapsulations,
        h_queries=args.h_queries, g_paths=args.g_paths, target_bits=args.target_bits)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(report, indent=2)+"\n")
    print(json.dumps(dict(status="computed", meets_target=report["meets_target_in_stated_model"],
        probability_exponent=report["modeled_probability_dyadic_exponent"], security_claim="none")))


if __name__ == "__main__":
    main()
