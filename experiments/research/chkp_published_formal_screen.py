"""Published-layout CHKP ROM target and a non-admission certificate.

This screen pins the EUROCRYPT 2010 ROHIBE layout: a depth-two identity uses
``A0 || H(receiver)`` (2m coefficients) and ``G(receiver, sender)`` as the
terminal syndrome.  For a conservative cross-depth anonymity target, the KEM
preamble is padded to 3m with independent uniform residues, following the
paper's separate padding observation.  The later 2011 author manuscript
instead writes a 3m *LWE leaf* while its theorem and simulator still use
``dm`` and only ``d-1`` H guesses; the installed research backend follows that
3m definition and is therefore not admitted by this certificate.

The selected numbers completely specify a *paper-layout numeric target* under
classical-ROM LWE assumptions.  They are not a formal security admission or an
executable backend profile and do not make a NIST or concrete-bit claim.
Estimator output is a separate heuristic attack screen and deliberately leaves
unsupported attack/distribution models open.
"""

import argparse
from fractions import Fraction
import hashlib
import json
from math import log2
from pathlib import Path
import platform
import sys

from experiments.research.structured_target_screen import (
    ALLOCATION,
    noise_condition,
    projected_distribution_budget,
    resource_projection,
    select_group,
)


SCHEMA = "CHKP-PUBLISHED-ROM-PARAMETER-TARGET/1"
PROFILE_ID = "chkp-published-rom-mp12-computational-n6144-v1"
TARGET_N = 6144
DEPTH = 2
SEED_BITS = 256
PUBLISHED_PDF_SHA256 = "87b5bff448f4e653bb7959a62c2b56c03ca495076678014b5dc8b7c90a90442f"
AUTHOR_MANUSCRIPT_SHA256 = "b1d8a2ae0e9d4e5c9145bbc6dc864090605c12a5b76149aa0684d62a8815d2ce"
MP12_PDF_SHA256 = "bf1160f088825ed28c343b299f5bc2acdca41cc50293310a03a4506d2fdbdb84"


def _dyadic_exponent(value):
    value = Fraction(value)
    if not 0 < value <= 1:
        raise ValueError("probability bound must be in (0,1]")
    return (value.denominator // value.numerator).bit_length() - 1


def _paper_layout(group):
    m = group["m"]
    return dict(
        identity_depth=DEPTH,
        root_columns=m,
        receiver_key_columns=m,
        leaf_recipient_columns=2 * m,
        used_leaf_preamble_columns=2 * m,
        conservative_anonymous_uniform_padding_columns=m,
        transmitted_preamble_columns=3 * m,
        terminal_syndromes=SEED_BITS,
        h_addresses=["H(receiver)"],
        g_addresses="G(receiver,sender,bit-position)",
        source=("CHKP EUROCRYPT 2010 proceedings section 5.3/Theorem 5.3 for the 2m "
                "depth-two ROHIBE leaf; section 5.2's BTE padding observation and the "
                "later manuscript's GENHIBE padding observation for conservative 3m wire padding"),
        padding_is_separate_from_Theorem_5_3=True,
        published_Theorem_5_3_is_adaptive_identity_not_anonymity=True,
    )


def _formal_finite_budget(group, finite):
    """Add proof-simulator and anonymous-wire terms to the service budget.

    This is still a projection: the exact CHKP/MP12 replacement proof and the
    constant hidden by CHKP Lemma 2.4(4) are not supplied here.  In particular,
    the ideal G-image term below is an explicitly labelled allocation, not a
    claim that the paper's asymptotic ``negl(n)`` has been instantiated.
    """
    terms = {key: Fraction(value) for key, value in finite["terms"].items()}
    controlled_roots = DEPTH * ALLOCATION["H_queries"]
    simulation = {
        "controlled_H_root_uniform_abort": controlled_roots * terms["root_uniform_abort"],
        "controlled_H_root_scalar_coupling": controlled_roots * terms["root_scalar_coupling"],
        "controlled_H_root_norm_abort": controlled_roots * terms["ideal_root_norm_abort"],
    }
    # The multi-bit transform uses a separate G syndrome for every bit.  The
    # proof simulator samples one spherical integer-Gaussian preimage for each
    # non-challenge G response; use the maximum 2m dimension for every query.
    scalar_tv = Fraction(finite["phases"]["leaf"]["scalar"]["tv_upper_including_abort"])
    simulated_G_vectors = ALLOCATION["G_paths"] * SEED_BITS
    simulation["controlled_G_finite_scalar_coupling"] = (
        simulated_G_vectors * 2 * group["m"] * scalar_tv
    )
    # This is the allocation intended for the exact smoothing/uniform-image
    # lemma mapping that remains open.  It is included in the arithmetic total
    # but cannot close the proof gate by itself.
    simulation["controlled_G_ideal_image_uniformity_allocation"] = (
        simulated_G_vectors * Fraction(1, 2**ALLOCATION["epsilon_bits"])
    )
    anonymous_wire = {
        "anonymous_padding_uniform_abort": (
            ALLOCATION["encapsulations"] * group["m"]
            * Fraction(1, 2**ALLOCATION["ciphertext_uniform_trials"])
        ),
    }
    total = min(Fraction(1), sum(terms.values(), Fraction(0))
                + sum(simulation.values(), Fraction(0))
                + sum(anonymous_wire.values(), Fraction(0)))
    bounded_simulation = {key: min(Fraction(1), value) for key, value in simulation.items()}
    bounded_anonymous = {key: min(Fraction(1), value) for key, value in anonymous_wire.items()}
    return dict(
        deployed_service_terms={key: str(value) for key, value in terms.items()},
        proof_simulator_terms={key: str(value) for key, value in bounded_simulation.items()},
        proof_simulator_term_dyadic_exponents={
            key: _dyadic_exponent(value) for key, value in bounded_simulation.items()
        },
        anonymous_wire_terms={key: str(value) for key, value in bounded_anonymous.items()},
        anonymous_wire_term_dyadic_exponents={
            key: _dyadic_exponent(value) for key, value in bounded_anonymous.items()
        },
        proof_simulator_controlled_H_roots=controlled_roots,
        proof_simulator_controlled_G_vectors=simulated_G_vectors,
        proof_simulator_controlled_G_scalar_draws=simulated_G_vectors * 2 * group["m"],
        root_terms_already_count_one_deployed_master=True,
        full_ROM_finite_TV_or_failure_upper=str(total),
        probability_dyadic_exponent=_dyadic_exponent(total),
        target_128_met=total <= Fraction(1, 2**128),
        source_service_projection_exponent=finite["probability_dyadic_exponent"],
        exact_CHKP_Lemma_2_4_4_constant_mapped=False,
        full_proof_finite_bound_admitted=False,
    )


def _loss_ledger(group):
    qh, qg = ALLOCATION["H_queries"], ALLOCATION["G_paths"]
    rom = DEPTH * qh ** (DEPTH - 1) * qg
    root_instances = (1 + DEPTH * qh) * group["w"]
    cipher = rom * SEED_BITS
    anonymous_cipher = 2 * cipher
    return dict(
        H_queries=qh,
        G_queries=qg,
        depth=DEPTH,
        CHKP_Theorem_5_3_factor=rom,
        CHKP_Theorem_5_3_log2=log2(rom),
        multibit_hybrid_factor=SEED_BITS,
        multibit_hybrid_log2=log2(SEED_BITS),
        ciphertext_LWE_total_factor=cipher,
        ciphertext_LWE_total_log2=log2(cipher),
        cross_depth_anonymity_two_endpoint_factor=2,
        cross_depth_anonymity_total_factor=anonymous_cipher,
        cross_depth_anonymity_total_log2=log2(anonymous_cipher),
        MP12_columns_per_computational_root=group["w"],
        computational_roots_in_master_and_controlled_H_simulation=1 + DEPTH * qh,
        root_LWE_total_factor=root_instances,
        root_LWE_total_log2=log2(root_instances),
        root_and_ciphertext_losses_are_separate_hybrids_not_summed=True,
    )


def build_target(n=TARGET_N):
    """Build public scalars only; no matrix, key, sample, or entropy read."""
    if type(n) is not int or not 2 <= n <= 16384:
        raise ValueError("formal target n requires an exact bounded integer")

    # select_group proves a prime sufficient even for the larger unadmitted 3m
    # used-leaf recipe.  Reusing it for the published 2m leaf is conservative,
    # and avoids claiming a separately optimized modulus.
    selected = select_group(n)
    conservative_leaf = selected["leaf_dimension"]
    group = dict(selected)
    group["leaf_dimension"] = 2 * group["m"]
    group["noise"] = noise_condition(
        group["q"], group["leaf_dimension"], group["leaf_width_squared"],
        group["q_alpha"], error_bits=ALLOCATION["decode_error_bits"],
    )
    finite = projected_distribution_budget(group)
    formal_finite = _formal_finite_budget(group, finite)
    resources = resource_projection(group)
    word = (group["q_bits"] + 7) // 8
    layout = _paper_layout(group)
    resources["codec_minimum_bytes"]["anonymous_capsule_residue_bytes"] = (
        layout["transmitted_preamble_columns"] + SEED_BITS
    ) * word
    resources["current_gates"]["anonymous_capsule_not_excluded_by_4MiB"] = (
        resources["codec_minimum_bytes"]["anonymous_capsule_residue_bytes"] <= 4 * 2**20
    )

    root_width = group["root_r_squared"]
    cipher_width = group["q_alpha"] ** 2
    ciphertext_samples = layout["used_leaf_preamble_columns"] - n + SEED_BITS
    losses = _loss_ledger(group)
    numeric_gates = dict(
        selected_modulus_is_proven_prime=group["q_prime_proved"] is True,
        published_depth_two_layout=layout["used_leaf_preamble_columns"] == 2 * group["m"],
        root_LWE_width_strictly_above_2sqrt_n=root_width > 4 * n,
        ciphertext_LWE_width_strictly_above_2sqrt_n=cipher_width > 4 * n,
        conditional_noisy_decode=group["noise"]["conditional_noise_sufficient"] is True,
        projected_finite_ROM_budget_128=formal_finite["target_128_met"] is True,
        exact_identity_and_seed_capacity=ALLOCATION["identity_bytes"] == 86 and ALLOCATION["seed_bytes"] == 32,
    )
    numeric_complete = all(numeric_gates.values())
    proof_mapping_gates = dict(
        published_layout_implemented=False,
        CHKP_RandBasis_or_equivalent_secret_key_distribution_proved=False,
        exact_CHKP_Lemma_2_4_4_constant_mapped=False,
        literal_rounded_noise_reduction_mapped=False,
        complete_concrete_attack_coverage=False,
        current_resource_and_wire_gates_pass=False,
    )
    return dict(
        schema=SCHEMA,
        profile_id=PROFILE_ID if n == TARGET_N else f"chkp-published-rom-mp12-computational-n{n}-projection",
        paper_numeric_target_complete=numeric_complete,
        paper_parameter_set_formal=False,
        parameters_are_formal=False,
        formal_scope="fully specified paper-layout numeric candidate; formal security mapping remains open",
        security_model="classical programmable random-oracle model",
        theorem_statement=("CHKP Theorem 5.3 gives adaptive-identity IND-CPA KEM security; "
                           "cross-depth anonymity uses a separate LWE-pseudorandom padding argument"),
        NIST_level_claimed=None,
        concrete_security_bits_claimed=None,
        security_claim="none",
        backend_admitted=False,
        current_backend_implementation_matches=False,
        current_backend_mismatch="installed mp12-structured-hg uses the later manuscript's 3m H/G leaf instead of the proceedings 2m leaf plus uniform anonymity padding",
        current_HIBE_recipe_implemented=False,
        actual_full_HIBE_execution=False,
        root_or_key_generations=0,
        sampler_calls=0,
        entropy_reads=0,
        sources=dict(
            CHKP_published_url="https://people.cs.rutgers.edu/~dc789/bonsai.pdf",
            CHKP_published_sha256=PUBLISHED_PDF_SHA256,
            CHKP_author_manuscript_local="papers/2010_bonsai_trees_cash.pdf",
            CHKP_author_manuscript_sha256=AUTHOR_MANUSCRIPT_SHA256,
            MP12_local="papers/2011_lattice_trapdoors_micciancio.pdf",
            MP12_sha256=MP12_PDF_SHA256,
            mapping=[
                "CHKP proceedings section 5.3 and Theorem 5.3",
                "CHKP proceedings section 5.2 anonymity padding",
                "CHKP KEM Lemma 5.1 and 256-bit hybrid",
                "MP12 section 5.2 computational GenTrap",
                "MP12 Algorithms 3/4, Theorem 5.5 and Lemma 5.7",
            ],
        ),
        allocation=dict(ALLOCATION),
        layout=layout,
        complete_group=group,
        conservative_modulus_selection=dict(
            selected_against_unadmitted_used_leaf_columns=conservative_leaf,
            published_used_leaf_columns=group["leaf_dimension"],
            minimal_for_published_layout_not_claimed=True,
        ),
        numeric_parameter_gates=numeric_gates,
        proof_mapping_gates=proof_mapping_gates,
        proof_mapping_complete=False,
        finite_projection=finite,
        formal_finite_budget=formal_finite,
        reduction_loss_ledger=losses,
        root_lwe=dict(
            n=n, q=group["q"], m=n, secret="small-Gaussian", squared_width=root_width,
            distribution="finite discrete Gaussian; estimator comparator uses ideal discrete Gaussian",
            independent_columns=group["w"], multi_target_factor_applied=losses["root_LWE_total_factor"],
            attack_goal="distinguish one normal-form MP12 root column; hybrid covers all roots/columns",
        ),
        ciphertext_lwe=dict(
            n=n, q=group["q"], m=ciphertext_samples, secret="small-Gaussian",
            squared_width=cipher_width,
            distribution="literal finite rounded-continuous Gaussian; estimator discrete-Gaussian comparator only",
            estimator_distribution_is_literal=False,
            equation="for every non-identity used column j: c_j-a_j^T*c_I=a_j^T*(-e_I)+e_j mod q",
            used_preamble_samples=layout["used_leaf_preamble_columns"] - n,
            known_terminal_samples=SEED_BITS,
            anonymous_padding_used_as_samples=False,
            adaptive_identity_reduction_factor_applied=losses["ciphertext_LWE_total_factor"],
            cross_depth_anonymity_reduction_factor_applied=losses["cross_depth_anonymity_total_factor"],
        ),
        resources=resources,
        estimator_results={},
        estimator_coverage=dict(
            completed=False,
            included_attacks=["primal_usvp", "primal_bdd", "dual", "dual_hybrid"],
            unresolved_attacks=["coded_bkw", "arora_gb", "algebraic/structural attacks"],
            literal_rounded_noise_modeled=False,
            complete_concrete_attack_coverage=False,
        ),
        measured_lattice_families_target_met=None,
        concrete_128bit_claim_admitted=False,
    )


def run_estimators(target, estimator_path):
    from experiments.research.luo_parameter_screen import verify_estimator_checkout

    root, revision = verify_estimator_checkout(Path(estimator_path))
    sys.path.insert(0, str(root))
    import estimator
    from estimator import LWE, ND
    from estimator.reduction import ADPS16
    from sage.all import RR, log, oo, pi

    if not Path(estimator.__file__).resolve().is_relative_to(root):
        raise ValueError("foreign estimator import")
    attacks = {
        "primal_usvp": lambda p, model: LWE.primal_usvp(p, red_cost_model=model, red_shape_model="lgsa"),
        "primal_bdd": lambda p, model: LWE.primal_bdd(p, red_cost_model=model, red_shape_model="lgsa"),
        "dual": lambda p, model: LWE.dual(p, red_cost_model=model),
        "dual_hybrid": lambda p, model: LWE.dual_hybrid(p, red_cost_model=model),
    }
    for role_name in ("root_lwe", "ciphertext_lwe"):
        role = target[role_name]
        sigma = RR(role["squared_width"]).sqrt() / (2 * pi).sqrt()
        params = LWE.Parameters(n=role["n"], q=role["q"], m=role["m"],
            Xs=ND.DiscreteGaussian(sigma), Xe=ND.DiscreteGaussian(sigma),
            tag=f"{target['profile_id']}:{role_name}")
        role_results = target["estimator_results"].setdefault(role_name, {})
        for mode in ("classical", "quantum"):
            model = ADPS16(mode=mode)
            for name, attack in attacks.items():
                key = f"{name}-{mode}"
                try:
                    cost = attack(params, model)
                    finite = cost["rop"] != oo
                    role_results[key] = dict(
                        status="finite_heuristic_estimate" if finite else "no_finite_estimate",
                        rop_log2=None if not finite else float(log(cost["rop"], 2)),
                        cost_fields={k: str(v) for k, v in cost.items() if k != "problem"},
                    )
                except Exception as exc:
                    role_results[key] = dict(status="error", rop_log2=None,
                        exception_type=type(exc).__name__, error=str(exc))

    losses = target["reduction_loss_ledger"]
    adjusted = {}
    for role_name, loss_name in (("root_lwe", "root_LWE_total_log2"),
            ("ciphertext_lwe", "cross_depth_anonymity_total_log2")):
        finite = [entry["rop_log2"] for entry in target["estimator_results"][role_name].values()
                  if entry["status"] == "finite_heuristic_estimate"]
        adjusted[role_name] = None if not finite else min(finite) - losses[loss_name]
    target["estimator"] = dict(
        repository="https://github.com/malb/lattice-estimator",
        commit=revision,
        models="ADPS16 classical/quantum Core-SVP; primal LGSA",
        completed_declared_subset=True,
        comparator_only=True,
    )
    target["estimator_coverage"]["completed"] = True
    target["loss_adjusted_measured_costs"] = adjusted
    target["measured_lattice_families_target_met"] = all(
        value is not None and value >= ALLOCATION["target_lifetime_bits"] for value in adjusted.values()
    )
    # Deliberately remains false: the literal distribution and the unresolved
    # attack families prevent a concrete-bit admission.
    target["concrete_128bit_claim_admitted"] = False
    return target


def build_report(n=TARGET_N, estimator_path=None):
    target = build_target(n)
    if estimator_path is not None:
        run_estimators(target, estimator_path)
    sources = [
        "experiments/research/chkp_published_formal_screen.py",
        "experiments/research/structured_target_screen.py",
        "src/ibme/lattice/matrix_sampling/mp12_structured.py",
        "src/ibme/lattice/matrix_sampling/mp12_extension.py",
    ]
    repository = Path(__file__).resolve().parents[2]
    return dict(
        schema=SCHEMA,
        status="completed_paper_target_non_admission",
        target=target,
        environment=dict(python=sys.version.split()[0], platform=platform.platform()),
        source_sha256={name: hashlib.sha256((repository / name).read_bytes()).hexdigest() for name in sources},
        security_claim="none",
        backend_admitted=False,
        paper_numeric_target_complete=target["paper_numeric_target_complete"],
        paper_parameter_set_formal=False,
        current_backend_parameters_are_formal=False,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dimension", type=int, default=TARGET_N)
    parser.add_argument("--estimator-path", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write('{"status":"started"}\n')
    report = build_report(args.dimension, args.estimator_path)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(dict(
        profile=report["target"]["profile_id"],
        paper_numeric_target_complete=report["paper_numeric_target_complete"],
        paper_parameter_set_formal=False,
        q=report["target"]["complete_group"]["q"],
        finite_exponent=report["target"]["formal_finite_budget"]["probability_dyadic_exponent"],
        backend_admitted=False,
    )))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
