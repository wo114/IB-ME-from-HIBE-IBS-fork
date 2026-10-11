"""Frozen n=2 CHKP research parameters, with exact public admission checks.

MP12 statistical GenTrap/complete-basis conversion is followed by CHKP's
ExtBasis/RandBasis and terminal GPV SampleD. This is not MP12 DelTrap.
The small LWE dimension is deliberately NOT a security parameter. Public
arithmetic checks never certify actual secret-basis geometry or execution.
"""

from copy import deepcopy
from fractions import Fraction
from math import isqrt


PROFILE_ID = "chkp-mp12-root-randbasis-n2-v1"
SCHEMA = "IBME/CHKP-RESEARCH-PARAMETERS/1"


def _ceil_sqrt(value):
    value = Fraction(value)
    root = isqrt(value.numerator // value.denominator)
    return root + int(root * root < value)


def _upward_sqrt(value, bits=192):
    return Fraction(_ceil_sqrt(Fraction(value) * 2 ** (2 * bits)), 2**bits)


def _smoothing(dimension, epsilon_bits):
    return (2 * dimension * (1 + 2**epsilon_bits) - 1).bit_length()


def selected_profile():
    """Return an independent copy; no entropy, Sage, files or key generation."""
    n, q, m_bar, width = 2, 1099511627791, 45, 1024
    k = (q - 1).bit_length()
    root, radius, eps = m_bar + n * k, 171, 128
    parent, leaf = 2 * root, 3 * root
    root_bound = 10 * (1 + m_bar * n * k * radius**2)
    s1 = 4 * root_bound * _smoothing(parent, eps)
    s2 = 4 * s1 * parent * _smoothing(leaf, eps)
    options = dict(tail_bits=128, mass_bits=256, precision_bits=320,
                   gaussian_abort_bits=128, max_uniform_trials=192,
                   max_gaussian_trials=2048, max_radius=2**48,
                   rational_bits=8192, max_tape_bytes=2**40)
    profile = dict(schema=SCHEMA, profile_id=PROFILE_ID,
        algorithm="MP12-statistical-root / CHKP-RandBasis / GPV-leaf",
        n=n, q=q, m_bar=m_bar, r_width_squared=width, k=k,
        root_dimension=root, parent_dimension=parent, leaf_dimension=leaf,
        regularity_bits=64, root_mass_lower="319/10", root_radius=radius,
        root_gs_squared_bound=root_bound, parent_width_squared=s1,
        parent_gs_squared_bound=s1 * parent, leaf_width_squared=s2,
        epsilon_bits=eps, parent_max_vectors=parent + 128,
        alpha_numerator=4, alpha_denominator=q,
        error_bits=64, seed_bits=256, encapsulation_budget=2**20,
        identity_encoded_bytes=86, finite_options=options,
        max_dimension=512, max_private_bytes=16 * 2**20,
        root_entropy_budget=2**34, parent_entropy_budget=2**39,
        leaf_entropy_budget=2**39, chain_entropy_budget=2**40,
        security_claim="none", backend_admitted=False,
        parameters_are_formal=False,
        geometry_and_sampling_executed=False)
    return deepcopy(profile)


def root_parameters(profile=None):
    """Only constructor fields; declaration flags are never passed as kwargs."""
    p = selected_profile() if profile is None else profile
    check_profile(p)
    return {name: p[name] for name in
            ("n", "q", "m_bar", "r_width_squared", "regularity_bits")} | {
                "uniform_trials": p["finite_options"]["max_uniform_trials"],
                "max_entropy_bytes": p["root_entropy_budget"]}


def check_profile(profile):
    """Independently recompute the frozen profile's integer/rational gates.

    Strict equality pins a single research configuration. A changed profile
    needs a new identifier and checker, not implicit fallback or admission.
    """
    from experiments.research.chkp_paper_preflight import _is_prime

    p = profile
    expected = selected_profile()
    if type(p) is not dict or set(p) != set(expected):
        raise ValueError("unknown or incomplete CHKP research profile")
    for name, value in expected.items():
        actual = p[name]
        if type(actual) is not type(value) or actual != value:
            raise ValueError(f"CHKP research profile field mismatch: {name}")
    # Dict equality alone accepts True == 1. Check nested options explicitly.
    opts = p["finite_options"]
    if any(type(value) is not int for value in opts.values()):
        raise ValueError("finite options must be exact integers")
    n, q, mb = p["n"], p["q"], p["m_bar"]
    if not _is_prime(q):
        raise ValueError("CHKP modulus is not prime")
    k, m = (q - 1).bit_length(), mb + n * (q - 1).bit_length()
    if (p["k"], p["root_dimension"], p["parent_dimension"], p["leaf_dimension"]) != (k, m, 2*m, 3*m):
        raise ValueError("root and extension dimensions disagree")
    if 2 * p["root_radius"] >= q:
        raise ValueError("finite root support is not injective modulo q")
    mass = Fraction(p["root_mass_lower"])
    regularity_squared = (n * k)**2 * Fraction(q**n, 1) / mass**mb
    if regularity_squared > Fraction(1, 2**(2*p["regularity_bits"])):
        raise ValueError("actual finite root mass floor is insufficient")
    root_bound = 10 * (1 + mb * n * k * p["root_radius"]**2)
    s1 = 4 * root_bound * _smoothing(2*m, p["epsilon_bits"])
    s2 = 4 * s1 * 2*m * _smoothing(3*m, p["epsilon_bits"])
    if (root_bound, s1, s1*2*m, s2) != tuple(p[name] for name in
            ("root_gs_squared_bound", "parent_width_squared",
             "parent_gs_squared_bound", "leaf_width_squared")):
        raise ValueError("public Gram-Schmidt width propagation mismatch")
    dim, norm2 = 3*m, s2*3*m
    l1 = _ceil_sqrt(dim * norm2)
    rounding = Fraction(l1 + 1, 2)
    phase_radius = (q // 2 - 1) // 2
    margin = phase_radius - rounding
    continuous2 = p["alpha_numerator"]**2 * (norm2+1) * (p["error_bits"]+1)
    if margin <= 0 or continuous2 > margin**2:
        raise ValueError("conditional rounded-noise decode budget does not hold")
    if p["alpha_numerator"]**2 < 4*n:
        raise ValueError("noise width fails the selected 2 sqrt(n) comparison")
    # Resource ceilings, not expected entropy use and not memory allocation.
    support_upper = 2 * opts["max_radius"] + 2
    candidate_bytes = ((support_upper-1).bit_length()+7)//8
    scalar_bytes = opts["max_gaussian_trials"] * (
        opts["max_uniform_trials"] * candidate_bytes + (opts["mass_bits"]+7)//8)
    root_gaussians = mb * n * k
    root_uniform_bytes = n * mb * opts["max_uniform_trials"] * ((k+7)//8)
    root_bytes = root_gaussians * scalar_bytes + root_uniform_bytes
    parent_gaussians = p["parent_max_vectors"] * 2*m
    leaf_gaussians = p["seed_bits"] * 3*m
    parent_bytes, leaf_bytes = parent_gaussians*scalar_bytes, leaf_gaussians*scalar_bytes
    total = root_bytes + parent_bytes + leaf_bytes
    if not (root_bytes <= p["root_entropy_budget"]
            and parent_bytes <= p["parent_entropy_budget"]
            and leaf_bytes <= p["leaf_entropy_budget"]
            and total <= p["chain_entropy_budget"]
            and 3*m <= p["max_dimension"]):
        raise ValueError("public worst-case entropy or dimension ceiling exceeded")
    return dict(profile_id=PROFILE_ID, static_numeric_gates_pass=True,
        root_regularity_upper_conditional=str(_upward_sqrt(regularity_squared)),
        root_mass_floor_requires_finite_sampler_check=True,
        root_mass_floor=str(mass), root_radius=p["root_radius"],
        selected_modulus_sufficient=q*q >= 16*s2*(3*m+1)**2,
        conditional_noise_sufficient=True,
        conditional_preimage_norm_squared_upper=norm2,
        conditional_rounding_error_upper=str(rounding),
        conditional_continuous_margin=str(margin),
        conditional_continuous_squared_upper=continuous2,
        conditional_per_bit_error_upper=str(Fraction(1, 2**p["error_bits"])),
        conditional_lifetime_error_upper=str(Fraction(
            p["seed_bits"]*p["encapsulation_budget"], 2**p["error_bits"])),
        worst_entropy_bytes=dict(scalar=scalar_bytes, root=root_bytes,
            parent=parent_bytes, leaf=leaf_bytes, chain=total),
        scalar_call_limits=dict(root=root_gaussians, parent=parent_gaussians,
                                leaf=leaf_gaussians),
        budgets_are_not_preallocated_memory=True,
        actual_geometry_or_sampling_checked=False,
        pending_execution_checks=["finite root mass and radius",
            "complete private kernel bases and public GS bound",
            "GPV scalar widths, rational centers and resource envelopes",
            "RandBasis rank/norm/ToBasis and checked reduction",
            "fixed 256 leaf syndromes and actual preimage norms",
            "measured entropy and persistence lifecycle"],
        security_claim="none", backend_admitted=False,
        parameters_are_formal=False,
        n2_is_not_a_security_parameter=True)


def check_finite_profile():
    """Sage-only finite scalar checks, without drawing any random bytes.

    The tested widths are boundaries and public schedule values. They are
    not a substitute for checking each actual private basis's scalar widths.
    """
    from sage.all import QQ
    from experiments.research.first_suite.finite_gaussian import (
        FirstFiniteGaussian, FirstFiniteOptions,
    )
    from experiments.research.first_suite.root_generation import (
        MP12RootGenerator, MP12RootParams,
    )

    p = selected_profile()
    public = check_profile(p)
    options = FirstFiniteOptions(**p["finite_options"])
    # Construction checks public distributions only. The binary is neither
    # inspected nor executed until generate(), which this function never calls.
    generator = MP12RootGenerator(MP12RootParams(**root_parameters()),
                                  "unused-no-root-generation", options=options)
    if (generator.scalar.radius != p["root_radius"]
            or generator.scalar.acceptance_mass_lower < QQ(p["root_mass_lower"])
            or generator.worst_entropy > p["root_entropy_budget"]):
        raise ValueError("frozen public finite root certificate no longer holds")
    rows = []
    for width in (1, 2, 4, p["r_width_squared"], p["parent_width_squared"],
                  p["leaf_width_squared"], 2**80):
        scalar = FirstFiniteGaussian(width, width, options=options)
        if scalar.random_tape_bytes > public["worst_entropy_bytes"]["scalar"]:
            raise ValueError("finite scalar exceeds public worst entropy envelope")
        rows.append(dict(width_squared=width, gaussian_trials=scalar.gaussian_trials,
                         radius=scalar.radius, worst_entropy_bytes=scalar.random_tape_bytes,
                         tv_upper_including_abort=str(scalar.tv_upper)))
    return dict(root_radius=generator.scalar.radius, root_mass_floor_pass=True,
                actual_root_mass_lower=str(generator.scalar.acceptance_mass_lower),
                root_regularity_upper_conditional=str(generator.regularity),
                root_profile_worst_entropy_bytes=generator.worst_entropy,
                scalar_profiles=rows, actual_geometry_or_sampling_checked=False,
                random_bytes_consumed=0, root_generated=False,
                security_claim="none", backend_admitted=False,
                parameters_are_formal=False)


def main():
    import argparse
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--finite", action="store_true", help="also run Sage finite scalar preflight")
    args = parser.parse_args()
    report = dict(profile=selected_profile(), checks=check_profile(selected_profile()))
    if args.finite:
        report["finite"] = check_finite_profile()
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
