"""Exact, allocation-free CHKP research capacity and refusal certificates.

The comparison holds q, root R width, root statistical target, and finite
sampler settings fixed. It does not identify security levels with n, certify
hard LWE instances, or prove that other CHKP implementations are impossible.
No matrices, keys, random bytes or large tapes are constructed.
"""

from dataclasses import asdict
from fractions import Fraction
import json
from math import isqrt

from experiments.research.chkp_parameter_profile import (
    check_profile, selected_profile,
)
from experiments.research.ibme_joint_parameters import evaluate_noise, smoothing_factor
from ibme.core.errors import InvalidParameterError
from ibme.hibe.chkp.params import CHKPParams, ciphertext_size, research_params


def minimum_entropy_columns(n, q, *, mass_floor=31, regularity_bits=64):
    """Smallest mbar for (nk)^2 q^n / mass_floor^mbar <= 2^-2b."""
    if (type(n) is not int or not 1 <= n <= 128
            or type(q) is not int or not 2 <= q < 2**61
            or type(mass_floor) is not int or not 2 <= mass_floor < q
            or type(regularity_bits) is not int or not 8 <= regularity_bits <= 192):
        raise ValueError("bounded exact comparison parameters required")
    k = (q-1).bit_length()
    target = (n*k)**2 * q**n * 2**(2*regularity_bits)
    low, high = 0, 1
    while mass_floor**high < target:
        high *= 2
    while high-low > 1:
        mid = (low+high)//2
        if mass_floor**mid >= target:
            high = mid
        else:
            low = mid
    return high


def _regularity_upper(n, q, mbar, mass_floor, bits=192):
    value = Fraction((n*(q-1).bit_length())**2 * q**n, mass_floor**mbar)
    scaled = value * 2**(2*bits)
    ceil_scaled = (scaled.numerator+scaled.denominator-1)//scaled.denominator
    root = isqrt(ceil_scaled)
    if root*root < ceil_scaled:
        root += 1
    return Fraction(root, 2**bits)


def projection(n):
    """A public dimension/representation calculation, never key generation."""
    base = selected_profile()
    p = research_params()
    q, k = base["q"], base["k"]
    mass, regularity = 31, 64
    mb = minimum_entropy_columns(n, q, mass_floor=mass, regularity_bits=regularity)
    root, parent, leaf = mb+n*k, 2*(mb+n*k), 3*(mb+n*k)
    root_bound = 10*(1+mb*n*k*base["root_radius"]**2)
    s1 = 4*root_bound*smoothing_factor(parent, base["epsilon_bits"])
    s2 = 4*s1*parent*smoothing_factor(leaf, base["epsilon_bits"])
    max_vectors = parent+128
    seed_bits = 8*32
    noise = evaluate_noise(q=q, dimension=leaf, width_squared=s2,
                           alpha=Fraction(4, q), error_bits=64,
                           seed_bits=seed_bits, encapsulations=2**20)
    # Sign byte + four-byte length + at least one magnitude byte. Headers,
    # public context, Python/Sage objects, RSS and temporary matrices excluded.
    lower = dict(root_basis=6*root*root, parent_basis=6*parent*parent,
                 leaf_preimages=6*leaf*seed_bits)
    refusals = []
    if n > 64:
        refusals.append("CHKPParams.n exceeds current maximum 64")
    if leaf > p.max_dimension:
        refusals.append("full leaf dimension exceeds explicit maximum 512")
    if root > 1024:
        refusals.append("MP12 root full-basis dimension exceeds maximum 1024")
    if max_vectors > 4096:
        refusals.append("RandBasis total candidate bound exceeds maximum 4096")
    if parent*parent > 2**20:
        refusals.append("parent complete-basis entries exceed private-state maximum 2^20")
    for name, size in lower.items():
        if size > 16*2**20:
            refusals.append(f"{name} integer bytes alone exceed private object maximum 16 MiB")
    values = asdict(p)
    values.update(n=n, m_bar=mb, root_gs_squared_bound=root_bound,
                  parent_width_squared=s1, leaf_width_squared=s2,
                  parent_max_vectors=max_vectors)
    try:
        CHKPParams(**values)
    except InvalidParameterError as exc:
        accepted, reason = False, str(exc)
    else:
        accepted, reason = True, None
    scalar_ceiling = check_profile(base)["worst_entropy_bytes"]["scalar"]
    counts = dict(root_gaussian_coordinates=mb*n*k,
                  parent_gaussian_coordinates_upper=max_vectors*parent,
                  leaf_gaussian_coordinates=seed_bits*leaf,
                  parent_candidates_minimum=parent,
                  parent_candidates_limit=max_vectors,
                  leaf_vector_samples=seed_bits)
    envelope = dict(root=counts["root_gaussian_coordinates"]*scalar_ceiling+n*mb*192*((k+7)//8),
                    parent=counts["parent_gaussian_coordinates_upper"]*scalar_ceiling,
                    leaf=counts["leaf_gaussian_coordinates"]*scalar_ceiling)
    return dict(n=n, q=q, k=k, m_bar=mb, root_r_width_squared=base["r_width_squared"],
        actual_finite_mass_floor=mass, root_regularity_target_bits=regularity,
        root_regularity_upper_conditional=str(_regularity_upper(n,q,mb,mass)),
        entropy_column_minimality={
            "sufficient": mass**mb >= (n*k)**2*q**n*2**128,
            "previous_column_count_fails": mass**(mb-1) < (n*k)**2*q**n*2**128},
        dimensions=dict(root=root,parent=parent,leaf=leaf),
        public_widths=dict(root_gs_squared_bound=root_bound,
                           parent_width_squared=s1, leaf_width_squared=s2),
        seed_bytes=32, seed_positions=seed_bits,
        scalar_call_counts=counts,
        private_integer_wire_lower_bytes=lower,
        private_wire_lower_bound_is_not_RSS_or_full_serialized_size=True,
        current_params_constructor_accepts=accepted,
        constructor_rejection=reason,
        resource_status="blocked" if refusals else "static_caps_fit",
        resource_refusal_reasons=refusals,
        conditional_noise=noise,
        fixed_noise_width_4_satisfies_2sqrt_n=16 >= 4*n,
        public_entropy_envelope_bytes=envelope,
        entropy_envelope_is_not_measured_use_or_a_lower_bound=True,
        envelope_within_stage_budgets=dict(root=envelope["root"]<=base["root_entropy_budget"],
            parent=envelope["parent"]<=base["parent_entropy_budget"],
            leaf=envelope["leaf"]<=base["leaf_entropy_budget"]),
        actual_geometry_or_sampling_executed=False,
        security_claim="none", backend_admitted=False,
        parameters_are_formal=False, n_does_not_name_security_bits=True)


def audit():
    p, profile = research_params(), selected_profile()
    checks = check_profile(profile)
    for key in ("n", "q", "m_bar", "r_width_squared", "root_gs_squared_bound",
                "parent_width_squared", "leaf_width_squared", "epsilon_bits",
                "regularity_bits", "parent_max_vectors", "max_dimension"):
        if getattr(p, key) != profile[key]:
            raise ValueError(f"runtime and independent profile disagree: {key}")
    rows = [projection(n) for n in (2, 16, 64, 128)]
    return dict(schema="IBME/CHKP-CAPACITY-AUDIT/1", profile_id=profile["profile_id"],
        scope="one root, one parent issuance, one fixed 32-byte/256-position leaf",
        current=dict(dimensions=[p.m, 2*p.m, p.leaf_dimension],
                     seed_mode_plaintext_bytes=p.max_message_bytes,
                     framed_mode_plaintext_bytes=research_params(message_mode="framed32").max_message_bytes,
                     framed_length_prefix_bytes=4,
                     seed_positions=256, encoded_identity_limit_bytes=p.identity_bytes,
                     raw_seed_capsule_bytes=ciphertext_size(p,32),
                     raw_cpa_all_byte_integrity_claim=False,
                     static_profile_checks=checks),
        comparison=dict(q=p.q, root_r_width_squared=p.r_width_squared,
            conservative_actual_finite_mass_floor=31, regularity_bits=64,
            epsilon_bits=128, fixed_noise_width=4,
            floor_verified_by="chkp_parameter_profile --finite verifies actual mass >= 31.9 > 31",
            dimensions_compared=[2,16,64,128], rows=rows),
        remaining_for_formal_admission=[
            "a simultaneously correct and computationally hard LWE parameter set",
            "measured generation/sampling and bounded resource gates for that same set",
            "finite root, delegation, leaf, noise and implementation-failure ledgers",
            "paper/Wang composition assumptions and query-dependent reduction losses",
            "independent estimation beyond one attack or a dimension label"],
        boundaries=["static research gates do not imply actual sampling completion",
                    "larger n is not automatically a corresponding security level",
                    "refusal concerns this implementation/profile, not all CHKP constructions",
                    "wire minima are integer payload lower bounds; entropy ceilings are upper bounds",
                    "published n=2 low-cost recovery attacks are not repaired by statistical accuracy"],
        random_bytes_consumed=0, large_matrices_allocated=False,
        security_claim="none", backend_admitted=False, parameters_are_formal=False)


def main():
    print(json.dumps(audit(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
