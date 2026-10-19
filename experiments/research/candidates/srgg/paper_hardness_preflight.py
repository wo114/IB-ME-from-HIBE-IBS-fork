"""Original Table 4 CRT/ring-HNF algebra and finite-resource preflight.

This does not invoke a coefficient-LWE surrogate or estimate attack costs.
It keeps the actual planted/seeded public law distinct from ideal uniform
ring matrices. Only public arithmetic is used: no keys, samplers, attacks,
external services or changed cryptographic parameters.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
from hashlib import sha256
import json
from math import gcd
from pathlib import Path
import platform

from .crt_projection import projection_certificate
from .paper_profiles import SOURCE_PDF, SOURCE_SHA256, profiles


SCHEMA = "IBME/SRGG-PAPER-CRT-HNF-PREFLIGHT/1"
ROOT = Path(__file__).resolve().parents[4]
MAX_MODULUS = 2**32
MAX_DEGREE = 512
MAX_ENUMERATION_STATES = 2**20
SOURCES = (
    "experiments/research/candidates/srgg/paper_hardness_preflight.py",
    "experiments/research/candidates/srgg/paper_profiles.py",
    "experiments/research/candidates/srgg/paper_algebra.py",
    "experiments/research/candidates/srgg/paper_backend.py",
    "experiments/research/candidates/srgg/structured_execution.py",
    "experiments/research/candidates/srgg/crt_projection.py",
)


def _integer(value, name, low=1, high=MAX_MODULUS):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("bounded exact integer required: " + name)
    return value


def factor_integer(value):
    """Complete bounded trial division; no probabilistic primality inference."""
    _integer(value, "integer to factor", low=2)
    remaining, prime, result = value, 2, []
    while prime * prime <= remaining:
        exponent = 0
        while remaining % prime == 0:
            remaining //= prime
            exponent += 1
        if exponent:
            result.append((prime, exponent))
        prime = 3 if prime == 2 else prime + 2
    if remaining > 1:
        result.append((remaining, 1))
    return tuple(result)


def multiplicative_order(value, modulus):
    """First positive modular order, with an explicit finite loop bound."""
    _integer(value, "order base", low=2)
    _integer(modulus, "order modulus", low=2, high=2 * MAX_DEGREE)
    if gcd(value, modulus) != 1:
        raise ValueError("order base and modulus must be coprime")
    state = 1
    for order in range(1, modulus + 1):
        state = state * value % modulus
        if state == 1:
            return order
    raise AssertionError("finite group order not found")


def coefficient_crt(modulus):
    """Exact scalar CRT idempotents for the entire original coefficient ring."""
    _integer(modulus, "coefficient modulus", low=3)
    result = []
    for prime, exponent in factor_integer(modulus):
        component = prime**exponent
        cofactor = modulus // component
        idempotent = cofactor * pow(cofactor, -1, component) % modulus
        centered = (idempotent + modulus // 2) % modulus - modulus // 2
        result.append({"prime": prime, "exponent": exponent,
            "prime_power": component, "cofactor": cofactor,
            "idempotent_mod_Q": idempotent, "idempotent_centered": centered})
    if sum(item["idempotent_mod_Q"] for item in result) % modulus != 1:
        raise AssertionError("CRT idempotents do not resolve the identity")
    for i, item in enumerate(result):
        a = item["idempotent_mod_Q"]
        if a * a % modulus != a:
            raise AssertionError("CRT idempotent failed")
        for j, other in enumerate(result):
            if a % other["prime_power"] != int(i == j):
                raise AssertionError("CRT projection/reconstruction failed")
    return result


def uniform_matrix_unit_probability(*, prime, degree, factor_count, rank):
    """Exact ideal-uniform GL probability across independent residue fields.

    Each field has q=prime**degree elements. A matrix over its unramified
    prime-power lift is invertible iff its residue matrix is invertible, so
    the lifting exponent does not change this probability. This is a rank
    diagnostic, not a secret-recovery probability or a planted-law bound.
    """
    _integer(prime, "prime", low=2)
    if factor_integer(prime) != ((prime, 1),):
        raise ValueError("exact prime required")
    _integer(degree, "field degree", high=MAX_DEGREE)
    _integer(factor_count, "field factor count", high=MAX_DEGREE)
    _integer(rank, "matrix rank", high=4)
    q = prime**degree
    one_field = Fraction(1)
    for i in range(1, rank + 1):
        one_field *= 1 - Fraction(1, q**i)
    return one_field**factor_count


def _packed(value):
    return {"numerator_hex": hex(value.numerator), "denominator_hex": hex(value.denominator)}


def _failure_dyadic_upper(probability):
    failure = 1 - probability
    if not 0 < failure <= 1:
        raise ValueError("nonzero failure probability required")
    bits = max(0, failure.denominator.bit_length() - failure.numerator.bit_length())
    while bits and failure.numerator << bits > failure.denominator:
        bits -= 1
    while failure.numerator << (bits + 1) <= failure.denominator:
        bits += 1
    return {"form": "2^-bits", "bits": bits,
            "scope": "probability of nonunit ideal-uniform square matrix, never attack-cost bits"}


def _cardinality(base, exponent, *, enumeration_limit=MAX_ENUMERATION_STATES):
    """Count a finite grid; do not allocate or enumerate its states."""
    cardinality = base**exponent
    return {"exact_power": {"base": base, "exponent": exponent},
        "cardinality_floor_log2": cardinality.bit_length() - 1,
        "enumeration_limit_states": enumeration_limit,
        "fits_enumeration_limit": cardinality <= enumeration_limit,
        "states_enumerated": 0}


def seed_support_boundary(*, base, exponent, seed_bits=256):
    """Marginal support bound for a FIXED deterministic seed expander.

    Any seed_bits-bit source has at most 2**seed_bits matrix images. Against
    a uniform grid of L states this gives TV>=max(0,1-2**seed_bits/L).
    It does not contradict computational pseudorandomness or a ROM proof.
    No oracle transcript, seed/A joint comparison or attack is claimed.
    """
    _integer(base, "support base", low=2)
    _integer(exponent, "support exponent", high=MAX_DEGREE * 16)
    _integer(seed_bits, "seed bits", high=512)
    count = base**exponent
    # L>=2^floor(log2 L) gives a smaller, exact dyadic TV lower bound.
    bits = max(0, count.bit_length() - 1 - seed_bits)
    return {"uniform_grid": {"base": base, "exponent": exponent},
        "seed_bits": seed_bits, "fixed_expander_image_size_upper": {"base": 2, "exponent": seed_bits},
        "tv_lower_exact_formula": "max(0,1-2^seed_bits/base^exponent)",
        "tv_lower_dyadic": {"form": "1-2^-bits", "bits": bits},
        "positive_support_obstruction_certified": count > 2**seed_bits,
        "reference_is_uniform_matrix_marginal": True,
        "fixed_deterministic_expander_only": True,
        "computational_or_ROM_security_inferred": False}


def _factorization(prime, degree):
    # This actual Sage factorization is checked independently against the
    # multiplicative order theorem for the power-of-two cyclotomic Phi_2n.
    from sage.all import GF, PolynomialRing

    ring = PolynomialRing(GF(prime), "x")
    x, polynomial = ring.gen(), ring.gen()**degree + 1
    order = multiplicative_order(prime, 2 * degree)
    factors = list(polynomial.factor())
    product = ring.one()
    records = []
    for factor, exponent in factors:
        product *= factor**exponent
        records.append({"degree": int(factor.degree()), "multiplicity": int(exponent),
                        "coefficients": [int(value) for value in factor.list()]})
    irreducible = all(factor.is_irreducible() for factor, _ in factors)
    squarefree = polynomial.gcd(polynomial.derivative()) == 1
    degrees_match = all(item["degree"] == order and item["multiplicity"] == 1 for item in records)
    if not (product == polynomial and irreducible and squarefree and degrees_match
            and len(records) * order == degree):
        raise AssertionError("actual factorization and cyclotomic order theorem differ")
    encoded = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("ascii")
    return {"prime": prime, "cyclotomic_index": 2 * degree,
        "multiplicative_order": order, "factor_degree": order, "factor_count": len(records),
        "polynomial": "X^n+1", "actual_factor_degrees": [item["degree"] for item in records],
        "actual_factor_multiplicities": [item["multiplicity"] for item in records],
        "actual_factors_sha256": sha256(encoded).hexdigest(),
        "actual_product_equals_polynomial": True, "actual_factors_irreducible": True,
        "actual_polynomial_squarefree": True, "order_theorem_and_actual_factorization_agree": True,
        "theorem": "Phi_(2n) over F_ell has n/ord_(2n)(ell) irreducible factors of degree ord_(2n)(ell), for power-of-two n and odd ell",
        "hensel_lift_status": "squarefree factors lift uniquely to pairwise comaximal monic factors over Z/(ell^e)",
        "hensel_factor_polynomials_constructed": False}


def _hnf_shape(*, degree, rank, columns, modulus):
    # For C=[I_d|U], z=(-U*t,t) is a bijection from the free tail to ker C.
    # It is valid over a composite ring as well as every residue field.
    rows, cols = rank * degree, columns * degree
    coefficient_bytes = ((modulus - 1).bit_length() + 7) // 8
    return {"module_rows": rank, "module_columns": columns,
        "coefficient_rows": rows, "coefficient_columns": cols,
        "free_kernel_module_rank": columns - rank,
        "free_tail_coefficient_count": (columns - rank) * degree,
        "surjective_for_every_U_because_of_identity_block": True,
        "kernel_parametrization": "t -> (-U*t,t)",
        "integer_kernel_lattice_dimension": cols,
        "integer_kernel_lattice_index_exact_power": {"base": modulus, "exponent": rows},
        "hypothetical_dense_scalar_entries": rows * cols,
        "hypothetical_fixed_width_dense_payload_bytes": rows * cols * coefficient_bytes,
        "payload_excludes_objects_algorithms_and_peak_memory": True,
        "matrix_materialized": False}


def build_report():
    """Complete the original rows' public CRT/rank/resource preflight only."""
    from sage.version import version as sage_version

    if sha256((ROOT / SOURCE_PDF).read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("frozen paper checksum differs")
    modulus, degree = profiles[0].Q, profiles[0].degree
    if any(item.Q != modulus or item.degree != degree for item in profiles):
        raise ValueError("original Table 4 rows no longer share Q,n")
    components = coefficient_crt(modulus)
    factorizations = {item["prime"]: _factorization(item["prime"], degree) for item in components}
    rows = []
    for source in profiles:
        d, n, w = source.rank, source.degree, source.digits
        public_columns, sis_columns = (2 + w) * d, (2 + w) * d + 1
        gamma, bound = Fraction(source.gamma), 2 * Fraction(source.gamma)
        whole_unit_probability = Fraction(1)
        projections = []
        for component in components:
            prime, exponent = component["prime"], component["exponent"]
            fact = factorizations[prime]
            f, count = fact["factor_degree"], fact["factor_count"]
            probability = uniform_matrix_unit_probability(prime=prime, degree=f, factor_count=count, rank=d)
            whole_unit_probability *= probability
            projections.append({"prime": prime, "coefficient_prime_power": component["prime_power"],
                "prime_power_exponent": exponent, "factor_degree": f, "factor_count": count,
                "one_local_ring_cardinality_exact_power": {"base": prime, "exponent": exponent * f},
                "one_residue_field_cardinality_exact_power": {"base": prime, "exponent": f},
                "one_field_public_shape": _hnf_shape(degree=f, rank=d, columns=public_columns, modulus=prime),
                "one_field_hnf_msis_shape": _hnf_shape(degree=f, rank=d, columns=sis_columns, modulus=prime),
                "uniform_Ahat_unit_probability_all_factors_exact": _packed(probability),
                "uniform_Ahat_nonunit_probability_dyadic_upper": _failure_dyadic_upper(probability),
                "prime_power_invertible_iff_residue_invertible": True,
                "uniform_Ahat_model_only": True,
                "actual_projected_CBD1_law": "mod3 joint noisy-column certificate below" if prime == 3 else None,
                "prime_power_CBD1_law_certified": exponent == 1 and prime == 3,
                "projected_secret_grid": _cardinality(prime, f * d),
                "full_Ahat_secret_error_residue_grid": _cardinality(prime, f * (d*d + 2*d)),
                "fixed_seed_Ahat_marginal_support_boundary": seed_support_boundary(base=prime, exponent=f*d*d),
                "ring_hnf_or_mlwe_attack_cost": None,
                "field_degree_is_not_attack_cost": True})
        rows.append({"profile": source.name,
            "source_parameters": {"n": n, "d": d, "w": w, "p": source.p, "base": source.base,
                "q": source.q, "Q": source.Q, "gamma": str(gamma)},
            "public_HNF_shape": _hnf_shape(degree=n, rank=d, columns=public_columns, modulus=modulus),
            "conditional_uniform_HNF_MSIS_shape": _hnf_shape(degree=n, rank=d, columns=sis_columns, modulus=modulus),
            "msis_Q_mapping_diagnostic": {"conditional_modulus": modulus,
                "squared_difference_length_bound_exact": str(bound**2), "difference_length_bound_exact": str(bound),
                "trivial_Q_times_unit_vector_norm": modulus,
                "trivial_Q_times_unit_vector_inside_difference_bound": Fraction(modulus) <= bound,
                "Q_strictly_exceeds_difference_bound": Fraction(modulus) > bound,
                "interpretation": "The Q-modulus short-kernel premise excludes Q*e_i only if Q>2*gamma; source theorem modulus mapping remains separate.",
                "IBS_direct_forgery_inferred": False},
            "CRT_projections": projections,
            "uniform_whole_ring_Ahat_unit_probability_exact": _packed(whole_unit_probability),
            "uniform_whole_ring_Ahat_nonunit_probability_dyadic_upper": _failure_dyadic_upper(whole_unit_probability),
            "fixed_seed_whole_Ahat_marginal_support_boundary": seed_support_boundary(base=modulus, exponent=n*d*d),
            "mod3_joint_public_noisy_columns": projection_certificate(degree=n, rank=d, columns=w*d),
            "mod3_law_scope": "independent unfiltered CBD1 source and ideal-uniform Ahat; not the accepted setup-root law",
            "setup_acceptance_conditioning_distance": None,
            "projection_bound_transferred_to_accepted_setup_roots": False,
            "source_CBD1_secret_and_error_assignments_per_noisy_column": _cardinality(3, 2*n*d),
            "structure_attack_or_advantage_established": False,
            "projected_non_mod3_secret_error_laws": None,
            "actual_seeded_matrix_uniformity_proof": None,
            "security_claim": "none", "backend_admitted": False,
            "parameters_are_formal": False, "nist_security_category": None})
    return {"schema": SCHEMA,
        "scope": "original Table 4 only; exact CRT/ring-HNF algebra, ideal-uniform rank law and finite-resource preflight",
        "paper": {"path": SOURCE_PDF, "sha256": SOURCE_SHA256},
        "source_sha256": {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES},
        "environment": {"python": platform.python_version(), "sage": sage_version, "platform": platform.platform()},
        "coefficient_modulus": modulus, "coefficient_CRT": components,
        "coefficient_CRT_all_components_jointly_reconstruct": True,
        "finite_field_factorizations": [factorizations[item["prime"]] for item in components],
        "rows": rows,
        "proved_preflight_scope": ["all original coefficient prime powers and residue-field factor dimensions",
            "actual Sage factorization agrees with the independent modular-order theorem",
            "identity-block HNF surjection and free kernel over every component",
            "exact ideal-uniform square-matrix unit law, including prime-power lifting",
            "fixed-expander marginal support boundary and finite enumeration/payload resources",
            "mod3 noisy-column law with the original shared-Ahat column counts"],
        "model_boundaries": ["Ahat generated by the actual fixed SHAKE seed expander is not statistically assumed uniform",
            "public B is planted CBD1 with a known gadget shift; the uniform HNF challenge needs a separate hybrid",
            "the independent CBD1 projection certificate precedes the setup positive-definiteness retry filter; conditioning costs have not been supplied",
            "CBD1 projections to different polynomial/coefficient factors may be correlated",
            "mod3 public noisy-column bounds average over ideal-uniform Ahat, never every fixed Ahat",
            "factor degree, module rank, invertibility probability and payload size are not attack costs",
            "the Q*e_i diagnostic is not an IBS forgery or a theorem-modulus resolution"],
        "unresolved_costs_and_laws": {"31_squared_CBD1_projection": None, "43_CBD1_projection": None,
            "127_CBD1_projection": None, "CRT_or_subfield_attack_cost": None,
            "ring_HNF_MSIS_attack_cost": None, "full_security_reduction": None},
        "actual_entropy_bytes": 0, "sampler_draws": 0, "attack_executions": 0,
        "private_state_read": False, "estimator_invoked": False, "HIBE_involved": False,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("--output already exists; preserve the old receipt")
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as output:
        output.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"schema": SCHEMA, "original_rows": len(report["rows"]),
        "actual_entropy_bytes": 0, "attack_executions": 0, "security_claim": "none"}))


if __name__ == "__main__":
    main()
