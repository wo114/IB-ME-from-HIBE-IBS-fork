"""Exact public CUR obstruction and conditional same-message malleation.

The first public block is 2I modulo 2Q.  Two short integer responses differing
by Q in one coefficient can therefore have the same commitment and challenge.
Given an already valid signature, a Q shift also preserves its hash commitment;
the transform succeeds if the new response still meets the public norm cap.
The default report does not instantiate source-profile honest signatures,
estimate this event's probability, certify CUR, or admit parameters.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import json
from pathlib import Path

from experiments.research.primitive_spec_audit import SRGG_ROWS, srgg_row

from .config import Config


SCHEMA = "IBME/SRGG-CUR-OBSTRUCTION/2"
MAX_MODULUS_BITS = 4096
MAX_BOUND_BITS = 2 * MAX_MODULUS_BITS
MAX_RESPONSE_COEFFICIENTS = 2**16


def _bounded_integer(value: int, name: str, *, minimum: int, bits: int) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} must be an exact integer >= {minimum}")
    if value.bit_length() > bits:
        raise ValueError(f"{name} exceeds the {bits}-bit public audit cap")
    return value


def collision_pair(modulus: int, gamma_squared: int) -> dict:
    """Public one-coefficient responses; all arithmetic is exact and bounded.

    Q=modulus must be odd and >=3.  gamma_squared is the inclusive integer
    squared-norm cap B.  In any response domain containing integer ring
    vectors, use c=0, z+=(Q-1)e/2, z-=-(Q+1)e/2 in the first 2I block.
    Other coefficients are zero.  The pair fits iff B >= ((Q+1)/2)^2.
    """

    q = _bounded_integer(modulus, "modulus Q", minimum=3, bits=MAX_MODULUS_BITS)
    cap = _bounded_integer(gamma_squared, "gamma squared", minimum=0, bits=MAX_BOUND_BITS)
    if q % 2 != 1:
        raise ValueError("odd modulus Q required")
    plus, minus = (q - 1) // 2, -(q + 1) // 2
    plus_commitment, minus_commitment = (2 * plus) % (2 * q), (2 * minus) % (2 * q)
    threshold = max(plus * plus, minus * minus)
    same_commitment = plus_commitment == minus_commitment
    distinct = plus != minus
    fits = threshold <= cap
    return {
        "modulus_Q": q,
        "commitment_modulus": 2 * q,
        "gamma_squared_cap": cap,
        "challenge": "all-zero binary polynomial",
        "response_support": "constant coefficient of the first polynomial in the 2I block",
        "other_response_coefficients": 0,
        "plus_coefficient": plus,
        "minus_coefficient": minus,
        "difference_coefficient": plus - minus,
        "plus_norm_squared": plus * plus,
        "minus_norm_squared": minus * minus,
        "pair_required_gamma_squared": threshold,
        "plus_commitment_coefficient": plus_commitment,
        "minus_commitment_coefficient": minus_commitment,
        "same_commitment": same_commitment,
        "distinct_responses": distinct,
        "both_responses_within_cap": fits,
        "cur_obstruction_at_this_cap": distinct and same_commitment and fits,
        "cur_certified_if_pair_does_not_fit": False,
        "full_fs_forgery": False,
        "hash_fixed_point_searched": False,
    }


def coefficient_malleation(modulus: int, gamma_squared: int, coefficient: int,
                          old_norm_squared: int) -> dict:
    """Check a public response coefficient's exact Q shift, without hashing.

    The coefficient must be in the first 2I block.  Other coefficients and c
    stay unchanged.  If the original FS signature is valid and both norms
    fit, this produces a different valid signature on that same message.
    Validity of the input signature is a precondition, not checked here.
    """

    q = _bounded_integer(modulus, "modulus Q", minimum=3, bits=MAX_MODULUS_BITS)
    cap = _bounded_integer(gamma_squared, "gamma squared", minimum=0, bits=MAX_BOUND_BITS)
    if q % 2 != 1:
        raise ValueError("odd modulus Q required")
    if type(coefficient) is not int:
        raise ValueError("public response coefficient must be an exact integer")
    if abs(coefficient).bit_length() > MAX_MODULUS_BITS:
        raise ValueError("public response coefficient exceeds the public audit cap")
    old = _bounded_integer(old_norm_squared, "old norm squared", minimum=0, bits=MAX_BOUND_BITS)
    if coefficient*coefficient > old:
        raise ValueError("old norm squared must include the supplied coefficient")
    # Pick the direction toward zero; at zero either direction has equal norm.
    shift = -q if coefficient > 0 else q
    changed = coefficient+shift
    new = old+q*q-2*q*abs(coefficient)
    original_fits, changed_fits = old <= cap, new <= cap
    return {
        "modulus_Q": q,
        "gamma_squared_cap": cap,
        "old_coefficient": coefficient,
        "shift": shift,
        "new_coefficient": changed,
        "old_norm_squared": old,
        "new_norm_squared": new,
        "same_commitment_for_every_unchanged_challenge": (2*shift) % (2*q) == 0,
        "distinct_response": changed != coefficient,
        "original_norm_within_cap": original_fits,
        "new_norm_within_cap": changed_fits,
        "sufficient_old_norm_squared_max": cap-q*q,
        "coefficient_independent_margin_condition_holds": old <= cap-q*q,
        "strong_malleation_if_original_signature_valid": original_fits and changed_fits,
        "original_signature_verified_by_this_check": False,
        "requires_coefficient_in_first_2I_block": True,
        "requires_transformed_response_in_valid_object_domain": True,
        "message_identity_context_and_challenge_must_remain_unchanged": True,
        "hash_fixed_point_search_required": False,
        "source_honest_signature_executed": False,
    }


def transform_response(response, modulus: int, gamma_squared: int) -> tuple[tuple[int, ...], dict]:
    """Transform the first coefficient of a flat PUBLIC signature response.

    No original signature is verified.  The first coefficient is necessarily
    in the first 2I polynomial under Algorithm 8's coefficient layout.  The
    returned response may exceed the norm cap; callers must inspect the check.
    Input data are never modified. No key or issuer-state files are loaded;
    callers must supply a public response in the actual coefficient layout.
    """

    if not isinstance(response, (tuple, list)) or not 1 <= len(response) <= MAX_RESPONSE_COEFFICIENTS:
        raise ValueError("bounded nonempty flat public response required")
    values = tuple(response)
    for value in values:
        if type(value) is not int or abs(value).bit_length() > MAX_MODULUS_BITS:
            raise ValueError("bounded exact public response coefficients required")
    norm_squared = sum(value*value for value in values)
    check = coefficient_malleation(modulus, gamma_squared, values[0], norm_squared)
    transformed = (check["new_coefficient"],)+values[1:]
    return transformed, check


def source_rows() -> list[dict]:
    """Apply the obstruction to Table 4's literal reported decimal cutoffs.

    All squared norms are integers, so floor(gamma^2) implements the same
    inclusive norm test without floating-point or Decimal rounding.  This is
    a check on the reported decimals, not a claim about unpublished precision.
    """

    result = []
    for row in SRGG_ROWS:
        q = srgg_row(row)["modulus_Q"]
        gamma_squared = Fraction(row["gamma"]) ** 2
        literal_cap = gamma_squared.numerator // gamma_squared.denominator
        result.append({
            "source_name": row["name"],
            "source_rank": row["rank"],
            "source_gamma_decimal": row["gamma"],
            "source_gamma_squared_exact": str(gamma_squared),
            **collision_pair(q, literal_cap),
            "conditional_strong_malleation": {
                "sufficient_old_norm_squared_max": literal_cap-q*q,
                "nonnegative_coefficient_independent_margin_exists": literal_cap >= q*q,
                "requires_already_valid_source_signature": True,
                "requires_unchanged_message_identity_context_and_challenge": True,
                "source_honest_signature_executed": False,
                "success_probability": None,
                "guaranteed_for_every_valid_signature": False,
                "hash_fixed_point_search_required": False,
            },
        })
    return result


def configuration_gate(config: Config | None = None) -> dict:
    """Check the executable Config's exact Q>2sqrt(B) exclusion of this pair.

    This checks an existing arithmetic gate; it does not change that gate or
    assert the absence of other short kernel vectors or strong forgeries.
    """

    config = Config() if config is None else config
    if not isinstance(config, Config):
        raise ValueError("an executable SRGG Config is required")
    q, cap = config.algebra.modulus, config.signature_bound_squared
    pair = collision_pair(q, cap)
    exact_gate = q * q > 4 * cap
    return {
        **pair,
        "exact_Q_gt_2gamma_gate": exact_gate,
        "gate_margin_Q_squared_minus_four_B": q * q - 4 * cap,
        "existing_config_gate_excludes_this_pair": exact_gate and not pair["cur_obstruction_at_this_cap"],
        "excludes_all_single_Q_shifts_between_norm_valid_responses": exact_gate,
        "Q_shift_exclusion_argument": "difference norm Q <= norm(z)+norm(z') <= 2*sqrt(B) contradicts Q^2>4B",
        "other_cur_obstructions_excluded": False,
        "strong_security_certified": False,
    }


def build_report() -> dict:
    return {
        "schema": SCHEMA,
        "source": {
            "doi": "10.1049/ise2/6684889",
            "pages": [6, 8, 9],
            "items": "Table 3; Algorithms 7/8; Table 4",
        },
        "scope": "exact CUR pair and conditional same-message signature malleation after an observable norm check",
        "required_verifier_relation": "Abar*z-Q*c*j = w modulo 2Q; norm_squared(z) <= B",
        "required_public_block": "first block 2I; integer coefficient responses and zero binary challenge allowed",
        "source_parameter_rows": source_rows(),
        "executable_config": configuration_gate(),
        "resource_caps": {"modulus_bits": MAX_MODULUS_BITS, "gamma_squared_bits": MAX_BOUND_BITS},
        "full_fs_forgery": False,
        "hash_fixed_point_searched": False,
        "cur_certified": False,
        "strong_security_proof_verified": False,
        "source_honest_signature_executed": False,
        "unconditional_source_signature_break_claimed": False,
        "conditional_malleation": {
            "input": "an already valid signature; change only a first-2I response coefficient by -sign(v)*Q (zero uses +Q)",
            "exact_new_norm_squared": "old_norm_squared+Q^2-2*Q*abs(v)",
            "sufficient_observable_condition": "old_norm_squared <= B-Q^2",
            "new_signature_requires": "original is valid and new_norm_squared <= B; same message, identity, context and c",
            "hash_fixed_point_search_required": False,
            "success_probability": None,
        },
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--modulus", type=int, help="optional odd public Q for an extra pair check")
    parser.add_argument("--gamma-squared", type=int, help="inclusive integer squared-norm cap for that check")
    parser.add_argument("--coefficient", type=int, help="optional first-2I response coefficient for a conditional malleation check")
    parser.add_argument("--old-norm-squared", type=int, help="squared norm of its original public response")
    args = parser.parse_args()
    if (args.modulus is None) != (args.gamma_squared is None):
        parser.error("--modulus and --gamma-squared must be supplied together")
    if (args.coefficient is None) != (args.old_norm_squared is None):
        parser.error("--coefficient and --old-norm-squared must be supplied together")
    if args.coefficient is not None and args.modulus is None:
        parser.error("malleation inputs require --modulus and --gamma-squared")
    report = build_report()
    if args.modulus is not None:
        try:
            report["requested_pair"] = collision_pair(args.modulus, args.gamma_squared)
            if args.coefficient is not None:
                report["requested_malleation"] = coefficient_malleation(
                    args.modulus, args.gamma_squared, args.coefficient, args.old_norm_squared)
        except ValueError as exc:
            parser.error(str(exc))
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8", newline="\n")
    print(encoded, end="")


if __name__ == "__main__":
    main()
