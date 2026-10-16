"""HIBE-independent SRGG parameter candidate screen.

This module is deliberately a *screen*, not a parameter admission routine.  It
freezes the SRGG component's public ``Config`` and derives dimensions, wire
budgets, correctness preconditions and finite sampler resource terms.  The
hardness section is an explicit placeholder because the current SRGG source
uses a module/gadget relation and its paper's theorem symbols have not yet
been mapped to a validated SIS estimate.

No HIBE object, shared registry, CLI or formal security flag is touched here.
The output is suitable for comparing candidates after a HIBE is selected, but
does not choose a HIBE or claim a NIST security level.
"""

from __future__ import annotations

import argparse
import json
from math import gcd, isqrt
from pathlib import Path
from typing import Any

from experiments.research.primitive_spec_audit import SRGG_ROWS, srgg_row

from .config import Config
from .objects import MAX_WIRE, PREFIX
from ..wang_pw.codec import canonical


SCHEMA = "IBME/SRGG-PARAMETER-SCREEN/1"

# NIST's ML-KEM standard is a useful external lattice reference, but it is a
# KEM and therefore cannot be treated as an IBS security proof or as a direct
# security-level conversion for SRGG.  Keep the comparison axes explicit so a
# later parameter study can fill them with independently measured/estimated
# values without silently importing a category claim.
KYBER_NIST_REFERENCE = {
    "standard": "NIST FIPS 203",
    "algorithm_family": "ML-KEM (CRYSTALS-Kyber lineage)",
    "primitive_type": "KEM",
    "comparison_status": "reference-only",
    "security_categories": [1, 3, 5],
    "source": "https://doi.org/10.6028/NIST.FIPS.203",
    "axes": [
        "module/ring dimensions and modulus",
        "public-key and wire-object byte sizes",
        "independently estimated classical and quantum attack costs",
        "correctness/decapsulation-failure versus signature sampler abort",
        "fixed implementation, hardware, repetitions and failure budgets",
    ],
    "non_equivalence": [
        "ML-KEM is a KEM; SRGG is an identity-based signature component",
        "a Kyber category is not an SRGG security level",
        "wire-size or runtime ratios do not establish a reduction",
    ],
}


def _positive_int(value: Any, name: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ValueError(f"{name} must be a positive integer in [1,{maximum}]")
    return value


def _ceil_sqrt(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("non-negative integer square root input required")
    root = isqrt(value)
    return root + int(root * root < value)


def _coefficient_layout(config: Config) -> dict[str, int]:
    p = config.algebra
    coefficient_bits = (p.modulus - 1).bit_length()
    coefficient_bytes = (coefficient_bits + 7) // 8
    return {
        "degree": p.degree,
        "rank": p.rank,
        "gadget_digits": p.digits,
        "gadget_base": p.base,
        "gadget_modulus": p.gadget_modulus,
        "p": p.p,
        "Q": p.modulus,
        "coefficient_bits": coefficient_bits,
        "coefficient_bytes": coefficient_bytes,
        "public_b_coefficient_count": p.rank * p.rank * p.digits * p.degree,
        "master_r_coefficient_count": 2 * p.rank * p.rank * p.digits * p.degree,
        "user_vector_coefficient_count": p.columns * p.degree,
        "response_coefficient_count": (p.columns + 1) * p.degree,
        "challenge_bits": p.degree,
        "challenge_bytes": (p.degree + 7) // 8,
    }


def _zero_poly(degree: int) -> tuple[int, ...]:
    return (0,) * degree


def _reference_records(config: Config) -> dict[str, dict]:
    """Create public-shape JSON records for deterministic wire accounting.

    These records are shape fixtures only.  They intentionally do not pass
    through object constructors, so no private relation or key is generated.
    The resulting sizes are exact for the canonical JSON layout for the given
    shapes, while the all-zero values avoid making a security or entropy claim.
    """

    p = config.algebra
    poly = _zero_poly(p.degree)
    b = tuple(tuple(poly for _ in range(p.rank * p.digits)) for _ in range(p.rank))
    r = tuple(tuple(poly for _ in range(p.rank * p.digits)) for _ in range(2 * p.rank))
    tail = tuple(poly for _ in range((1 + p.digits) * p.rank))
    response = tuple(poly for _ in range(p.columns + 1))
    public = {"config": config.record(), "seed": "00" * 32, "b": b}
    public_wire_hex = (PREFIX + b"PK\0" + canonical(public)).hex()
    signing = {"pk": public_wire_hex, "identity": (b"I" * config.identity_max_bytes).hex(), "tail": tail}
    master = {"pk": public_wire_hex, "r": r, "states": {}}
    signature = {"context": "00" * 32, "z": response, "challenge": (0,) * p.degree}
    return {"public_key": public, "signing_key": signing, "master_secret_empty": master, "signature": signature}


def _wire_layout(config: Config) -> dict[str, Any]:
    records = _reference_records(config)

    def size(kind: str, record: dict) -> int:
        return len(PREFIX) + len(kind) + 1 + len(canonical(record))

    sizes = {
        "public_key_reference_bytes": size("PK", records["public_key"]),
        "signing_key_reference_bytes": size("SK", records["signing_key"]),
        "master_secret_empty_cache_reference_bytes": size("MSK", records["master_secret_empty"]),
        "signature_reference_bytes": size("SIG", records["signature"]),
    }
    layout = _coefficient_layout(config)
    packed_lower_bounds = {
        "public_key": 32 + layout["public_b_coefficient_count"] * layout["coefficient_bytes"],
        "signing_key": sizes["public_key_reference_bytes"] + config.identity_max_bytes
        + layout["user_vector_coefficient_count"] * layout["coefficient_bytes"],
        "master_secret_empty": sizes["public_key_reference_bytes"]
        + layout["master_r_coefficient_count"] * layout["coefficient_bytes"],
        "signature": 32 + layout["response_coefficient_count"] * layout["coefficient_bytes"]
        + layout["challenge_bytes"],
    }
    return {
        **sizes,
        "packed_lower_bounds_bytes": packed_lower_bounds,
        "object_wire_limit_bytes": MAX_WIRE,
        "reference_values": "canonical JSON shape fixture with zero coefficients; not a key or signature",
        "all_reference_objects_within_wire_limit": all(value <= MAX_WIRE for value in sizes.values()),
    }


def _capacity(config: Config, *, identity_bytes: int | None, message_bytes: int | None,
              issuer_users: int | None) -> dict[str, Any]:
    identity = config.identity_max_bytes if identity_bytes is None else _positive_int(
        identity_bytes, "identity_bytes", maximum=config.identity_max_bytes)
    message = config.message_max_bytes if message_bytes is None else _positive_int(
        message_bytes, "message_bytes", maximum=config.message_max_bytes)
    users = config.max_users if issuer_users is None else _positive_int(
        issuer_users, "issuer_users", maximum=config.max_users)
    p = config.algebra
    framing = {"identity_length_prefix_bytes": 4, "message_length_prefix_bytes": 4,
               "hash_domain_separation": "SRGG-ID-v1/SRGG-MESSAGE-v1"}
    return {
        "identity_max_bytes": identity,
        "message_max_bytes": message,
        "issuer_identity_slots": users,
        "response_polynomials": p.columns + 1,
        "response_coefficients": (p.columns + 1) * p.degree,
        "challenge_bits": p.degree,
        "framing": framing,
        "capacity_is_component_local": True,
        "hibe_capacity_unselected": True,
    }


def _correctness(config: Config) -> dict[str, Any]:
    p = config.algebra
    root_bound = 2 * p.rank * p.rank * p.digits * p.degree**2 + p.rank * p.digits * p.degree
    user_bound = p.degree * config.user_norm_squared + p.degree
    gamma_bound = _ceil_sqrt(config.signature_bound_squared)
    gates = {
        "config_constructor": True,
        "odd_p_and_base": p.p % 2 == 1 and p.base % 2 == 1,
        "gadget_modulus_coprime_p": gcd(p.p, p.base) == 1,
        "bounded_coefficient_dimension": (p.columns + 1) * p.degree <= 128,
        "master_width_covers_cbd1_root_class": min(config.master_first_squared,
                                                      config.master_second_squared) >
        config.gadget_width_squared * root_bound + config.r_squared,
        "signature_width_covers_user_norm_class": min(config.signature_first_squared,
                                                        config.signature_second_squared) >
        2 * config.r_squared * user_bound + config.r_squared,
        "exact_Q_gt_2_gamma_bound": p.modulus > 2 * gamma_bound,
        "zeta_noise_factor_is_two": config.signature_noise_factor == 2,
        "identity_capacity_positive": config.identity_max_bytes >= 1,
        "message_capacity_positive": config.message_max_bytes >= 1,
        "issuer_capacity_positive": config.max_users >= 1,
    }
    return {
        "gates": gates,
        "all_component_gates_pass": all(gates.values()),
        "derived": {
            "master_root_class_bound": root_bound,
            "user_norm_class_bound": user_bound,
            "gamma_bound_ceiling": gamma_bound,
            "Q": p.modulus,
            "Q_squared": p.modulus**2,
            "signature_bound_squared": config.signature_bound_squared,
        },
        "interpretation": "algebraic/resource preconditions only; not a correctness proof for every sampler path",
    }


def _sampling(config: Config) -> dict[str, Any]:
    p = config.algebra
    # These counts follow the current runtime call graph.  They are upper
    # resource counts, not a claim that every finite sampler has this exact TV.
    extraction_geometry_scalars = p.columns * p.degree
    extraction_gadget_scalars = p.rank * p.degree * p.digits
    signing_geometry_scalars = (p.columns + 1) * p.degree
    signing_uniform_scalars = p.degree
    scalar_term = {
        "tail_upper_model": f"1/2^{config.scalar_tail_bits}",
        "mass_quantization_upper_model": f"1/2^{config.scalar_mass_bits}",
        "precision_error_upper_model": f"1/2^{max(0, config.precision_bits - max(config.ticket_bits, config.scalar_mass_bits))}",
        "certified": False,
    }
    gadget_term = {
        "tail_upper_model": f"1/2^{config.gadget_tail_bits}",
        "mass_quantization_upper_model": f"1/2^{config.scalar_mass_bits}",
        "precision_error_upper_model": f"1/2^{max(0, config.precision_bits - config.scalar_mass_bits)}",
        "certified": False,
    }
    return {
        "scalar_sampler": scalar_term,
        "gadget_sampler": gadget_term,
        "draw_counts": {
            "key_extraction_geometry_scalar_draws": extraction_geometry_scalars,
            "key_extraction_gadget_scalar_draws": extraction_gadget_scalars,
            "sign_geometry_scalar_draws": signing_geometry_scalars,
            "sign_uniform_scalar_draws": signing_uniform_scalars,
            "sign_total_scalar_draws": signing_geometry_scalars + signing_uniform_scalars,
        },
        "operation_budgets": {
            "setup_max_attempts": config.setup_max_attempts,
            "sign_max_attempts": config.sign_max_attempts,
            "identity_issuance_retry_policy": "none after pending/failed; fixed service blocks reselection",
        },
        "abort_terms": {
            "setup_norm_rejection_upper": None,
            "key_extraction_entropy_abort_upper": None,
            "sign_entropy_abort_upper": None,
            "sign_norm_rejection_abort_upper": None,
            "reason": "acceptance probabilities and finite continuous-stage TV are not certified",
        },
        "modeled_total_tv_upper": None,
        "modeled_total_tv_certified": False,
        "independent_uniform_bytes_assumed": True,
        "constant_time": False,
    }


def _hardness(config: Config) -> dict[str, Any]:
    p = config.algebra
    rows = [srgg_row(row) for row in SRGG_ROWS]
    return {
        "model": "uninstantiated module/SIS estimate placeholder",
        "dimension": p.columns * p.degree,
        "modulus_Q": p.modulus,
        "classical_core_svp_bits": None,
        "quantum_core_svp_bits": None,
        "attack_cost_bits": None,
        "reduction_loss_accounted": False,
        "paper_parameter_rows": rows,
        "source_mapping": "primitive_spec_audit.srgg_row; conditional source-table arithmetic only",
        "hardness_estimate_ready": False,
        "open_obligations": [
            "map SRGG q/p/Q symbols and exact theorem conditions",
            "choose and validate a module/SIS estimator and reduction loss",
            "account for challenge entropy and fixed-service/query loss",
            "reconcile source Table 1/Table 4 wire dimensions with this Config",
        ],
    }


def screen(config: Config | None = None, *, identity_bytes: int | None = None,
           message_bytes: int | None = None, issuer_users: int | None = None) -> dict[str, Any]:
    """Return a deterministic, HIBE-independent SRGG candidate screen."""

    config = Config() if config is None else config
    if not isinstance(config, Config):
        raise TypeError("SRGG Config required")
    result = {
        "schema": SCHEMA,
        "algorithm": "SRGG IBS component",
        "parameters": config.record(),
        "derived_layout": _coefficient_layout(config),
        "wire": _wire_layout(config),
        "capacity": _capacity(config, identity_bytes=identity_bytes,
                               message_bytes=message_bytes, issuer_users=issuer_users),
        "correctness": _correctness(config),
        "sampling": _sampling(config),
        "hardness": _hardness(config),
        "kyber_nist_reference": KYBER_NIST_REFERENCE,
        "hibe_independent": True,
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
        "limitations": [
            "Config is a bounded research profile, not a standard security parameter set.",
            "Wire sizes are canonical JSON shape references and are not compressed production encodings.",
            "Sampling terms are resource/model placeholders; no total-TV or abort certificate is asserted.",
            "Hardness estimates, reduction losses, strong unforgeability and HIBE composition remain open.",
            "Kyber/NIST labels are not inferred from this SRGG component screen.",
        ],
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--identity-bytes", type=int)
    parser.add_argument("--message-bytes", type=int)
    parser.add_argument("--issuer-users", type=int)
    args = parser.parse_args()
    report = screen(identity_bytes=args.identity_bytes, message_bytes=args.message_bytes,
                    issuer_users=args.issuer_users)
    encoded = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8", newline="\n")
    print(encoded, end="")


if __name__ == "__main__":
    main()
