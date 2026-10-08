"""Public arithmetic checks for the R1 paper-to-implementation specifications.

This module generates no keys, signatures or ciphertexts and never admits a
backend. Modulus compatibility, packing sizes and literal theorem conditions
are necessary bookkeeping checks, not security estimates or proof repairs.
"""

from __future__ import annotations

import argparse
from decimal import Decimal
import json
from pathlib import Path
from typing import Callable


LUO_ROWS = (
    dict(name="table-1-I", bits=34, k=6, l=5, kappa=39, gamma1=49920,
         drop_bits=26, beta2=1946880, gamma2=4984012800,
         signature_bytes_reported=6691, bkz_blocksize_reported=312),
    dict(name="table-1-II", bits=36, k=8, l=7, kappa=39, gamma1=69888,
         drop_bits=27, beta2=2725632, gamma2=9768665088,
         signature_bytes_reported=9738, bkz_blocksize_reported=470),
    dict(name="table-1-III", bits=38, k=11, l=10, kappa=49, gamma1=125440,
         drop_bits=28, beta2=6146560, gamma2=31470387200,
         signature_bytes_reported=14680, bkz_blocksize_reported=688),
)

SRGG_ROWS = (
    dict(name="PARAM-I", rank=2, gamma="42086491.7", table1_mpk=3104,
         table4_mpk=12320, table1_signature=12088, table4_signature=12148),
    dict(name="PARAM-II", rank=3, gamma="63653172.0", table1_mpk=4640,
         table4_mpk=27680, table1_signature=17736, table4_signature=17786),
    dict(name="PARAM-III", rank=4, gamma="86573930.5", table1_mpk=6176,
         table4_mpk=49184, table1_signature=23480, table4_signature=23516),
)


def positive_integer(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def coefficient_bits(modulus: int) -> int:
    """Bits for the canonical coefficient range 0 <= x < modulus."""
    positive_integer(modulus, "modulus")
    if modulus < 2:
        raise ValueError("modulus must be at least two")
    return (modulus - 1).bit_length()


def compatible_moduli(bits: int, alpha: int, degree: int = 256) -> list[int]:
    """Conditional q values for b-bit q, alpha | q-1, and 2n | q-1.

    This interprets the paper's approximate log2(q) row as a bit-length interval.
    It does not prove that the authors used any returned q or that q is prime.
    """
    positive_integer(bits, "bits")
    positive_integer(alpha, "alpha")
    positive_integer(degree, "degree")
    if bits > 63:
        raise ValueError("this finite source-table check supports at most 63 bits")
    lower, upper = 1 << (bits - 1), (1 << bits) - 1
    first = max(1, (lower - 1 + alpha - 1) // alpha)
    last = (upper - 1) // alpha
    if last - first > 10000:
        raise ValueError("candidate interval too large for this source-table check")
    return [multiplier * alpha + 1 for multiplier in range(first, last + 1)
            if (multiplier * alpha) % (2 * degree) == 0]


def luo_row(row: dict, is_prime: Callable[[int], bool] | None = None) -> dict:
    """Keep source values and missing assumptions separate from derived checks."""
    candidates = compatible_moduli(row["bits"], row["gamma2"])
    n = 256
    gamma1, beta1 = row["gamma1"], row["kappa"]
    # Inclusive uniform masks and the paper's Extract rejection rule.
    mask_values = 2 * gamma1 + 1
    accepted_values = 2 * (gamma1 - beta1) + 1
    repetitions = (Decimal(mask_values) / Decimal(accepted_values)) ** (
        n * (row["k"] + row["l"]))
    moduli = []
    for q in candidates:
        moduli.append(dict(q=q, coefficient_bits=coefficient_bits(q),
                           rounding_divisor_ok=(q - 1) % row["gamma2"] == 0,
                           ntt_divisibility_ok=(q - 1) % (2 * n) == 0,
                           legacy_uint32_params_compatible=q < 2**32,
                           prime=None if is_prime is None else bool(is_prime(q))))
    blocksize = row["bkz_blocksize_reported"]
    return dict(
        source=row.copy(), polynomial_degree=n,
        beta2_relation_ok=row["beta2"] == row["kappa"] * gamma1,
        key_acceptance_bound=gamma1 - beta1,
        sign_acceptance_bound_strict=row["gamma2"] - row["beta2"],
        extract_repetitions_derived=str(repetitions),
        compatible_moduli_interpretation="bit length and alpha=2*gamma3=gamma2; conditional",
        compatible_moduli=moduli,
        exact_paper_modulus_known=False,
        classical_core_svp_exponent_from_source=str(Decimal("0.292") * blocksize),
        quantum_core_svp_exponent_from_source=str(Decimal("0.265") * blocksize),
        reduction_query_loss_accounted=False,
        backend_admitted=False, security_claim="none",
    )


def srgg_row(row: dict) -> dict:
    """Check two explicitly conditional readings of the paper's q/Q symbols."""
    n, w, q_gadget, p = 512, 2, 31**2, 2**14 - 1
    modulus = p * q_gadget
    gamma = Decimal(row["gamma"])
    # Algorithm 1's non-identity public block has d by w*d ring elements.
    public_coefficients = row["rank"] ** 2 * w * n
    packed_bytes = (public_coefficients * coefficient_bits(modulus) + 7) // 8 + 32
    return dict(
        source=row.copy(), polynomial_degree=n, gadget_base=31,
        gadget_dimension=w, gadget_modulus=q_gadget, p=p, modulus_Q=modulus,
        public_coefficient_count=public_coefficients,
        public_fixed_bit_packing_plus_seed_bytes=packed_bytes,
        table4_matches_this_public_matrix_layout=packed_bytes == row["table4_mpk"],
        table1_table4_public_sizes_equal=row["table1_mpk"] == row["table4_mpk"],
        table1_table4_signature_sizes_equal=row["table1_signature"] == row["table4_signature"],
        theorem1_interpretation="Not a proved mapping: requires clarification of Section 3 q versus IBS Q",
        literal_Q_gt_2gamma=Decimal(modulus) > 2 * gamma,
        literal_2Q_gt_2gamma=Decimal(2 * modulus) > 2 * gamma,
        twice_gamma=str(2 * gamma),
        underlying_strong_signature_condition_verified=False,
        backend_admitted=False, security_claim="none",
    )


def chkp_payload_cost(m: int, payload_bytes: int, modulus_bits: int,
                      *, depth: int = 2) -> dict:
    """Coefficient-count comparison for the two published payload layouts.

    Assumes a fixed maximum depth and excludes framing, keys and all timings.
    A multi-bit ciphertext shares its preamble; each bit has its own syndrome.
    The resulting decryption vectors and public RO expansion are not free.
    """
    positive_integer(m, "m")
    positive_integer(modulus_bits, "modulus_bits")
    positive_integer(depth, "depth")
    if isinstance(payload_bytes, bool) or not isinstance(payload_bytes, int) or payload_bytes < 1:
        raise ValueError("payload_bytes must be a positive integer")
    bits = 8 * payload_bytes
    columns = (depth + 1) * m
    independent = bits * (columns + 1)
    amortized = columns + bits
    return dict(
        maximum_depth=depth, base_columns=m, padded_preamble_coefficients=columns,
        payload_bytes=payload_bytes, payload_bits=bits,
        independent_bit_ciphertext_coefficients=independent,
        amortized_ciphertext_coefficients=amortized,
        independent_bit_packed_bytes=(independent * modulus_bits + 7) // 8,
        amortized_packed_bytes=(amortized * modulus_bits + 7) // 8,
        independent_bit_hibe_random_secret_vectors=bits,
        amortized_hibe_random_secret_vectors=1,
        amortized_distinct_syndromes=bits,
        decryption_preimage_coefficients_if_materialized=columns * bits,
        public_syndrome_elements_per_row=bits,
        parameter_admitted=False, security_claim="none",
    )


def build_report(is_prime: Callable[[int], bool] | None = None) -> dict:
    return dict(
        scope="Public specification arithmetic; no cryptographic execution",
        security_claim="none", backend_admitted=False,
        luo=[luo_row(row, is_prime) for row in LUO_ROWS],
        srgg=[srgg_row(row) for row in SRGG_ROWS],
        chkp_layout=dict(depth=2, parent_columns_multiplier=2,
                         child_columns_multiplier=3,
                         fixed_decapsulation_key_per_identity_required=True),
        payload_cost_examples=[chkp_payload_cost(128, sig + 32, 17)
                               for sig in (6691, 9738, 14680)],
        payload_cost_example_parameters="m=128, 17-bit q is only a counting model, not legal LWE parameters",
        hardware_or_performance_result=False,
        primality_checked_with_sage=is_prime is not None,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--certify-primes-with-sage", action="store_true")
    args = parser.parse_args()
    is_prime = None
    if args.certify_primes_with_sage:
        from sage.all import ZZ
        is_prime = lambda q: bool(ZZ(q).is_prime(proof=True))
    report = build_report(is_prime)
    encoded = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
