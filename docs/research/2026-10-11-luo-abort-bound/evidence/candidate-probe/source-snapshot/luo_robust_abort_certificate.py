"""Directed-rational availability bounds; NOT security admission or exact rates.

See the companion robust-set/CRT second-moment proof. Assumes ideal independent
uniform source words and an ideal XOF; the implementation's SHAKE is not proved
equal to either. This module never changes the backend's default parameters.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, replace
from fractions import Fraction as Q
import json
import math
from pathlib import Path

from ibme.ibs.luo_module import LuoModuleParams, HASH_BYTES


def require(condition, message):
    if not condition:
        raise ValueError(message)


def ceil_div(a, b):
    return (a + b - 1) // b


def power_interval(value, exponent, bits=1024):
    """Enclose value**exponent by dyadics, including underflow, without floats."""
    value = Q(value)
    require(0 <= value <= 1 and isinstance(exponent, int) and exponent >= 0,
            "invalid probability or exponent")
    require(isinstance(bits, int) and 16 <= bits <= 4096, "invalid precision")
    scale = 1 << bits
    lo = value.numerator * scale // value.denominator
    hi = ceil_div(value.numerator * scale, value.denominator)
    out_lo = out_hi = scale
    while exponent:
        if exponent & 1:
            out_lo = out_lo * lo // scale
            out_hi = ceil_div(out_hi * hi, scale)
        lo = lo * lo // scale
        hi = ceil_div(hi * hi, scale)
        exponent >>= 1
    return Q(out_lo, scale), Q(out_hi, scale)


def dyadic_record(value, direction, bits=1024):
    value = Q(value)
    require(0 <= value <= 1 and direction in ("lower", "upper"), "invalid bound")
    scale = 1 << bits
    numerator = (value.numerator * scale // value.denominator if direction == "lower"
                 else ceil_div(value.numerator * scale, value.denominator))
    return {"direction": direction, "numerator": str(numerator),
            "denominator_power_of_two": bits,
            "approx_log2_bound": None if not numerator else math.log2(numerator) - bits,
            "approximation_is_not_the_certificate": True}


def read_bound(record):
    return Q(int(record["numerator"]), 1 << record["denominator_power_of_two"])


def scalar_abort(bound, attempts, bits=1024):
    require(bound >= 1 and attempts >= 1, "invalid scalar sampler")
    width = max(1, ((bound - 1).bit_length() + 7) // 8)
    ceiling = 1 << (8 * width)
    rho = Q(ceiling % bound, ceiling)
    return power_interval(rho, attempts, bits)[1]


def challenge_abort(p, bits=1024):
    # For this theorem profile N<=256: each position and sign uses one byte.
    require(p.degree <= 256 and p.kappa * (p.max_uniform_attempts + 1) <= HASH_BYTES,
            "XOF capacity needs a separate proof for this profile")
    return min(Q(1), sum((scalar_abort(p.degree - j, p.max_uniform_attempts, bits)
                         for j in range(p.kappa)), Q(0)))


def profile(name):
    p = LuoModuleParams()
    if name == "current":
        return p
    if name == "k49-cap4096":
        return replace(p, kappa=49, max_extract_attempts=4096, max_sign_attempts=4096)
    if name == "availability-candidate":
        return replace(p, kappa=49, gamma1=145000, gamma2=34000000000,
                       max_extract_attempts=4096, max_sign_attempts=4096)
    raise ValueError("unknown research profile")


def certificate(p, *, epsilon=Q(1, 100), extracts=1, signs=1, oracle_queries=0, bits=1024):
    require(isinstance(p, LuoModuleParams), "explicit module parameters required")
    require(0 < epsilon < 1 and p.l >= 2 and (p.q - 1) % (2 * p.degree) == 0,
            "CRT/second-moment conditions fail")
    require(all(isinstance(x, int) and not isinstance(x, bool) and x >= 0
                for x in (extracts, signs, oracle_queries)) and extracts <= p.max_cached_identities,
            "invalid finite call budget")
    # Constructor validates the approved prime and primitive 2N-th root.
    p.ring()
    p.rounding()
    beta = p.beta2
    core = 2 * p.gamma2 - 4 * beta - 1
    full = 2 * p.gamma2 + 1
    threshold = p.gamma3 - 2 * beta
    require(0 < core < p.q and threshold > 0 and p.gamma1 >= 2 * p.beta1,
            "robust center set is empty or not injective modulo q")
    buckets = (p.q - 1) // (2 * p.gamma3)
    residues = buckets * (2 * threshold - 1)
    require(0 < residues < p.q and p.kappa * 2 ** (p.dropped_bits - 1) < p.gamma3,
            "robust low-bit or hint condition fails")
    f_lo, f_hi = power_interval(Q(residues, p.q), p.degree * p.k, bits)
    require(f_lo > 0, "increase precision; target mass underflow")
    z_lo, _ = power_interval(Q(core, full), p.degree * p.l, bits)
    delta_zero = Q(p.degree, core ** p.l)
    delta_pair = min(Q(1), delta_zero + Q(p.degree, core ** (p.l - 1)))
    delta_a = min(Q(1), (delta_pair + 2 * delta_zero * f_hi ** 2)
                  / (epsilon ** 2 * f_lo ** 2))
    sign_success = z_lo * (1 - epsilon) * f_lo
    sign_retry = power_interval(1 - sign_success, p.max_sign_attempts, bits)[1]
    extract_core = 2 * p.gamma1 - 4 * p.beta1 + 1
    extract_success = power_interval(Q(extract_core, 2 * p.gamma1 + 1),
                                     p.degree * (p.k + p.l), bits)[0]
    extract_retry = power_interval(1 - extract_success, p.max_extract_attempts, bits)[1]
    h_abort = challenge_abort(p, bits)
    setup_sources = min(Q(1), p.degree * p.k * p.l * scalar_abort(p.q, p.max_uniform_attempts, bits)
                        + p.degree * (p.k + p.l) * scalar_abort(2 * p.eta + 1, p.max_uniform_attempts, bits))
    sign_sources = min(Q(1), p.max_sign_attempts * p.degree * p.l
                       * scalar_abort(full, p.max_uniform_attempts, bits)
                       + (2 * p.max_sign_attempts + 1) * h_abort)
    extract_sources = min(Q(1), p.max_extract_attempts * p.degree * (p.k + p.l)
                          * scalar_abort(2 * p.gamma1 + 1, p.max_uniform_attempts, bits)
                          + 2 * (p.max_extract_attempts + 1) * h_abort)
    external_hash = min(Q(1), oracle_queries * h_abort)
    total = min(Q(1), delta_a + setup_sources + extracts * (extract_retry + extract_sources)
                + signs * (sign_retry + sign_sources) + external_hash)
    values = {"matrix_bad_event": delta_a, "setup_source_abort": setup_sources,
              "sign_retry_given_good_matrix": sign_retry, "sign_source_abort": sign_sources,
              "extract_retry": extract_retry, "extract_source_abort": extract_sources,
              "challenge_decode_abort_per_fresh_query": h_abort,
              "external_oracle_decode_abort": external_hash, "finite_lifecycle_abort": total}
    bounds = {name: dyadic_record(value, "upper", bits) for name, value in values.items()}
    bounds["sign_per_attempt_success_given_good_matrix"] = dyadic_record(sign_success, "lower", bits)
    bounds["extract_per_attempt_success"] = dyadic_record(extract_success, "lower", bits)
    return {"schema": "IBME/LUO-ROBUST-AVAILABILITY/1", "parameters": asdict(p),
            "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False,
            "kind": "conservative mathematical bound, not measured acceptance or security strength",
            "model": "independent ideal source words; ideal XOF challenge decoder",
            "matrix_scope": "uniform Setup A except the explicit matrix_bad_event; not every adversarial A",
            "quantifiers": "all valid fixed keys/messages/challenge outputs on the same good A; fresh masks per attempt",
            "budgets": {"setups": 1, "new_identity_extract_calls": extracts, "sign_calls": signs,
                        "external_fresh_oracle_queries": oracle_queries,
                        "operating_system_entropy_failures_included": False,
                        "invalid_input_cache_capacity_or_storage_failures_included": False},
            "epsilon": str(epsilon), "precision_bits": bits,
            "arithmetic": {"mask_core_length": core, "mask_full_length": full,
                           "lowbit_core_threshold": threshold, "lowbit_core_residues": residues,
                           "lowbit_buckets": buckets, "extract_core_length": extract_core},
            "bounds": bounds,
            "claims_not_made": ["exact joint LowBits distribution", "all-public-matrix bound",
                                "SHAKE indistinguishability proof", "EUF-ID-CMA reduction",
                                "security level or production admission", "actual CHKP combination"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("current", "k49-cap4096", "availability-candidate"), default="current")
    parser.add_argument("--extracts", type=int, default=1)
    parser.add_argument("--signs", type=int, default=1)
    parser.add_argument("--oracle-queries", type=int, default=0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = certificate(profile(args.profile), extracts=args.extracts, signs=args.signs,
                         oracle_queries=args.oracle_queries)
    result["profile"] = args.profile
    raw = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(raw)
    else:
        print(raw, end="")


if __name__ == "__main__":
    main()
