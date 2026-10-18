"""Recompute the existing honest-service arithmetic, without sampler calls.

Run from any directory with ordinary Python. --output creates a new receipt
exclusively; the default writes JSON to stdout. Source the law/model hypotheses
from honest-service-law.md; this arithmetic does not prove them or security.
"""
import argparse
from fractions import Fraction
from hashlib import sha256
import json
from math import isqrt
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
from experiments.research.candidates.srgg import service_budget as budget


def require(condition, message):
    if not condition:
        raise ValueError(message)


def ceil(value):
    return -(-value.numerator // value.denominator)


def report():
    receipts, inputs, declared_sources = budget.load_inputs(ROOT)
    require(len(inputs) == 5 and len(declared_sources) == 16, "frozen input/source inventory differs")
    integrated = budget._profile(receipts["integrated"])
    execution = receipts["execution"]
    params, components = integrated["parameters"], budget.components(receipts)
    tickets = execution["series_options"]["ticket_bits"]
    radius = execution["scalar_options"]["max_radius"]
    require(tickets == 768 and radius == 2**56, "frozen finite support profile differs")
    caps, series_inputs = {}, {}
    for name in ("master_sampler", "sign_sampler"):
        sampler = integrated[name]
        series = sampler["series"]
        scale = Fraction(series["scale_upper_exact"])
        rounding = Fraction(series["operator_vector_rounding_l2_error_upper"])
        dimension = sampler["dimension"]
        noise = scale * (4 * dimension * (tickets + 1) + rounding)
        caps[name] = ceil(noise) + radius + 2
        series_inputs[name] = {
            "dimension": dimension,
            "scale_upper_exact": str(scale),
            "operator_vector_rounding_l2_error_upper": str(rounding),
            "noise_cap_exact": str(noise),
            "noise_cap_ceiling": ceil(noise),
            "finite_sample_coefficient_abs_upper": caps[name],
        }
    n, d, w, b = (params[key] for key in ("degree", "rank", "digits", "base"))
    digit = (b-1) + b*(radius+2)
    raw = caps["master_sampler"] + w*d*n*digit
    response = caps["sign_sampler"] + n*isqrt(params["user_norm_cap"])*(2*(radius+2)+1)
    values = {
        "master_perturbation": caps["master_sampler"],
        "sign_perturbation": caps["sign_sampler"],
        "gadget_digit": digit,
        "raw_U": raw,
        "sign_response_before_norm_gate": response,
    }
    require(all(value.bit_length() <= 256 for value in values.values()), "finite all-path coefficient guard failed")
    scenarios = []
    for name, nk, qs, qi in (
            ("audit-counts-only-not-rerun", 2, 3, 4),
            ("two-fixed-keys-large-query-arithmetic-only", 2, 2**40, 4),
            ("sixty-four-fixed-keys-large-query-arithmetic-only", 64, 2**40, 2**40)):
        ns = params["sign_max_attempts"] * qs
        same_f = min(Fraction(1), nk*components["issuance_to_latent_dual_gate"]
                     + ns*components["sign_attempt_to_sequential_ideal"])
        uniform = min(Fraction(1), same_f + components["matrix_hash_failure"]
                      + qi*components["identity_hash_failure"])
        scenarios.append({
            "name": name, "delta_hist": budget.pack(Fraction(0)),
            "N_K": nk, "q_S": qs, "L": params["sign_max_attempts"],
            "N_S_upper": ns, "Q_I_upper": qi,
            "Delta_FA_F_exact": budget.pack(same_f),
            "Delta_FA_U_classical_exact": budget.pack(uniform),
            "executed_in_this_receipt": False,
        })
    require([row["Delta_FA_U_classical_exact"]["dyadic_upper_exponent"] for row in scenarios]
            == [-172, -134, -134], "previously reviewed scenario bounds differ")
    extra_sources = (
        "experiments/research/candidates/srgg/service_budget.py",
        "experiments/research/candidates/srgg/structured_backend.py",
        "src/ibme/ibs/srgg_structured_service.py",
        "src/ibme/ibs/srgg_service.py",
        str(Path(__file__).resolve().relative_to(ROOT)).replace("\\", "/"),
        "docs/research/team-b-delivery/2026-10-16-srgg-joint-law/honest-service-law.md",
    )
    source_hashes = dict(declared_sources)
    source_hashes.update({path: sha256((ROOT/path).read_bytes()).hexdigest() for path in extra_sources})
    component_names = {
        "delta_I": "issuance_to_latent_dual_gate",
        "delta_E": "issuance_to_common_final_gate",
        "raw_ideal_gate_bottom": "raw_ideal_gate_bottom",
        "delta_S": "sign_attempt_to_sequential_ideal",
        "beta_M": "matrix_hash_failure", "beta_H": "identity_hash_failure",
        "ideal_sign_norm_reject": "ideal_sign_norm_reject",
    }
    return {
        "schema": "IBME/SRGG-HONEST-SERVICE-EXACT-BUDGET/1",
        "profile": "query-bounded-deep", "parameters": params, "Q": integrated["Q"],
        "verified_input_sha256": inputs,
        "verified_declared_source_sha256": declared_sources,
        "verified_by_load_inputs": {"input_receipts": len(inputs), "declared_sources": len(declared_sources)},
        "source_sha256": source_hashes,
        "exact_probability_encoding": "canonical hex numerator/denominator plus smallest dyadic upper exponent; decode with service_budget.unpack",
        "components": {key: budget.pack(components[value]) for key, value in component_names.items()},
        "hash_rejection_exact_inputs": {
            key: receipts["hash"][section]["exact_union_bound_factored"]
            for key, section in (("beta_M", "matrix_expansion"), ("beta_H", "identity_expansion"))},
        "scenarios": scenarios,
        "coefficient_guard": {
            "guard_bits": 256, "ticket_bits": tickets, "scalar_max_radius": radius,
            "series_inputs": series_inputs,
            "formulas": {
                "noise": "scale_hi*(4*D*(ticket_bits+1)+operator_rounding_error)",
                "perturbation": "ceil(noise)+scalar_max_radius+2",
                "digit": "(base-1)+base*(scalar_max_radius+2)",
                "raw": "P_master+digits*rank*degree*digit",
                "response": "P_sign+degree*isqrt(Ucap)*(2*(scalar_max_radius+2)+1)"},
            "coefficient_abs_upper": values,
            "coefficient_bit_lengths": {name: value.bit_length() for name, value in values.items()},
            "all_finite_paths_fit_downstream_guard": True,
            "key_coefficient_abs_upper": isqrt(params["user_norm_cap"]),
            "accepted_signature_coefficient_abs_upper": isqrt(params["signature_norm_cap"]),
            "accepted_signature_coefficient_bit_length": isqrt(params["signature_norm_cap"]).bit_length(),
            "scope": "finite outputs and deterministic linear partial sums under the stated correct-arithmetic model; not fault probability or elimination of existing sampler aborts"},
        "reproduce_command": "python docs/research/team-b-delivery/2026-10-16-srgg-joint-law/verify-honest-budget.py",
        "sampler_calls": 0, "random_bytes": 0, "sagemath_required": False,
        "scope": "conditional honest-service arithmetic; same-F cq sampler comparison and classical decoded-uniform comparison; no new full audit or quantum experiment",
        "hypotheses": ["fresh genesis or separately supplied full joint delta_hist", "independent uniform fresh sampler bytes", "correct exact/interval arithmetic", "same causal fault kernel excluding hidden sampler trace/timing/entropy", "classical Extract/Sign inputs", "classical hash comparison additionally assumes fresh ideal byte-XOF; quantum hash law switch is separate"],
        "unquantified_by_this_receipt": ["production SHAKE replacement", "entropy-source deviation", "infrastructure fault probability", "unknown external history provenance", "full QROM reduction and hardness"],
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(report(), indent=2, sort_keys=True)+"\n"
    if args.output is None:
        print(encoded, end="")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
