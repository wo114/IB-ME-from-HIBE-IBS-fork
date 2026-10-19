"""Unified HIBE-independent SRGG parameter-completion ledger.

The repository already has separate receipts for source correspondence,
finite sampler bounds, hardness comparators, CRT projections and service
budgets.  This module joins only their public summaries so a reviewer can see
which parts of parameter closure are executable, conditional, or still open.
It never runs a secret-key sampler, reads private payloads, changes a profile,
or turns a heuristic estimate into a security claim.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
from fractions import Fraction
import hashlib
import json
from pathlib import Path
from typing import Any

from experiments.research.primitive_spec_audit import SRGG_ROWS

from .crt_projection import projection_certificate
from .formal_candidates import Candidate, resource_model
from .issuance_analysis import finite_gaussian_hnf_counterexample, rare_success_counterexample
from .paper_profiles import profiles
from .spectral_bounds import public_t_squared_upper
from .strong_structure import quotient_certificate


SCHEMA = "IBME/SRGG-PARAMETER-COMPLETION/1"
ROOT = Path(__file__).resolve().parents[4]
PAPER = ROOT / "papers/2025_efficient_ibs_jia.pdf"
PAPER_SHA256 = "258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152"
HARDNESS_RECEIPT = ROOT / "docs/research/team-b-delivery/2026-10-16-srgg-hardness/finite-search.json"
HARDNESS_VALIDATION = ROOT / "docs/research/team-b-delivery/2026-10-16-srgg-hardness/validation.json"
N512_RECEIPT = ROOT / "docs/research/team-b-delivery/2026-10-16-srgg-bridge/structured-execution-n512-d2w8.json"


def _read_json(path: Path) -> Any:
    if not path.is_file() or path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError(f"missing or oversized public receipt: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _safe(value: Any) -> Any:
    """Encode exact fractions for JSON without converting them to floats."""
    if isinstance(value, Fraction):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _safe(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_safe(v) for v in value]
    return value


def _source_sizes() -> dict[str, Any]:
    """Keep Table 1 and Table 4 size namespaces separate."""
    result = []
    for row, profile in zip(SRGG_ROWS, profiles):
        report = profile.author_report
        if row["name"] != profile.name or int(row["rank"]) != profile.rank:
            raise ValueError("source row/profile identity mismatch")
        if str(row["gamma"]) != str(profile.gamma):
            raise ValueError("source gamma mismatch")
        table4 = {
            "master_public_bytes": report.master_public_bytes,
            "master_secret_bytes": report.master_secret_bytes,
            "user_secret_bytes": report.user_secret_bytes,
            "signature_bytes": report.signature_bytes,
        }
        table1 = {
            "target_bits": report.target_bits,
            "master_public_bytes": row["table1_mpk"],
            "signature_bytes": row["table1_signature"],
            "extract_cycles": report.extract_cycles,
            "sign_cycles": report.sign_cycles,
            "forgery_classical_bits": report.forgery_classical_bits,
            "forgery_quantum_bits": report.forgery_quantum_bits,
        }
        return_row = {
            "name": profile.name,
            "rank": profile.rank,
            "table1_summary": table1,
            "table4_parameters_and_sizes": table4,
            "table1_mpk_equals_table4_mpk": table1["master_public_bytes"] == table4["master_public_bytes"],
            "table1_signature_equals_table4_signature": table1["signature_bytes"] == table4["signature_bytes"],
            "difference_explanation": None,
            "source_size_namespace_is_preserved": True,
        }
        result.append(return_row)
    return {
        "rows": result,
        "table1_and_table4_are_distinct_source_views": True,
        "difference_explanation": "The paper reports two size tables with different values; no compression or error cause is inferred.",
        "author_cycle_environment_reproduced": False,
    }


def _candidate_row(receipt: dict[str, Any], *, degree: int, rank: int, base: int, digits: int) -> dict[str, Any]:
    if degree == 512 and rank == 2 and base == 31 and digits == 8:
        row = receipt.get("current_research_point")
    else:
        row = next((item for item in receipt.get("selected_candidates", [])
                    if item.get("parameters", {}).get("degree") == degree
                    and item["parameters"].get("rank") == rank
                    and item["parameters"].get("base") == base
                    and item["parameters"].get("digits") == digits), None)
    if not isinstance(row, dict) or not isinstance(row.get("parameters"), dict):
        raise ValueError("requested public hardness candidate is absent")
    return row


def _resource_summary() -> dict[str, Any]:
    receipt = _read_json(HARDNESS_RECEIPT)
    validation = _read_json(HARDNESS_VALIDATION)
    expected = validation.get("artifacts_sha256", {}).get("finite-search.json")
    actual = hashlib.sha256(HARDNESS_RECEIPT.read_bytes()).hexdigest()
    if expected != actual:
        raise ValueError("hardness receipt hash differs from its validation manifest")
    rows = []
    for label, source in (
        ("n512-d2-b31-w8", _candidate_row(receipt, degree=512, rank=2, base=31, digits=8)),
        ("n2048-d3-b3-w22", _candidate_row(receipt, degree=2048, rank=3, base=3, digits=22)),
    ):
        candidate = Candidate(**source["parameters"])
        modeled = resource_model(candidate)
        extraction_dimension = modeled["master_geometry"]["coefficient_dimension"]
        signing_dimension = modeled["signature_geometry"]["coefficient_dimension"]
        execution_checks = {
            "degree_le_512_structured_execution_cap": candidate.degree <= 512,
            "rank_le_4_execution_cap": candidate.rank <= 4,
            "digits_le_8_execution_cap": candidate.digits <= 8,
            "modulus_bits_le_128_execution_cap": candidate.modulus.bit_length() <= 128,
            "signing_dimension_le_32768_structured_sampler_cap": signing_dimension <= 32768,
            "witness_coefficients_le_2pow20_geometry_cap": (
                2 * candidate.rank * candidate.rank * candidate.digits * candidate.degree <= 2**20
            ),
        }
        rows.append({
            "label": label,
            "candidate_name": candidate.name,
            "parameters": asdict(candidate),
            "Q": candidate.modulus,
            "coefficient_dimensions": {
                "extraction": extraction_dimension,
                "signing": signing_dimension,
            },
            "modeled_payload_bytes": modeled["hypothetical_fixed_width_component_payload_bytes"],
            "ring_operation_counts": modeled["schoolbook_ring_arithmetic"],
            "runtime_observation": modeled["runtime_observations"],
            "execution_limits": {
                "structured_execution_degree_max": 512,
                "structured_samplef_dimension_max": 32768,
                "geometry_witness_coefficients_max": 2**20,
                "checks": execution_checks,
                "legacy_dense_config_dimension_le_128_comparator": signing_dimension <= 128,
                "status": (
                    "listed_static_guards_pass_only"
                    if all(execution_checks.values())
                    else "rejected_by_listed_static_guards"
                ),
                "complete_runtime_preflight_performed": False,
                "unchecked_runtime_gates": [
                    "all remaining ExecutionParams inequalities and exact types",
                    "prepared witness residual, series terms and rational-center limits",
                    "whole sampler and retry entropy budgets",
                    "objects, wire and service snapshot budgets",
                ],
            },
            "execution_status": (
                "n512_receipt_exists_but_candidate_resource_model_is_static"
                if candidate.degree == 512 else "preflight_only_current_execution_params_cap_degree_at_512"
            ),
            "heuristic_attack_estimates_are_not_repeated_here": True,
        })
    n512_manifest = _read_json(N512_RECEIPT.parent / "MANIFEST.json")
    relative = N512_RECEIPT.relative_to(ROOT).as_posix()
    frozen = next(item for item in n512_manifest["files"] if item["path"] == relative)
    n512_bytes = N512_RECEIPT.read_bytes()
    n512_hash = hashlib.sha256(n512_bytes).hexdigest()
    if len(n512_bytes) != frozen["bytes"] or n512_hash != frozen["sha256"]:
        raise ValueError("n512 execution receipt differs from frozen manifest")
    n512 = _read_json(N512_RECEIPT)
    return {
        "hardness_receipt_sha256": actual,
        "hardness_receipt_manifest_match": True,
        "rows": rows,
        "n512_execution_receipt": {
            "path": relative,
            "sha256": n512_hash,
            "manifest_match": True,
            "schema": n512["schema"],
            "completed": n512["completed"],
            "actual_entropy_bytes": n512["actual_entropy_bytes"],
            "peak_rss_KiB": n512["peak_rss_KiB"],
            "security_claim": n512["security_claim"],
            "parameters_are_formal": n512["parameters_are_formal"],
        },
        "n2048_execution_performed": False,
        "peak_memory_is_modeled_for_candidates_and_measured_only_for_n512": True,
    }


def _theorem_secondary_gate() -> dict[str, Any]:
    """Keep the displayed ``s1*eta`` gate separate from the unresolved q map."""
    rows = []
    for profile in profiles:
        s1 = Fraction(profile.signature_first_stddev)
        r = profile.r_stddev
        product = s1 * r
        Q = profile.Q
        rows.append({
            "name": profile.name,
            "s1_source_value": str(s1),
            "s1_candidate_source": "Table 4 signature sigma_bar1; response ellipse in Section 3.1/Theorem 1",
            "eta_r_source_value": str(r),
            "s1_times_eta_r": str(product),
            "Q_candidate": Q,
            "conditional_Q_gt_s1_eta_r": Q > product,
            "conditional_gate_margin": str(Fraction(Q) - product),
            "physical_stddev_two_widths_product_upper": str(Fraction(44, 7) * product),
            "physical_stddev_conversion_bound": "2*pi < 44/7 applied to both s1 and eta width conversions",
            "conditional_Q_gt_converted_product_upper": Q > Fraction(44, 7) * product,
            "q_mapping_to_Q_verified": False,
            "s1_symbol_mapping_formally_verified": False,
            "r_precision_and_normalization_verified": False,
            "formal_theorem1_gate_closed": False,
        })
    return {
        "rows": rows,
        "interpretation": "conditional arithmetic only: response width sigma_bar1, rounded r, both literal-width and physical-stddev conversions; exact source mapping remains open",
        "all_conditional_Q_gt_s1_eta_r": all(row["conditional_Q_gt_s1_eta_r"] for row in rows),
        "formal_gate_closed": False,
    }


def _structure_summary() -> dict[str, Any]:
    rows = []
    for label, degree, rank, digits in (("n512-d2-w8", 512, 2, 8), ("n2048-d3-w22", 2048, 3, 22)):
        columns = rank * digits
        projection = projection_certificate(degree=degree, rank=rank, columns=columns)
        challenge = quotient_certificate(degree)
        rows.append({
            "label": label,
            "degree": degree,
            "rank": rank,
            "digits": digits,
            "columns": columns,
            "mod3_one_factor_tv_bits": projection["one_factor_tv_dyadic_bits_lower"],
            "mod3_full_ring_tv_bits": projection["full_mod3_tv_dyadic_bits_lower"],
            "mod3_shared_column_tv_bits": projection["full_mod3_shared_columns_tv_dyadic_bits_lower"],
            "mod3_projection_scope": {
                "both_crt_factors_jointly_covered": projection["both_CRT_factors_jointly_covered"],
                "prime_power_covered": projection["prime_power_3_to_w_covered"],
                "other_prime_factors_covered": projection["other_prime_factors_covered"],
                "pointwise_in_Ahat": projection["tv_bound_pointwise_for_every_Ahat"],
            },
            "challenge_effective_bits": challenge["effective_challenge_bits"],
            "same_coset_success_probability": challenge["independent_uniform_same_coset_probability_exact"],
            "strong_reduction_closed": False,
            "ring_hnf_msis_attack_cost_closed": False,
            "public_cbd1_spectral_squared_upper": str(public_t_squared_upper(degree, rank, digits)),
        })
    return {
        "rows": rows,
        "interpretation": "exact public projection and quotient counts only; projected secret/error laws and efficient attacks remain open",
        "structured_attack_estimate_closed": False,
        "ring_hnf_msis_correspondence_closed": False,
    }


def _finite_law_summary() -> dict[str, Any]:
    hnf = finite_gaussian_hnf_counterexample()
    conditioning = rare_success_counterexample()
    return {
        "toy_hnf_probe": _safe(hnf),
        "shared_filter_probe": _safe(conditioning),
        "toy_probe_is_actual_srgg_sampler": False,
        "n512_hnf_key_distribution_identified": False,
        "n512_final_signature_law_identified": False,
        "finite_samplef_to_hnf_bridge_closed": False,
        "reason": "exact finite pushforward helpers show the required law and conditioning inputs, but the production SRGG sampler law is not an explicit finite table",
    }


def build_report() -> dict[str, Any]:
    paper_sha = hashlib.sha256(PAPER.read_bytes()).hexdigest()
    if paper_sha != PAPER_SHA256:
        raise ValueError("SRGG paper digest differs from frozen review")
    return {
        "schema": SCHEMA,
        "paper": {"path": str(PAPER.relative_to(ROOT)).replace("\\", "/"), "sha256": paper_sha},
        "scope": "HIBE-independent SRGG parameter closure continuation",
        "source_table_mapping": _source_sizes(),
        "theorem_secondary_gate": _theorem_secondary_gate(),
        "resource_preflight": _resource_summary(),
        "structure_and_attack_boundaries": _structure_summary(),
        "finite_law_and_hnf_boundary": _finite_law_summary(),
        "service_abort_boundary": {
            "conditional_algorithm_abort_composition_lemma_available": True,
            "historical_numerical_receipts_revalidated_after_endpoint_fix": False,
            "full_service_abort_including_IO_crash_and_runtime_fault": None,
            "reason": "historical interval-derived finite errors require revalidation; filesystem/crash/runtime fault probability also has no declared model",
        },
        "global_status": {
            "source_tables_mapped": True,
            "listed_static_resource_checks_complete": True,
            "complete_runtime_resource_preflight_closed": False,
            "finite_sampler_to_hnf_closed": False,
            "ring_hnf_msis_closed": False,
            "crt_and_subfield_structured_attacks_closed": False,
            "native_strong_rom_qrom_closed": False,
            "security_claim": "none",
            "parameters_are_formal": False,
            "backend_admitted": False,
            "nist_security_category": None,
        },
        "remaining_independent_tasks": [
            "derive a production SampleF-to-HNF key law or a theorem-level coupling with explicit abort conditioning",
            "complete ring-HNF/MSIS, CRT/subfield and structured attack models with the projected secret/error law",
            "close the external failure model before claiming a complete service abort budget",
            "finish native-strong ROM/QROM target-identity simulation and its query losses",
            "run a full lifecycle on any candidate that passes the preceding proof and resource gates",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(_safe(report), ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"schema": report["schema"], "security_claim": "none", "parameters_are_formal": False}))


if __name__ == "__main__":
    main()
