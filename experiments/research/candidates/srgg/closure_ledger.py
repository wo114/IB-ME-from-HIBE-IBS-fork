"""Consolidate the SRGG paper/code, finite-sampler, and condition audits.

This is an evidence index, not a security proof.  A field is only filled with a
number when an earlier receipt proves that number under its stated model.  A
conditional bound is kept separate from a production-game bound, and every
missing term remains ``None`` with a reason.  The module intentionally uses
only the standard library so the audit can be checked without Sage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


SCHEMA = "IBME/SRGG-CLOSURE-LEDGER/1"
PAPER_SHA256 = "258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def _load(root: Path, relative: str) -> tuple[dict[str, Any], str]:
    path = root / relative
    data = path.read_bytes()
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError(f"JSON object required: {relative}")
    return value, hashlib.sha256(data).hexdigest()


def _entry(status: str, *, value: str | None, reason: str,
           evidence: list[str], scope: str) -> dict[str, Any]:
    if status not in {"conditional", "unresolved", "closed"}:
        raise ValueError("invalid ledger status")
    if status == "unresolved" and value is not None:
        raise ValueError("unresolved ledger item cannot carry a production value")
    return {"status": status, "value": value, "reason": reason,
            "evidence": evidence, "scope": scope}


def _source_rows() -> list[dict[str, Any]]:
    return [
        {
            "item": "zeta_and_hnf_algebra",
            "paper_location": "pp.6-8, Algorithms 7-8",
            "implementation": [
                "experiments/research/candidates/srgg/paper_algebra.py",
                "experiments/research/candidates/srgg/paper_backend.py",
            ],
            "evidence": [
                "docs/research/team-b-delivery/2026-10-16-srgg-paper-baseline/SOURCE_MAP.md",
                "docs/research/team-b-delivery/2026-10-16-srgg-paper-baseline/validation.json",
            ],
            "status": "closed",
            "finding": "The public relation, 2Q recovery and centered HNF representative are checked by exact tests; this does not identify the output distribution.",
        },
        {
            "item": "published_parameters",
            "paper_location": "p.9 Section 5.1, p.10 Tables 4-7",
            "implementation": [
                "experiments/research/candidates/srgg/paper_profiles.py",
                "experiments/research/candidates/srgg/paper_parameters.py",
            ],
            "evidence": [
                "docs/research/team-b-delivery/2026-10-16-srgg-paper-baseline/SOURCE_MAP.md",
                "docs/research/team-b-delivery/2026-10-16-srgg-paper-baseline/validation.json",
            ],
            "status": "closed",
            "finding": "The three literal Table 4 parameter rows are executable inputs; the two Gaussian interpretations remain explicit alternatives.",
        },
        {
            "item": "gaussian_normalization_and_r",
            "paper_location": "pp.3,6,9",
            "implementation": [
                "experiments/research/candidates/srgg/paper_parameters.py",
                "experiments/research/candidates/srgg/source_correspondence.py",
            ],
            "evidence": [
                "docs/research/team-b-delivery/2026-10-16-srgg-paper-baseline/README_zh-CN.md",
                "docs/research/team-b-delivery/2026-10-16-srgg-qualification/source-eligibility.md",
            ],
            "status": "unresolved",
            "finding": "The paper reports r approximately 1.16 without fixing the covariance convention. The implementation preserves both interpretations and does not silently choose one as author intent.",
        },
        {
            "item": "factor1_vs_zeta_shape",
            "paper_location": "p.6 Table 3 and p.8 Algorithm 7",
            "implementation": [
                "experiments/research/candidates/srgg/paper_algebra.py",
                "experiments/research/candidates/srgg/paper_samplef.py",
            ],
            "evidence": [
                "docs/research/team-b-delivery/2026-10-16-srgg-paper-baseline/SOURCE_MAP.md",
            ],
            "status": "unresolved",
            "finding": "The algebra gives zeta*zeta*=2, while the displayed perturbation factor is retained literally as factor1; distributional equivalence is not established.",
        },
        {
            "item": "native_strong",
            "paper_location": "p.4 Definition 3 and pp.8-9 Theorem 2",
            "implementation": [
                "experiments/research/candidates/srgg/paper_backend.py",
                "experiments/research/candidates/srgg/paper_validation.py",
            ],
            "evidence": [
                "docs/research/team-b-delivery/2026-10-16-srgg-paper-baseline/PARAM-II.json",
                "docs/research/team-b-delivery/2026-10-16-srgg-paper-baseline/PARAM-III.json",
                "docs/research/team-b-delivery/2026-10-16-srgg-reduction/target-signing.md",
            ],
            "status": "unresolved",
            "finding": "PARAM-II and PARAM-III accepted same-message plus/minus-Q response replacements. This is a native-strong counterexample for those runs, not a fresh-message EUF forgery.",
        },
        {
            "item": "theorem_modulus_mapping",
            "paper_location": "p.4 Theorem 1 and p.9 Section 5.1",
            "implementation": [
                "experiments/research/candidates/srgg/paper_profiles.py",
                "experiments/research/candidates/srgg/source_correspondence.py",
            ],
            "evidence": [
                "docs/research/team-b-delivery/2026-10-16-srgg-qualification/source-eligibility.md",
                "docs/research/team-b-delivery/2026-10-16-srgg-bridge/theorem-obligations.md",
            ],
            "status": "unresolved",
            "finding": "The literal Q rows do not satisfy the displayed odd-q and q>2gamma condition, while verification is modulo 2Q. The paper-to-theorem modulus mapping is still open.",
        },
    ]


def _sampling_rows(root: Path) -> tuple[list[dict[str, Any]], dict[str, str]]:
    rows: list[dict[str, Any]] = []
    hashes: dict[str, str] = {}
    for relative in (
        "docs/research/team-b-delivery/2026-10-16-srgg-qualification/sampling-error-default.json",
        "docs/research/team-b-delivery/2026-10-16-srgg-qualification/sampling-error-width3.json",
    ):
        data, digest = _load(root, relative)
        hashes[relative] = digest
        parameter = data.get("parameters", {})
        profile = parameter.get("profile", parameter.get("profile_name", relative.rsplit("/", 1)[-1]))
        rows.append({
            "receipt": relative,
            "receipt_sha256": digest,
            "profile": profile,
            "interpretation": parameter.get("interpretation", "legacy research profile"),
            "extraction_tv_upper": data.get("extraction_vs_sequential_ideal_sampler_tv_upper_including_abort"),
            "sign_attempt_tv_upper": data.get("sign_attempt_vs_sequential_ideal_sampler_tv_upper_including_abort"),
            "max_sign_sequence_tv_upper": data.get("max_sign_attempt_sequence_tv_upper_including_abort"),
            "master_abort_upper": data.get("issuance_internal_sampling_abort_upper"),
            "sign_abort_upper": data.get("sign_attempt_internal_sampling_abort_upper"),
            "peikert_or_center_degenerates": {
                "extraction_output_law": data.get("raw_extraction_convolution_identified") is not True,
                "signature_output_law": data.get("signature_output_gaussian_identified") is not True,
                "full_service_abort": data.get("full_service_abort_upper") is None,
            },
            "scope": "finite sampler versus declared sequential reference, including internal sampler abort; not HNF/key/signature law or security advantage",
        })
    return rows, hashes


def _parameter_gates(root: Path) -> tuple[list[dict[str, Any]], str]:
    """Expose the exact source arithmetic that blocks theorem admission."""
    relative = "docs/research/team-b-delivery/2026-10-16-srgg-source-correspondence/source-correspondence.json"
    data, digest = _load(root, relative)
    rows = []
    for item in data.get("source_parameter_rows", []):
        source = item["source"]
        gamma = source["gamma"]
        # Decimal strings in this receipt are exact finite decimals.  Keeping
        # the subtraction as a string avoids silently changing the published
        # decimal into a binary float.
        from decimal import Decimal
        gap = Decimal(str(item["modulus_Q"])) - Decimal(str(item["twice_gamma"]))
        rows.append({
            "profile": source["name"],
            "rank": source["rank"],
            "Q": item["modulus_Q"],
            "gamma": gamma,
            "Q_minus_2gamma_exact_decimal": str(gap),
            "Q_is_odd": item["Q_is_odd"],
            "2Q_is_odd": item["twice_Q_is_odd"],
            "Q_gt_2gamma": item["literal_Q_gt_2gamma"],
            "2Q_gt_2gamma": item["literal_2Q_gt_2gamma"],
            "theorem_mapping": item["theorem1_interpretation"],
        })
    # The paper's quoted r is checked against the displayed necessary
    # smoothing condition with a rational lower bound.  This is intentionally
    # a necessary-condition failure check, not a sufficient parameter proof.
    epsilon_denominator = 2**24
    smoothing = []
    for item in rows:
        degree = 512
        dimension = 4 * (item["rank"] + 1) * degree
        lower_numerator, lower_denominator = 2 * dimension, 243
        smoothing.append({
            "profile": item["profile"],
            "dimension": dimension,
            "literal_r": "1.16",
            "epsilon": "2^-24",
            "dual_mass_lower_bound": f"{lower_numerator}/{lower_denominator}",
            "necessary_condition_fails": lower_numerator * epsilon_denominator > lower_denominator,
            "scope": "necessary-condition check for the literal width; author normalization remains unresolved",
        })
    return [{"parameter_gate": row, "literal_smoothing_check": smooth}
            for row, smooth in zip(rows, smoothing)], digest


def _parameter_source_audit(root: Path) -> tuple[dict[str, Any], str]:
    """Load the exact source-symbol audit without promoting its gates."""

    relative = "docs/research/team-b-delivery/2026-10-17-srgg-parameter-closure/parameter-closure.json"
    data, digest = _load(root, relative)
    if data.get("schema") != "IBME/SRGG-PARAMETER-CLOSURE/1":
        raise ValueError("unexpected SRGG parameter closure schema")
    status = data.get("global_status")
    if not isinstance(status, dict) or status.get("security_claim") != "none":
        raise ValueError("parameter closure must remain a non-admission receipt")
    rows = []
    for row in data.get("rows", []):
        modulus = row["modulus_gates"]
        rows.append({
            "profile": modulus["profile"],
            "Q": modulus["Q"],
            "mapping_status": modulus["mapping_status"],
            "modulus_candidates": modulus["modulus_candidates"],
            "smoothing": row["smoothing"],
            "physical_stddev_diagnostic": row["physical_stddev_diagnostic"],
        })
    return {
        "receipt": relative,
        "receipt_sha256": digest,
        "source_constants": data.get("source_constants"),
        "epsilon_parses": data.get("epsilon_parses"),
        "rows": rows,
        "global_status": status,
        "scope": data.get("scope"),
    }, digest


def _ledger() -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    evidence = {
        "conditional": [
            "experiments/research/candidates/srgg/integrated_bridge.py",
            "docs/research/team-b-delivery/2026-10-16-srgg-joint-law/honest-service-law.md",
        ],
        "sampling": [
            "experiments/research/candidates/srgg/sampling_error.py",
            "docs/research/team-b-delivery/2026-10-16-srgg-qualification/sampling-error-review.md",
        ],
        "classical": [
            "experiments/research/candidates/srgg/bounded_classical_cost.py",
            "docs/research/team-b-delivery/2026-10-16-srgg-reduction/strong-games.md",
        ],
    }
    scope = "conditional component only; not a production IBS game bound"
    ledger = {
        "delta0": _entry("unresolved", value=None, reason="Genesis, prior history, OS/SHAKE behavior, source caps and service faults are not jointly coupled to one production game.", evidence=evidence["conditional"], scope=scope),
        "delta_issue": _entry("conditional", value="<=2^-177", reason="Deep structured namespace issuance-to-reference bridge under its explicit model; public FixedIssuer and full production law are not identified.", evidence=evidence["conditional"], scope=scope),
        "delta_bad": _entry("conditional", value="<=2^-256", reason="GoodKey tail under mixed ideal key law only; actual seeded/HNF key law remains open.", evidence=evidence["conditional"], scope=scope),
        "delta_alias": _entry("unresolved", value=None, reason="Uniform-H1 alias formula is conditional; actual Hbar identity/image law and cross-identity state are not closed.", evidence=evidence["classical"], scope=scope),
        "epsilon_image": _entry("conditional", value="exact conditional bound in integrated_bridge receipt", reason="The bound applies to the mixed-domain explicit-Ahat reference and norm gate, not the seeded production IBS.", evidence=evidence["conditional"], scope=scope),
        "delta_pub": _entry("conditional", value="<=2^-177 (issue), <=2^-178 (sign attempt)", reason="Finite sampler receipts cover the declared sequential reference; they do not identify the final HNF or signature law.", evidence=evidence["sampling"], scope=scope),
        "commitment_collision": _entry("conditional", value="full-cap ideal entropy alpha=36351 bits", reason="The collision calculator uses only 512 bits and an illustrative free-entry count; it is not an actual IBS query bound.", evidence=evidence["classical"], scope=scope),
        "delta_zk": _entry("conditional", value="4667/2^256", reason="GoodKey zero-knowledge tail under the declared ideal reference.", evidence=evidence["classical"], scope=scope),
        "eta_sign": _entry("conditional", value="<=2/2^256", reason="Ideal signing norm/rejection term under the declared ideal reference; actual service retries and failure interface remain separate.", evidence=evidence["classical"], scope=scope),
        "delta_sim": _entry("conditional", value="<=2^-178 per sign attempt", reason="Structured sign sampler comparison under the deep research profile only.", evidence=evidence["sampling"], scope=scope),
        "delta_known": _entry("unresolved", value=None, reason="Non-target known-key signatures and their complete H2/internal retry transcript are not certified against the same production game.", evidence=evidence["classical"], scope=scope),
        "delta_overlay": _entry("unresolved", value=None, reason="Seed prehistory, public matrix overlay, adaptive H1/QROM programming and infrastructure failures are not jointly bounded.", evidence=evidence["conditional"], scope=scope),
    }
    premises = {
        "complete_honest_reference": {"satisfied": False, "reason": "Only component references exist; the complete production transcript is not coupled."},
        "hidden_index_independent_common_space": {"satisfied": False, "reason": "Target-index and full service coupling remain conditional."},
        "uniform_reachable_history_bounds": {"satisfied": False, "reason": "Uniform bounds for all adaptive histories are not certified."},
        "canonical_native_strong_log": {"satisfied": False, "reason": "The strong target is retained, but native strong has observed same-message replacements."},
        "independent_uniform_target": {"satisfied": False, "reason": "Actual identity/image distribution is not uniform by a closed production proof."},
        "ideal_classical_free_h2": {"satisfied": False, "reason": "The owner/fork arithmetic assumes it; the complete production router is not implemented."},
        "raw_first_touch_consistent": {"satisfied": True, "reason": "The classical conditional-XOF component fixes first-touch prefixes and suffixes under its stated model."},
        "replayable_nonfree_and_callback": {"satisfied": False, "reason": "Target-sign callback and all failure paths are not certified as replayable in the real game."},
        "two_run_source_byte_envelope": {"satisfied": False, "reason": "The bounded runner has a finite input/source certificate, but not a complete production-service envelope."},
        "same_bounded_game_and_failure_interfaces": {"satisfied": False, "reason": "Service, OS, SHAKE and simulator failure interfaces are not unified."},
        "specified_source_and_arithmetic_model": {"satisfied": True, "reason": "The receipts declare the byte-XOF, Sage arithmetic and finite-resource model used by each component."},
    }
    return ledger, premises


def build_report(root: Path | None = None) -> dict[str, Any]:
    root = _repo_root() if root is None else Path(root)
    paper = root / "papers/2025_efficient_ibs_jia.pdf"
    if hashlib.sha256(paper.read_bytes()).hexdigest() != PAPER_SHA256:
        raise ValueError("SRGG paper digest differs from the frozen reviewed version")
    sampling, receipt_hashes = _sampling_rows(root)
    parameter_gates, source_receipt_hash = _parameter_gates(root)
    receipt_hashes["docs/research/team-b-delivery/2026-10-16-srgg-source-correspondence/source-correspondence.json"] = source_receipt_hash
    parameter_source_audit, parameter_source_hash = _parameter_source_audit(root)
    receipt_hashes["docs/research/team-b-delivery/2026-10-17-srgg-parameter-closure/parameter-closure.json"] = parameter_source_hash
    ledger, premises = _ledger()
    unresolved = [name for name, value in ledger.items() if value["status"] == "unresolved"]
    return {
        "schema": SCHEMA,
        "generator": {
            "path": "experiments/research/candidates/srgg/closure_ledger.py",
            "sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        },
        "paper": {"path": "papers/2025_efficient_ibs_jia.pdf", "sha256": PAPER_SHA256},
        "scope": "SRGG items 2-4: source/code correspondence, finite sampler error, and remaining classical/QROM/parameter conditions",
        "source_code_rows": _source_rows(),
        "sampling_receipts": sampling,
        "parameter_gates": parameter_gates,
        "parameter_source_audit": parameter_source_audit,
        "ibs_ledger": ledger,
        "premises": premises,
        "unresolved_ledger_terms": unresolved,
        "closure": {
            "source_code_correspondence": "partial",
            "finite_sampler_reference": "conditional",
            "complete_classical_production_reduction": False,
            "qrom_reduction": False,
            "hardness_and_formal_parameters": False,
            "native_strong_security": False,
            "security_claim": "none",
            "backend_admitted": False,
            "parameters_are_formal": False,
            "nist_security_category": None,
        },
        "receipt_sha256": receipt_hashes,
        "limits": [
            "A conditional TV bound is not a measured TV distance and is not an IBS security advantage.",
            "The native-strong same-message Q-shift observation is retained; it is not relabeled as a fresh-message forgery.",
            "The QROM row, H1/H2 programming, ring-HNF collapsing, hardness estimates and HIBE composition remain open.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(build_report(args.root), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8", newline="\n")
    print(encoded, end="")


if __name__ == "__main__":
    main()
