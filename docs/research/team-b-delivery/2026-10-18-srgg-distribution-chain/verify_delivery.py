"""Verify actual local LF-normalized files, algebra and scope without Sage.

No Git or entropy source is used; a copied delivery with its declared sources
is sufficient. Digest refresh cannot override the independent semantic checks.
"""
from __future__ import annotations

from fractions import Fraction
from hashlib import sha256
import json
import math
from pathlib import Path, PurePosixPath
import re
import sys

if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(0)

ROOT = Path(__file__).resolve().parents[4]
HERE = Path(__file__).resolve().parent
PREFIX = HERE.relative_to(ROOT).as_posix()
DELIVERY = "docs/research/team-b-delivery/"
PROFILES = ("PARAM-I", "PARAM-II", "PARAM-III")
INTERPRETATIONS = ("table-standard-deviation", "literal-density-width")
EXPECTED = {(p, i) for p in PROFILES for i in INTERPRETATIONS}
MODULES = (
    "paper_distribution_guard", "paper_distribution_chain", "paper_schur_backend",
    "paper_backend", "paper_parameters", "paper_profiles", "paper_objects",
    "paper_schur_samplef", "paper_schur_fourier", "paper_source_issuance_bridge",
    "paper_issuance_bridge", "paper_schur_finite_chain", "paper_schur_numerical",
    "paper_schur_normalizer", "paper_schur_convolution", "paper_schur_literal_moment",
    "paper_sign_budget", "paper_rounding_budget", "paper_setup_acceptance",
    "paper_setup_conditioning",
)
REQUIRED_DEPENDENCIES = frozenset(
    "experiments/research/candidates/srgg/" + name + ".py" for name in MODULES
) | frozenset((
    "src/ibme/ibs/srgg_paper_service.py", "src/ibme/ibs/srgg_paper/service.py",
    "src/ibme/ibs/srgg_paper/guarded.py", "papers/2025_efficient_ibs_jia.pdf",
))
REQUIRED_DELIVERY = frozenset((
    "README_zh-CN.md", "boundary-PARAM-I.json", "boundary-PARAM-II.json",
    "boundary-PARAM-III.json", "boundary_probe.py", "distribution-chain.json",
    "proof.md", "verify_delivery.py",
))
REQUIRED_FROZEN = frozenset(DELIVERY + name for name in (
    "2026-10-18-srgg-finite-chain/joint-fixed-root.json",
    "2026-10-18-srgg-source-issuance/source-issuance.json",
    "2026-10-18-srgg-history-law-followup/history-law.json",
    "2026-10-18-srgg-setup-acceptance/setup-acceptance.json",
))
REPORT_DEPENDENCIES = frozenset("experiments/research/candidates/srgg/" + name + ".py"
    for name in ("paper_schur_finite_chain", "paper_source_issuance_bridge",
                 "paper_schur_numerical", "paper_schur_backend",
                 "paper_setup_acceptance", "paper_issuance_bridge"))
SECURITY = {"security_claim": "none", "backend_admitted": False,
            "parameters_are_formal": False, "nist_security_category": None}
HISTORY_SCOPE = "logical_api_outputs_and_deterministic_persistent_state"
PAPER_SHA256 = "258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(
                          ValueError("non-finite JSON constant: " + value)))


def file_digest(path):
    data = path.read_bytes()
    if path.suffix in (".py", ".json", ".md", ".csv", ".txt", ".toml"):
        data = data.replace(b"\r\n", b"\n")
    return sha256(data).hexdigest()


def check_digests(mapping, expected, label):
    require(type(mapping) is dict and set(mapping) == set(expected), label + " path set differs")
    for name, digest in mapping.items():
        rel = PurePosixPath(name)
        require(not rel.is_absolute() and ".." not in rel.parts and "\\" not in name,
                label + " unsafe path")
        path = ROOT.joinpath(*rel.parts)
        require(path.is_file() and path.resolve().is_relative_to(ROOT.resolve()),
                label + " missing or escaped file: " + name)
        require(type(digest) is str and re.fullmatch("[0-9a-f]{64}", digest) is not None,
                label + " invalid digest")
        require(file_digest(path) == digest, label + " digest differs: " + name)


def check_security(record):
    for key, value in SECURITY.items():
        require(key in record and type(record[key]) is type(value) and record[key] == value,
                "unsafe or missing security field: " + key)


def fraction(value):
    require(type(value) is str, "exact fraction string required")
    return Fraction(value)


def dyadic(value):
    require(type(value) is str and re.fullmatch(r"2\^-\d{1,5}", value) is not None,
            "bounded dyadic string required")
    bits = int(value[3:])
    require(bits <= 16384, "dyadic exponent too large")
    return Fraction(1, 2**bits)


def check_report(path):
    report = _load(path)
    require(report["schema"] == "IBME/SRGG-PAPER-DISTRIBUTION-CHAIN/1", "chain schema differs")
    check_security(report)
    require(report["source_pdf"] == "papers/2025_efficient_ibs_jia.pdf" and
            report["source_sha256"] == PAPER_SHA256, "paper differs")
    require(report["scope"] == "independent SRGG IBS distribution chain; no HIBE" and
            report["scope_version"] == "mathematical_events_and_conditional_implemented_gates_v2",
            "distribution scope differs")
    require(report["source_parameters_unchanged"] is True and
            report["guard_is_service_change"] is True and
            report["independent_uniform_bytes_assumed"] is True, "required premises differ")
    history = report["history_scope"]
    require(history["included"] == HISTORY_SCOPE and history["actual_service_full_history_TV"] is None
            and history["matching_setup_or_conditioned_success_required"] is True,
            "actual/conditional history scope differs")
    require(set(history["excluded"]) == {
        "wall_clock_timing", "internal_sampler_or_runtime_traces",
        "unmodeled_disk_process_lock_rollback_or_power_faults"} and
        len(history["excluded"]) == 3, "history exclusions differ")
    for field in ("A_minus_B_upper_exact", "accepted_root_distribution_TV_upper_exact"):
        require(report["unguarded_original_backend"][field] is None, "legacy law must remain null")
    check_digests(report["dependency_sha256"], REPORT_DEPENDENCIES, "report source")
    rows = report["rows"]
    require(type(rows) is list and len(rows) == 6, "six rows required")
    seen = set()
    for row in rows:
        key = (row["profile"], row["interpretation"])
        require(key in EXPECTED and key not in seen, "unknown or duplicate row")
        seen.add(key)
        require(row["parameters"] == {"n": 512, "p": 16383, "b": 31, "w": 2,
                "Q": 15744063, "d": PROFILES.index(key[0]) + 2}, "Table 4 parameters differ")
        check_security(row["security"])
        c, b = row["good_root_constants"], row["bad_root_mass"]
        require((c["profile"], c["interpretation"]) == key and
                (b["profile"], b["interpretation"]) == key, "row identity mismatch")
        require(fraction(c["threshold_C_gate_squared_exact"]) <
                fraction(c["threshold_A_squared_exact"]) and
                fraction(c["threshold_C_gate_squared_exact"]) <
                fraction(c["threshold_schur_gate_squared_exact"]), "threshold order differs")
        require(fraction(c["uniform_schur_lower_bound_exact"]) > 64 and
                c["C_gate_implies_A"] is True and c["C_gate_implies_schur_floor"] is True,
                "ideal good-root implication differs")
        qa = fraction(b["A_rejection_one_attempt_upper_exact"])
        qc = fraction(b["C_gate_rejection_one_attempt_upper_exact"])
        tv = fraction(b["mathematical_mu_A_mu_G_tv_upper_exact"])
        require(0 < qa < qc < 1 and tv == qc / (1 - qa) and 0 < tv < 1,
                "mathematical conditioning identity differs")
        require(qc**64 <= dyadic(b["mathematical_G_64_retry_abort_upper_dyadic"]) and
                b["mathematical_G_64_retry_abort_below_2_minus_64"] is True and
                b["scope"] == "ideal mathematical G_C predicate; all G_C failures retried" and
                b["implemented_guard_retry_abort_upper"] is None, "mathematical retry scope differs")
        require("accepted_root_tv_upper_exact" not in b and
                "guarded_64_retry_abort_upper_dyadic" not in b, "stale actual-service labels")
        accepted = row["accepted_root_distribution"]
        for field in ("G_C_subset_B_legacy_certified", "uniform_implementation_preparation_error_upper",
                      "implemented_C_gate_inconclusive_shell_mass_upper", "A_minus_B_upper_exact",
                      "TV_mu_A_mu_B_upper_exact", "TV_mu_A_mu_B_upper_dyadic",
                      "TV_mu_A_mu_H_upper_exact", "original_backend_64_retry_abort_upper",
                      "guarded_64_retry_abort_dyadic"):
            require(accepted[field] is None, "unestablished implementation bound: " + field)
        composition = row["guarded_composition"]
        require(composition["scope"] == "conditional on H_setup, common signing guard and abort semantics"
                and composition["history_scope"] == HISTORY_SCOPE and
                composition["implemented_full_history_TV"] is None and
                composition["beta_bad_unguarded"] is None and
                composition["beta_bad_strictly_positive"] is True and row["fault_history"]["TV"] is None,
                "conditional composition scope differs")
        require("guarded_no_fault_history_TV" not in composition, "stale history scope")
        delta, epsilon = (composition["unguarded_key_TV_delta_issue"],
                          composition["good_key_one_call_TV_epsilon_good"])
        if delta is None or epsilon is None:
            require(all(composition[field] is None for field in (
                "guarded_issue_plus_1_sign_TV", "guarded_issue_plus_2_signs_TV",
                "conditional_logical_no_fault_history_TV")), "missing-premise composition must be null")
        else:
            d, e = fraction(delta), fraction(epsilon)
            require(0 <= d <= 1 and 0 <= e <= 1, "conditional probability out of range")
            for signs, field in ((1, "guarded_issue_plus_1_sign_TV"),
                                 (2, "guarded_issue_plus_2_signs_TV"),
                                 (2, "conditional_logical_no_fault_history_TV")):
                require(fraction(composition[field]) == min(1, d + signs * e),
                        "conditional composition identity differs")
        probe = row.get("lifecycle_probe")
        require(probe is not None, "frozen lifecycle receipt required")
        require((probe["profile"], probe["interpretation"]) == key, "lifecycle identity differs")
        require(all(probe[field] is True for field in ("functional_verified", "master_audit_certified",
                    "sign_audit_certified", "c_gate_certified", "object_envelope_certified")) and
                probe["setup_attempts"] == 1, "lifecycle gate failed")
    require(seen == EXPECTED, "profile/interpretation coverage differs")
    return report


def check_boundary(report, validation):
    expected = {"boundary-" + p + ".json" for p in PROFILES}
    require({p.name for p in HERE.glob("boundary-*.json")} == expected,
            "boundary receipt set differs")
    summaries = validation["boundary_probes"]
    require(len(summaries) == 3 and {row["profile"] for row in summaries} == set(PROFILES),
            "boundary validation coverage differs")
    checked = []
    for profile in PROFILES:
        data = _load(HERE / ("boundary-" + profile + ".json"))
        check_security(data)
        require(data["profile"] == profile and data["interpretation"] == "literal-density-width",
                "boundary profile differs")
        require(set(data["all_gates"]) == {"setup_returned", "c_gate", "master_audit",
                    "object_envelope", "verify"} and
                all(v is True for v in data["all_gates"].values()) and
                data["functional_pass"] is True, "boundary gate failed")
        require(data["scope"] == "one deterministic worst-case witness; not a probability or security proof",
                "boundary scope differs")
        row = next(r for r in report["rows"] if (r["profile"], r["interpretation"]) ==
                   (profile, "literal-density-width"))
        threshold = fraction(row["good_root_constants"]["threshold_C_gate_squared_exact"])
        require(fraction(data["threshold_C_squared_exact"]) == threshold, "boundary threshold differs")
        gap, largest = data["witness_gap_to_C"], data["witness_lambda_max"]
        require(type(gap) in (int, float) and type(largest) in (int, float) and
                math.isfinite(gap) and math.isfinite(largest) and gap > 0 and largest > 0 and
                math.isclose(float(threshold) - largest, gap, rel_tol=1e-8, abs_tol=1e-8),
                "boundary witness gap differs")
        require(data["samples_examined"] == 20000 and data["search_seed"] == 20261018 and
                data["setup_attempts"] == 1 and data["extract_calls"] == 1 and
                type(data["sign_attempts"]) is int and data["sign_attempts"] >= 1,
                "boundary execution counts differ")
        summary = next(r for r in summaries if r["profile"] == profile)
        require(all(data[k] == v for k, v in summary.items()), "boundary summary differs")
        checked.append("boundary-" + profile + ".json")
    return checked


def main():
    validation = _load(HERE / "validation.json")
    require(validation["schema"] == "IBME/SRGG-PAPER-DISTRIBUTION-CHAIN-VALIDATION/1",
            "validation schema differs")
    check_security(validation)
    files = validation["delivery_file_sha256"]
    require(type(files) is dict and set(files) == REQUIRED_DELIVERY, "delivery file set differs")
    check_digests({PREFIX + "/" + k: v for k, v in files.items()},
                  {PREFIX + "/" + k for k in REQUIRED_DELIVERY}, "delivery")
    require(validation["report_sha256"] == files["distribution-chain.json"], "report digest differs")
    check_digests(validation["current_dependency_sha256"], REQUIRED_DEPENDENCIES, "current source")
    check_digests(validation["frozen_receipts"], REQUIRED_FROZEN, "predecessor")
    require(file_digest(ROOT / "papers/2025_efficient_ibs_jia.pdf") == PAPER_SHA256,
            "frozen paper content differs")
    report = check_report(HERE / "distribution-chain.json")
    boundary = check_boundary(report, validation)
    print(json.dumps({"ok": True, "rows": 6, "boundary_receipts": boundary,
                      "current_dependencies": len(REQUIRED_DEPENDENCIES),
                      "scope": "mathematical root events and conditional logical APIs"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
