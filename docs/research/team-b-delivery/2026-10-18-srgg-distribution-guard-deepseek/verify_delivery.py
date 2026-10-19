"""Verify local LF-normalized receipts without Sage, Git, or new sampling.

Validation digests bind the actual local files, including uncommitted changes.
They are integrity receipts, not signatures: semantic checks independently
reject stale scopes and stronger security claims even after digest refresh.
"""
from __future__ import annotations

from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import re
import sys

if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(0)

ROOT = Path(__file__).resolve().parents[4]
PACKAGE = Path(__file__).resolve().parent
PREFIX = PACKAGE.relative_to(ROOT).as_posix()
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
REQUIRED_DIGESTS = frozenset(PREFIX + "/" + name for name in (
    "README_zh-CN.md", "distribution-guard.json", "proof.md", "verify_delivery.py",
)) | frozenset((
    "experiments/research/candidates/srgg/paper_distribution_guard.py",
    "tests/test_srgg_paper_distribution_guard.py",
))
REQUIRED_FROZEN = frozenset(DELIVERY + name for name in (
    "2026-10-18-srgg-finite-chain/finite-fixed-root.json",
    "2026-10-18-srgg-finite-chain/joint-fixed-root.json",
    "2026-10-18-srgg-source-issuance/source-issuance.json",
    "2026-10-18-srgg-history-law-followup/history-law.json",
))
SECURITY = {"security_claim": "none", "backend_admitted": False,
            "parameters_are_formal": False, "nist_security_category": None}
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
    require(type(mapping) is dict and set(mapping) == set(expected),
            label + " path set differs")
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


def row_map(report):
    rows = report["rows"]
    require(type(rows) is list and len(rows) == 6, "six rows required")
    mapped = {}
    for row in rows:
        key = (row["profile"], row["interpretation"])
        require(key in EXPECTED and key not in mapped, "unknown or duplicate row")
        mapped[key] = row
    require(set(mapped) == EXPECTED, "profile/interpretation coverage differs")
    return mapped


def probability(value):
    require(type(value) is str, "exact probability string required")
    result = Fraction(value)
    require(0 <= result <= 1, "probability outside [0,1]")
    return result


def check_report(report, joint, source, history):
    require(report["schema"] == "IBME/SRGG-PAPER-DISTRIBUTION-GUARD/1/REPORT",
            "guard schema differs")
    check_security(report)
    require(report["paper"] == {"path": "papers/2025_efficient_ibs_jia.pdf",
                                "sha256": PAPER_SHA256}, "paper differs")
    require(report["scope"] == "six original Table 4 roots; complete guarded accept set; "
            "uniform conditional bounds; gate-set masses remain null", "guard scope differs")
    require(type(report["complete_gate_set"]) is list and
            len(report["complete_gate_set"]) == 10 and
            len(set(report["complete_gate_set"])) == 10, "complete gate set differs")
    mapped, jm, sm, hm = (row_map(r) for r in (report, joint, source, history))
    for key, row in mapped.items():
        check_security(row)
        require(row["private_material_exported"] is False, "private export claimed")
        require(row["gate_floor"] == "64", "gate floor differs")
        require(row["guarded_backend_ran_audit_at_setup_and_sign"] is True and
                row["source_schur_backend_runs_audit"] is True and
                row["historical_unguarded_backend_runs_audit"] is False,
                "current/historical backend semantics differ")
        require("original_backend_runs_audit" not in row, "ambiguous original-backend tag")
        for field in ("root_gate_mass_under_actual_setup", "a_minus_b_event_mass",
                      "bad_issued_key_mass_beta", "full_history_tv", "fault_history_tv",
                      "implementation_root_law_tv_upper", "implementation_setup_64_attempt_abort_upper"):
            require(row[field] is None, "unestablished mass/history bound: " + field)
        require(row["history_observables"] == "logical_api_outputs_and_deterministic_persistent_state"
                and row["timing_and_internal_sampling_traces_included"] is False and
                row["full_history_formula_reference"] ==
                "legacy unguarded reference; not the same-guard logical comparison",
                "logical/historical history scope differs")
        require(row["bad_key_mass_strictly_positive"] is True, "bad key scope differs")
        require(row["setup_attempts"] == 1 and type(row["setup_attempts"]) is int and
                row["setup_gate_rejections"] == 0, "fixture attempt counts differ")
        params = row["paper_parameters"]
        require(set(params) == {"gadget_remainder_representative", "hnf_representative",
                "interpretation", "perturbation_noise_factor", "pi_precision_bits",
                "profile_name", "r_published_approximation", "source_sha256"},
                "paper parameter field set differs")
        require(params["profile_name"] == key[0] and params["interpretation"] == key[1]
                and params["source_sha256"] == PAPER_SHA256
                and params["perturbation_noise_factor"] == 1
                and params["pi_precision_bits"] == 512
                and params["r_published_approximation"] == "1.16"
                and params["gadget_remainder_representative"] == "centered-mod-p"
                and params["hnf_representative"] == "centered-mod-Q", "paper parameters differ")
        require(row["second_root_uniformity"]["master_joint_tv_identical"] is True and
                row["second_root_uniformity"]["same_gate_floor"] == "64",
                "second witness metadata differs")
        for phase in ("master_phase", "signature_phase"):
            require(row[phase]["closed"] is True and row[phase]["gate_floor"] == "64",
                    "conditional phase scope differs")
            probability(row[phase]["joint_tv_exact"])
        require(row["issuance_c_gate"]["certified"] is True and
                row["finite_key_object_guard"]["raw_and_key_within_256bit_object_guard"] is True,
                "fixture complete gates not certified")
        require(row["sign_call"]["sign_attempts_per_call"] == 64, "sign budget differs")
        if key[1] == "table-standard-deviation":
            for phase, frozen_phase in (("master_phase", "master"),
                                        ("signature_phase", "signature")):
                require(row[phase]["joint_tv_dyadic_upper"] ==
                        jm[key][frozen_phase]["finite_vs_joint_integer_gaussian_tv_dyadic_upper"]
                        and probability(row[phase]["joint_tv_exact"]) == probability(
                            jm[key][frozen_phase]["finite_vs_joint_integer_gaussian_tv_upper_exact"]),
                        "joint predecessor bound differs")
            require(row["issuance"]["closed"] is True and row["sign_call"]["closed"] is True,
                    "std conditional closure differs")
            require(row["issuance"]["complete_law_tv_upper_including_abort"] ==
                    sm[key]["complete_law_tv_upper_including_abort"], "issuance bound differs")
            require(row["sign_call"]["one_sign_call_tv_dyadic_upper"] ==
                    hm[key]["same_fixture_key_one_sign_call_tv_upper"], "sign bound differs")
        else:
            require(row["master_phase"]["joint_tv_dyadic_upper"] == "1" and
                    row["signature_phase"]["joint_tv_dyadic_upper"] == "1",
                    "literal bound must remain trivial")
            require(row["issuance"]["closed"] is False and
                    row["issuance"]["complete_law_tv_upper_including_abort"] is None and
                    row["sign_call"]["closed"] is False and
                    row["sign_call"]["one_sign_call_tv_dyadic_upper"] == "1",
                    "literal conditional limitations differ")
    probes = report["probes"]
    gap = probes["unguarded_gate_gap"]
    require(gap["status"] == "not_run_after_guard_unification" and
            gap["witness_found"] is None and type(gap["seeds_tried"]) is int and
            gap["seeds_tried"] == 0 and gap["enabled"] is False, "stale unguarded probe")
    sign = probes["sign_gate_mass"]
    require(sign["roots_attempted"] == 3 and sign["all_attempted_fixtures_accounted_for"] is True,
            "sign probe accounting differs")
    require(sign["sign_gate_accepts"] + sign["sign_gate_rejections"] == 3,
            "sign fixture counts differ")
    require(probes["scope"].startswith("deterministic fixture searches only"), "probe scope differs")
    return mapped


def main():
    validation = _load(PACKAGE / "validation.json")
    require(validation["schema"] == "IBME/SRGG-DISTRIBUTION-GUARD-VALIDATION/1",
            "validation schema differs")
    check_security(validation["security"])
    check_digests(validation["digests"], REQUIRED_DIGESTS, "delivery")
    check_digests(validation["frozen_receipts"], REQUIRED_FROZEN, "predecessor")
    check_digests(validation["current_dependency_sha256"], REQUIRED_DEPENDENCIES, "current source")
    require(file_digest(ROOT / "papers/2025_efficient_ibs_jia.pdf") == PAPER_SHA256,
            "frozen paper content differs")
    reports = [_load(ROOT / (DELIVERY + name)) for name in (
        "2026-10-18-srgg-finite-chain/joint-fixed-root.json",
        "2026-10-18-srgg-source-issuance/source-issuance.json",
        "2026-10-18-srgg-history-law-followup/history-law.json")]
    report = _load(PACKAGE / "distribution-guard.json")
    mapped = check_report(report, *reports)
    require(validation["probes"] == report["probes"], "validation probe summary differs")
    validated = row_map(validation)
    for key, row in validated.items():
        require(row["setup_attempts"] == mapped[key]["setup_attempts"] and
                row["setup_gate_rejections"] == mapped[key]["setup_gate_rejections"],
                "validation fixture differs")
        require(row["one_sign_call_dyadic_upper"] ==
                mapped[key]["sign_call"]["one_sign_call_tv_dyadic_upper"],
                "validation sign summary differs")
    print(json.dumps({"ok": True, "rows": 6, "current_dependencies": len(REQUIRED_DEPENDENCIES),
                      "scope": "conditional guarded gates; no security admission"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
