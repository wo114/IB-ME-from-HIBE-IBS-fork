"""Check SRGG source-Schur issuance delivery bytes and narrow claim scope."""
from __future__ import annotations

from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PREFIX = "docs/research/team-b-delivery/2026-10-18-srgg-source-issuance/"
FINITE_PREFIX = "docs/research/team-b-delivery/2026-10-18-srgg-finite-chain/"
FINITE_MANIFEST = FINITE_PREFIX + "MANIFEST.json"
PREVIOUS_MANIFEST = "docs/research/team-b-delivery/2026-10-18-srgg-source-schur/MANIFEST.json"
FINITE_MANIFEST_LF_SHA256 = "698bdeaa45979c69766233b9ba008ac6fca9bae62b7482cd77b8033b49c2142b"
PREVIOUS_MANIFEST_SHA256 = "1210d3306053a2f69ccf463406206e25ceff96cca00f25917e966b4aefabba22"
SCHEMA = "IBME/SRGG-SOURCE-SCHUR-ISSUANCE-DELIVERY-MANIFEST/1"
SOURCE = "experiments/research/candidates/srgg/paper_source_issuance_bridge.py"
GUARD_SOURCE = "experiments/research/candidates/srgg/paper_distribution_guard.py"
REQUIRED = {
    SOURCE,
    "tests/test_srgg_paper_source_issuance_bridge.py",
    PREFIX + "README.md",
    PREFIX + "README_zh-CN.md",
    PREFIX + "source-issuance.json",
    PREFIX + "validation.json",
    PREFIX + "verify_delivery.py",
    FINITE_MANIFEST,
    PREVIOUS_MANIFEST,
}
FINITE_DEPENDENCIES = {
    FINITE_PREFIX + "finite-fixed-root.json",
    FINITE_PREFIX + "joint-fixed-root.json",
    FINITE_PREFIX + "proof.md",
    "experiments/research/candidates/srgg/paper_schur_finite_chain.py",
    "experiments/research/candidates/srgg/paper_schur_joint_bound_audit.py",
    "experiments/research/candidates/srgg/paper_schur_convolution.py",
    "experiments/research/candidates/srgg/paper_schur_literal_moment.py",
    "experiments/research/candidates/srgg/paper_schur_normalizer.py",
    "experiments/research/candidates/srgg/paper_rounding_budget.py",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def file_at(name):
    require(type(name) is str and name and "\\" not in name, "noncanonical manifest path")
    relative = Path(name)
    require(not relative.is_absolute() and all(part not in ("", ".", "..")
                                               for part in relative.parts), "unsafe manifest path")
    path = (ROOT / relative).resolve()
    require(path.is_relative_to(ROOT) and path.is_file(), "missing or escaped package file")
    return path


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def delivery_bytes(name):
    raw = file_at(name).read_bytes()
    if name == FINITE_MANIFEST:
        # This already committed manifest was generated with CRLF in this
        # Windows worktree, while Git stores/archives LF.  Bind the Git LF
        # bytes and accept only a strict CRLF-to-LF normalization locally.
        require(raw.count(b"\r") == raw.count(b"\r\n"),
                "finite manifest has noncanonical line endings")
        return raw.replace(b"\r\n", b"\n")
    return raw


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def safety(value):
    require(value.get("security_claim") == "none" and
            value.get("backend_admitted") is False and
            value.get("parameters_are_formal") is False and
            value.get("nist_security_category") is None,
            "formal security marker drift")


def verify_entries(entries):
    require(type(entries) is dict, "manifest entries required")
    for name, expected in entries.items():
        require(type(expected) is dict and set(expected) == {"bytes", "sha256"} and
                type(expected["bytes"]) is int and expected["bytes"] >= 0 and
                type(expected["sha256"]) is str and len(expected["sha256"]) == 64,
                "manifest entry structure")
        raw = delivery_bytes(name)
        require(len(raw) == expected["bytes"] and
                sha256(raw).hexdigest() == expected["sha256"],
                "package byte mismatch: " + name)


def main():
    package = read_json(HERE / "MANIFEST.json")
    require(package.get("schema") == SCHEMA and REQUIRED <= set(package.get("entries", {})),
            "source issuance package coverage")
    verify_entries(package["entries"])

    validation = read_json(HERE / "validation.json")
    receipt_path = HERE / "source-issuance.json"
    require(validation.get("receipt_sha256") == digest(receipt_path) and
            validation.get("targeted_tests", {}).get("passed") >= 12 and
            validation.get("targeted_tests", {}).get("failed") == 0 and
            validation.get("security_claim") == "none", "validation record drift")

    finite_manifest_bytes = file_at(FINITE_MANIFEST).read_bytes()
    require(finite_manifest_bytes.count(b"\r") == finite_manifest_bytes.count(b"\r\n"),
            "finite manifest line ending drift")
    normalized = finite_manifest_bytes.replace(b"\r\n", b"\n")
    require(sha256(normalized).hexdigest() == FINITE_MANIFEST_LF_SHA256,
            "finite-chain normalized manifest bytes changed")
    finite_manifest = json.loads(finite_manifest_bytes)
    require(finite_manifest.get("schema") == "IBME/SRGG-FINITE-CHAIN-DELIVERY-MANIFEST/1" and
            FINITE_DEPENDENCIES <= set(finite_manifest.get("entries", {})),
            "finite-chain dependency coverage")
    finite_entries = finite_manifest["entries"]
    verify_entries(finite_entries)
    require(digest(file_at(PREVIOUS_MANIFEST)) == PREVIOUS_MANIFEST_SHA256,
            "inherited source manifest bytes changed")
    finite_report = read_json(file_at(FINITE_PREFIX + "finite-fixed-root.json"))
    joint_report = read_json(file_at(FINITE_PREFIX + "joint-fixed-root.json"))
    receipt = read_json(receipt_path)
    safety(receipt)
    require(receipt.get("schema") == "IBME/SRGG-SOURCE-SCHUR-FIXED-ROOT-ISSUANCE-REPORT/1" and
            receipt.get("source_sha256") == {SOURCE: digest(file_at(SOURCE)),
                                             GUARD_SOURCE: digest(file_at(GUARD_SOURCE))} and
            receipt.get("paper") == {"path": "papers/2025_efficient_ibs_jia.pdf",
                                      "sha256": digest(file_at("papers/2025_efficient_ibs_jia.pdf"))},
            "source/paper report binding")
    require(receipt.get("fixed_root_standard_interpretation_nontrivial_rows") == 3 and
            receipt.get("literal_density_complete_issuance_bounds") is None and
            receipt.get("all_accepted_setup_roots_tv") is None and
            receipt.get("full_issuance_signature_fault_history_tv") is None and
            receipt.get("native_strong_security_proven") is False and
            receipt.get("private_material_exported") is False,
            "aggregate scope drift")

    rows = receipt.get("rows")
    require(type(rows) is list and len(rows) == len(finite_report.get("rows", ())) ==
            len(joint_report.get("rows", ())) == 6, "six fixed-root issuance rows required")
    for index, (row, finite_row, joint_row) in enumerate(zip(rows, finite_report["rows"],
                                                          joint_report["rows"])):
        profile = ("PARAM-I", "PARAM-II", "PARAM-III")[index // 2]
        interpretation = ("table-standard-deviation", "literal-density-width")[index % 2]
        safety(row)
        require((row.get("profile"), row.get("interpretation")) ==
                (finite_row.get("profile"), finite_row.get("interpretation")) ==
                (joint_row.get("profile"), joint_row.get("interpretation")) ==
                (profile, interpretation), "Table 4 row order or interpretation drift")
        seed = ("paper-baseline-" + profile + "-" + interpretation).encode("ascii")
        require(row.get("seed_sha256") == sha256(seed).hexdigest() ==
                finite_row.get("seed_sha256") == joint_row.get("seed_sha256") and
                row.get("inherited_source_manifest_sha256") == PREVIOUS_MANIFEST_SHA256 and
                row.get("paper_parameters") == finite_row.get("paper_parameters") and
                row.get("identity_bytes") == 5 and row.get("message_bytes") is None and
                row.get("setup_attempts") == row.get("extraction_calls") == 1,
                "root/identity/parameter binding drift")
        binding = row.get("finite_chain_manifest_binding", {})
        require(binding.get("schema") == finite_manifest["schema"] and
                binding.get("normalized_lf_sha256") == FINITE_MANIFEST_LF_SHA256 and
                binding.get("all_manifest_entries_sha256_verified") is True and
                binding.get("entry_count") == len(finite_entries) == 36 and
                binding.get("dependent_file_sha256") == {
                    path: finite_entries[path]["sha256"] for path in FINITE_DEPENDENCIES},
                "finite-chain manifest dependency binding drift")
        require(row.get("finite_report_sha256") ==
                finite_entries[FINITE_PREFIX + "finite-fixed-root.json"]["sha256"] and
                row.get("joint_report_sha256") ==
                finite_entries[FINITE_PREFIX + "joint-fixed-root.json"]["sha256"] and
                row.get("finite_source_schur_to_joint_master_tv_upper_including_abort") ==
                joint_row["master"]["finite_vs_joint_integer_gaussian_tv_upper_exact"],
                "fixed-root Schur master bound binding drift")
        guard = row.get("successful_finite_key_object_guard", {})
        require(row.get("source_schur_backend") == "SourceSchurBackend" and
                row.get("master_plan_numerical_input_replayed_exactly") is True and
                row.get("trapdoor_public_relation_verified") is True and
                row.get("gadget_identity_target_and_hnf_equation_verified") is True and
                row.get("first_key_canonical_roundtrip_verified") is True and
                row.get("same_root_c_gate", {}).get("certified") is True and
                guard.get("raw_and_key_within_256bit_object_guard") is True and
                guard.get("external_storage_faults_included") is False and
                row.get("abort_atom_retained") is True and
                row.get("gadget_fiber_bias_counted_once") is True and
                row.get("hnf_deterministic_pushforward_adds_no_tv_cost") is True,
                "same-root algorithm/guard evidence drift")
        require(row.get("all_accepted_setup_roots_tv") is None and
                row.get("full_issuance_signature_fault_history_tv") is None and
                row.get("native_strong_security_proven") is False and
                row.get("private_material_exported") is False and
                row.get("rng") == "DeterministicRandom TEST FIXTURE ONLY" and
                row.get("independent_uniform_bytes_required_for_tv") is True,
                "fixed-root/fault/security boundary drift")

        d_source = Fraction(row["finite_source_schur_to_joint_master_tv_upper_including_abort"])
        d_gadget = Fraction(row["gadget_scalar_tv_upper_including_aggregate_abort"])
        x = Fraction(row["gadget_digit_normalizer_relative_sum_exact"])
        epsilon_text = row["completed_square_center_theta_relative_error_exact"]
        epsilon = None if epsilon_text is None else Fraction(epsilon_text)
        if interpretation == "table-standard-deviation":
            require(0 <= x < 1 and epsilon is not None and 0 <= epsilon < 1,
                    "standard issuance normalizer premises missing")
            digit_cost, center_cost = x / (2 - x), epsilon / (1 - epsilon)
            expected = min(Fraction(1), d_source + d_gadget + digit_cost + center_cost)
            require(0 < expected < 1 and row.get("certified") is True and
                    row.get("complete_law_tv_upper_including_abort") == str(expected) and
                    row.get("denominator_removal_tv_upper") == str(digit_cost) and
                    row.get("completed_square_center_tilt_tv_upper") == str(center_cost) and
                    row.get("first_issuance_tv_bound_applies_under_iid_bytes_and_no_external_faults") is True,
                    "standard fixed-root first-issuance arithmetic drift")
        else:
            require(x >= 1 and row.get("certified") is False and
                    row.get("complete_law_tv_upper_including_abort") is None and
                    row.get("denominator_removal_tv_upper") is None and
                    row.get("completed_square_center_tilt_tv_upper") is None and
                    row.get("first_issuance_tv_bound_applies_under_iid_bytes_and_no_external_faults") is False,
                    "literal insufficient bound was promoted")
    print(json.dumps({"status": "verified", "rows": 6,
                      "standard_fixed_root_bounds": 3, "literal_issuance_bounds": None,
                      "finite_manifest_entries": len(finite_entries),
                      "package_entries": len(package["entries"]),
                      "security_claim": "none"}, sort_keys=True))


if __name__ == "__main__":
    main()
