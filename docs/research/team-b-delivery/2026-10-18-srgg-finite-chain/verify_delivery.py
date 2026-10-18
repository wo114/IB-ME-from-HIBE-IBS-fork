"""Verify byte bindings and limited claims in this SRGG research package."""
from __future__ import annotations

from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SCHEMA = "IBME/SRGG-FINITE-CHAIN-DELIVERY-MANIFEST/1"
REQUIRED = {
    "experiments/research/candidates/srgg/paper_schur_finite_chain.py",
    "experiments/research/candidates/srgg/paper_schur_finite_chain_audit.py",
    "experiments/research/candidates/srgg/paper_schur_convolution.py",
    "experiments/research/candidates/srgg/paper_schur_joint_bound_audit.py",
    "experiments/research/candidates/srgg/paper_schur_literal_fallback.py",
    "experiments/research/candidates/srgg/paper_schur_literal_fallback_audit.py",
    "experiments/research/candidates/srgg/paper_schur_literal_moment.py",
    "tests/test_srgg_paper_schur_finite_chain.py",
    "tests/test_srgg_paper_schur_convolution.py",
    "tests/test_srgg_paper_schur_joint_bound_audit.py",
    "tests/test_srgg_paper_schur_literal_fallback.py",
    "tests/test_srgg_paper_schur_literal_fallback_audit.py",
    "tests/test_srgg_paper_schur_literal_moment.py",
    "docs/research/team-b-delivery/2026-10-18-srgg-finite-chain/README.md",
    "docs/research/team-b-delivery/2026-10-18-srgg-finite-chain/README_zh-CN.md",
    "docs/research/team-b-delivery/2026-10-18-srgg-finite-chain/proof.md",
    "docs/research/team-b-delivery/2026-10-18-srgg-finite-chain/finite-fixed-root.json",
    "docs/research/team-b-delivery/2026-10-18-srgg-finite-chain/joint-fixed-root.json",
    "docs/research/team-b-delivery/2026-10-18-srgg-finite-chain/literal-product-fallback.json",
    "docs/research/team-b-delivery/2026-10-18-srgg-finite-chain/validation.json",
    "docs/research/team-b-delivery/2026-10-18-srgg-finite-chain/verify_delivery.py",
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
    require(path.is_relative_to(ROOT) and path.is_file(), "missing or escaped package file: " + name)
    return path


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def receipt(name):
    return json.loads((HERE / name).read_text(encoding="utf-8"))


def _security(value):
    require(value.get("security_claim") == "none" and
            value.get("backend_admitted") is False and
            value.get("parameters_are_formal") is False and
            value.get("nist_security_category") is None,
            "formal security marker drift")


def main():
    manifest = receipt("MANIFEST.json")
    require(manifest.get("schema") == SCHEMA, "manifest schema")
    entries = manifest.get("entries")
    require(type(entries) is dict and REQUIRED <= set(entries), "manifest coverage")
    for name, expected in entries.items():
        require(type(expected) is dict and set(expected) == {"bytes", "sha256"},
                "manifest entry structure")
        path = file_at(name)
        require(path.stat().st_size == expected["bytes"] and
                digest(path) == expected["sha256"], "package byte mismatch: " + name)

    finite = receipt("finite-fixed-root.json")
    joint = receipt("joint-fixed-root.json")
    product = receipt("literal-product-fallback.json")
    require(finite.get("schema") == "IBME/SRGG-SCHUR-FIXED-ROOT-FINITE-CHAIN/1",
            "finite receipt schema")
    require(joint.get("schema") == "IBME/SRGG-SCHUR-FIXED-ROOT-JOINT-BOUND/1",
            "joint receipt schema")
    require(product.get("schema") == "IBME/SRGG-SCHUR-LITERAL-FALLBACK-AUDIT/1",
            "literal product receipt schema")
    require(joint.get("finite_report_sha256") == digest(HERE / "finite-fixed-root.json"),
            "three-link receipt input binding")
    for report in (finite, joint, product):
        _security(report)
        paper = report.get("paper", {})
        require(paper.get("path") == "papers/2025_efficient_ibs_jia.pdf" and
                digest(file_at(paper["path"])) == paper.get("sha256"), "frozen paper binding")
        for name, expected in report.get("source_sha256", {}).items():
            require(digest(file_at(name)) == expected, "report source drift: " + name)

    require(len(finite.get("rows", ())) == len(joint.get("rows", ())) == 6,
            "six fixed-root rows")
    require(len(product.get("rows", ())) == 3 and
            product.get("actual_tv_measured") is False and
            product.get("full_ibs_tv_upper") is None,
            "literal product fallback scope")
    for i, item in enumerate(product["rows"]):
        require(item.get("profile") == ("PARAM-I", "PARAM-II", "PARAM-III")[i] and
                item.get("paper_parameters", {}).get("interpretation") ==
                "literal-density-width", "literal product profile")
        for phase in ("master", "signature"):
            cert = item[phase]
            _security(cert)
            require(cert.get("whole_chain_bound_nontrivial") is False and
                    cert.get("mathematical_algorithm34_to_ideal_sequential_discrete_tv_upper_exact") == "1",
                    "failed product route mislabeled")
    expected = [
        (profile, interpretation) for profile in ("PARAM-I", "PARAM-II", "PARAM-III")
        for interpretation in ("table-standard-deviation", "literal-density-width")
    ]
    finite_expected = ((72, 71), (72, 71), (72, 71), (72, 71), (71, 70), (71, 70))
    joint_expected = ((26, 25), (None, None), (25, 24), (None, None), (25, 24), (None, None))
    for i, (first, second) in enumerate(zip(finite["rows"], joint["rows"])):
        require((first.get("profile"), first.get("interpretation")) == expected[i] ==
                (second.get("profile"), second.get("interpretation")), "profile/order mismatch")
        require(first.get("seed_sha256") == second.get("seed_sha256") and
                first.get("setup_attempts", 0) >= 1 and first.get("extraction_calls") == 1 and
                first.get("private_material_exported") is False and
                first.get("all_accepted_setup_roots_covered") is False,
                "fixed-root execution/privacy boundary")
        for j, phase in enumerate(("master", "signature")):
            finite_phase = first[phase]
            joint_phase = second[phase]
            _security(finite_phase["finite_chain"])
            _security(finite_phase["ideal_schur_normalizer"])
            require(finite_phase["numerical_input"]["full_target_integer_tv_upper_including_abort"] is None and
                    finite_phase["finite_chain"]["finite_vs_joint_integer_gaussian_tv_upper"] is None,
                    "finite-only result mislabeled as joint")
            require(finite_phase["finite_chain"]["finite_vs_exact_algorithm34_tv_dyadic_bits"] ==
                    finite_expected[i][j], "fixed-root finite bound drift")
            require(joint_phase["finite_vs_joint_integer_gaussian_tv_dyadic_bits"] ==
                    joint_expected[i][j], "combined fixed-root bound drift")
            exact = joint_phase.get("finite_vs_joint_integer_gaussian_tv_upper_exact")
            require(exact is not None and 0 < Fraction(exact) < 1 and
                    joint_phase.get("fixed_root_combined_tv_bound_nontrivial") is True,
                    "combined fixed-root rational bound drift")
            middle = joint_phase["mathematical_algorithm34_vs_ideal_sequential"]
            require(middle["all_accepted_setup_roots_covered"] is False,
                    "convolution scope drift")
            if second["interpretation"] == "literal-density-width":
                require(middle.get("schema") == "IBME/SRGG-SCHUR-LITERAL-FOURIER-MOMENT/1" and
                        Fraction(1, 2) < Fraction(exact) < 1 and
                        middle.get("fixed_root_pivot_floor_authenticated_here") is False,
                        "literal moment scope or strength drift")
            else:
                require(Fraction(exact) <= Fraction(1, 2**joint_expected[i][j]),
                        "standard dyadic ceiling does not cover exact bound")
    require(finite.get("full_IBS_service_history_tv") is None and
            joint.get("full_issuance_signature_history_tv") is None and
            joint.get("accepted_setup_root_distribution_bound") is None,
            "service/Setup closure falsely claimed")
    print(json.dumps({"status": "verified", "manifest_entries": len(entries),
                      "fixed_root_rows": 6, "exact_joint_phase_bounds": 12,
                      "strong_dyadic_joint_phase_bounds": 6,
                      "security_claim": "none"}, sort_keys=True))


if __name__ == "__main__":
    main()
