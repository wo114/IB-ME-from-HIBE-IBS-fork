"""Combine separately proved fixed-root SRGG finite, convolution and Schur bounds.

The input finite receipt is authenticated against current source bytes.  A
missing mathematical convolution bound leaves the final joint comparison null.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path

from .paper_parameters import PaperParams
from .paper_profiles import SOURCE_PDF, SOURCE_SHA256
from .paper_schur_convolution import chain_convolution_certificate
from .paper_schur_finite_chain import _dyadic_bits, _fraction
from .paper_schur_finite_chain_audit import SCHEMA as FINITE_SCHEMA
from .paper_schur_literal_moment import moment_chain_certificate
from .paper_schur_normalizer import SCHEMA as NORMALIZER_SCHEMA, ideal_normalizer_bias
from .paper_rounding_budget import theta_certificate


SCHEMA = "IBME/SRGG-SCHUR-FIXED-ROOT-JOINT-BOUND/1"
ROOT = Path(__file__).resolve().parents[4]
GUARD_SOURCE = "experiments/research/candidates/srgg/paper_distribution_guard.py"
BACKEND_SOURCE = "experiments/research/candidates/srgg/paper_schur_backend.py"
_GATE_SCOPE = {
    "receipt_generated_on_fixed_roots": True,
    "fixed_roots_are_witnesses": True,
    "bound_scope": "every_plan_passing_complete_gate_set",
    "guard_built_into_backend": True,
    "all_gate_passing_setup_roots_covered": True,
}
_GATE_MASS_REASON = (r"the gate-set mass P(A\B), P(B\G) and the accepted-root "
                     r"distribution relative to mu_A remain unbounded; beta_bad remains null")
FINITE_REPORT_SHA256 = "011e9dae5f33780bf4ac7b0f025f6b7f8e172c2e3433c7c100e720c893b7914b"
SOURCE_FILES = (
    "experiments/research/candidates/srgg/paper_schur_convolution.py",
    "experiments/research/candidates/srgg/paper_schur_joint_bound_audit.py",
    "experiments/research/candidates/srgg/paper_schur_literal_moment.py",
    "experiments/research/candidates/srgg/paper_rounding_budget.py",
    "experiments/research/candidates/srgg/paper_schur_normalizer.py",
)


def _read_authentic_finite(path):
    raw = path.read_bytes()
    if sha256(raw).hexdigest() != FINITE_REPORT_SHA256:
        raise ValueError("frozen finite-chain receipt bytes changed")
    report = json.loads(raw)
    if report.get("schema") != FINITE_SCHEMA or len(report.get("rows", ())) != 6:
        raise ValueError("six-row finite-chain receipt required")
    if report.get("paper") != {"path": SOURCE_PDF, "sha256": SOURCE_SHA256}:
        raise ValueError("finite-chain paper binding differs")
    if sha256((ROOT / SOURCE_PDF).read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("frozen paper checksum differs")
    sources = report.get("source_sha256")
    if not isinstance(sources, dict) or not sources:
        raise ValueError("finite-chain source binding missing")
    for name, expected in sources.items():
        if (type(name) is not str or type(expected) is not str or
                not name.startswith("experiments/research/candidates/srgg/") or
                sha256((ROOT / name).read_bytes()).hexdigest() != expected):
            raise ValueError("finite-chain source bytes changed")
    if (report.get("security_claim") != "none" or report.get("backend_admitted") is not False
            or report.get("parameters_are_formal") is not False
            or report.get("finite_vs_ideal_joint_integer_tv") is not None):
        raise ValueError("finite-chain receipt scope drift")
    return raw, report


def _dyadic_probability(text):
    if type(text) is not str or not text.startswith("2^-"):
        raise ValueError("dyadic upper required")
    bits = text[3:]
    if not bits.isdecimal() or len(bits) > 4 or int(bits) > 8192:
        raise ValueError("bounded dyadic exponent required")
    return Fraction(1, 2**int(bits))


def build_report(finite_report):
    raw, previous = _read_authentic_finite(Path(finite_report))
    rows = []
    expected = {(profile, interpretation) for profile in
                ("PARAM-I", "PARAM-II", "PARAM-III") for interpretation in
                ("table-standard-deviation", "literal-density-width")}
    for item in previous["rows"]:
        identity = (item.get("profile"), item.get("interpretation"))
        if identity not in expected:
            raise ValueError("duplicate or unexpected finite-chain row")
        expected.remove(identity)
        params = PaperParams(*identity)
        if item.get("paper_parameters") != params.record() or item.get("private_material_exported") is not False:
            raise ValueError("finite-chain parameter or privacy binding differs")
        phases = {}
        for phase in ("master", "signature"):
            body = item.get(phase)
            if not isinstance(body, dict):
                raise ValueError("finite-chain phase missing")
            numerical = body.get("numerical_input", {})
            finite = body.get("finite_chain", {})
            normalizer = body.get("ideal_schur_normalizer", {})
            degree, leaves = numerical.get("degree"), numerical.get("upper_polynomials")
            if (type(degree) is not int or degree != params.degree or
                    type(leaves) is not int or not 1 <= leaves <= 16 or
                    numerical.get("all_ideal_schur_pivot_eigenvalues_at_least_64") is not True or
                    finite.get("degree") != degree or finite.get("upper_leaf_count") != leaves or
                    finite.get("bound_scope") != "every_plan_passing_complete_gate_set" or
                    finite.get("guard_built_into_backend") is not True or
                    finite.get("finite_vs_joint_integer_gaussian_tv_upper") is not None or
                    normalizer.get("schema") != NORMALIZER_SCHEMA or
                    normalizer.get("bound_scope") != "every_plan_passing_complete_gate_set" or
                    normalizer.get("guard_built_into_backend") is not True or
                    normalizer.get("ideal_pivot_density_shape_lower") != 64):
                raise ValueError("fixed-root phase certificate mismatch")
            finite_upper = _dyadic_probability(finite.get("finite_vs_exact_algorithm34_tv_dyadic_upper"))
            independent_theta = theta_certificate(dimension=degree,
                density_shape=Fraction(64), precision_bits=512)
            independent_epsilon = independent_theta["relative_normalizer_error_upper_exact"]
            if independent_epsilon is None:
                raise ValueError("independent ideal Schur normalizer gate failed")
            independent_normalizer = ideal_normalizer_bias(dimension=degree,
                stages=leaves, relative_normalizer_error=Fraction(independent_epsilon))
            if (normalizer.get("ideal_sequential_vs_joint_integer_tv_dyadic_upper") !=
                    independent_normalizer["ideal_sequential_vs_joint_integer_tv_dyadic_upper"] or
                    normalizer.get("ideal_sequential_vs_joint_integer_tv_dyadic_bits") !=
                    independent_normalizer["ideal_sequential_vs_joint_integer_tv_dyadic_bits"]):
                raise ValueError("frozen ideal Schur normalizer differs from independent recomputation")
            normalizer_upper = _dyadic_probability(
                normalizer.get("ideal_sequential_vs_joint_integer_tv_dyadic_upper"))
            rounding = _fraction(params.r_squared)
            if item["interpretation"] == "literal-density-width":
                convolution = moment_chain_certificate(degree=degree,
                    upper_polynomials=leaves, rounding_squared=rounding,
                    ideal_pivot_lower=Fraction(64))
            else:
                convolution = chain_convolution_certificate(degree=degree,
                    upper_polynomials=leaves, rounding_squared=rounding,
                    ideal_pivot_lower=Fraction(64))
            middle = convolution["mathematical_algorithm34_to_ideal_sequential_discrete_tv_upper_exact"]
            combined = None if middle is None else finite_upper+Fraction(middle)+normalizer_upper
            nontrivial = combined is not None and 0 <= combined < 1
            bits = None if not nontrivial or combined == 0 else _dyadic_bits(combined)
            # A pure-power-of-two envelope cannot express 0.68..0.99 without
            # rounding to one.  Keep the exact outward rational instead.
            if bits == 0:
                bits = None
            phases[phase] = {
                **_GATE_SCOPE,
                "accepted_setup_root_distribution_bound": None,
                "accepted_setup_root_distribution_reason": _GATE_MASS_REASON,
                "finite_vs_mathematical_algorithm34_dyadic_upper": str(finite["finite_vs_exact_algorithm34_tv_dyadic_upper"]),
                "mathematical_algorithm34_vs_ideal_sequential": convolution,
                "ideal_sequential_vs_joint_dyadic_upper": str(normalizer["ideal_sequential_vs_joint_integer_tv_dyadic_upper"]),
                "finite_vs_joint_integer_gaussian_tv_upper_exact": None if not nontrivial else str(combined),
                "finite_vs_joint_integer_gaussian_tv_dyadic_upper": None if bits is None else "2^-"+str(bits),
                "finite_vs_joint_integer_gaussian_tv_dyadic_bits": bits,
                "fixed_root_combined_tv_bound_nontrivial": nontrivial,
                "combination": "triangle inequality across three distinct comparisons; abort remains an extra atom in the finite first link",
            }
        rows.append({"profile": item["profile"], "interpretation": item["interpretation"],
                     "seed_sha256": item["seed_sha256"], "master": phases["master"],
                     "signature": phases["signature"]})
    if expected:
        raise ValueError("missing original Table 4 interpretation")
    return {"schema": SCHEMA,
            "paper": {"path": SOURCE_PDF, "sha256": SOURCE_SHA256},
            "finite_report_sha256": sha256(raw).hexdigest(),
            "source_sha256": {name: sha256((ROOT/name).read_bytes()).hexdigest()
                              for name in (*SOURCE_FILES, GUARD_SOURCE, BACKEND_SOURCE)},
            "rows": rows,
            "scope": ("six deterministic accepted roots as witnesses; guarded backend; joint finite/convolution/"
                      "normalizer bounds apply to every complete-gate plan"),
            "bound_scope": "every_plan_passing_complete_gate_set",
            "guard_built_into_backend": True,
            "accepted_setup_root_distribution_bound": None,
            "full_issuance_signature_history_tv": None,
            "native_strong_security_proven": False,
            "security_claim": "none", "backend_admitted": False,
            "parameters_are_formal": False, "nist_security_category": None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--finite-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("--output already exists")
    report = build_report(args.finite_report)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"rows": len(report["rows"]),
                      "joined_phase_bounds": sum(item[p]["finite_vs_joint_integer_gaussian_tv_dyadic_bits"]
                                                 is not None for item in report["rows"]
                                                 for p in ("master", "signature"))}))


if __name__ == "__main__":
    main()
