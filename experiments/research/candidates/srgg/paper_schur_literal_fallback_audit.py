"""Record the first bounded literal-density Algorithm 4 fallback at Table 4 sizes.

The result is a sufficient all-center mathematical bound.  Its trivial chain
values are failed certification evidence, not measurements of the actual TV.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

from .paper_parameters import PaperParams
from .paper_profiles import SOURCE_PDF, SOURCE_SHA256
from .paper_schur_literal_fallback import literal_product_certificate


SCHEMA = "IBME/SRGG-SCHUR-LITERAL-FALLBACK-AUDIT/1"
ROOT = Path(__file__).resolve().parents[4]
SOURCE_FILES = (
    "experiments/research/candidates/srgg/paper_schur_literal_fallback.py",
    "experiments/research/candidates/srgg/paper_schur_literal_fallback_audit.py",
    "experiments/research/candidates/srgg/paper_rounding_budget.py",
    "experiments/research/candidates/srgg/paper_parameters.py",
    "experiments/research/candidates/srgg/paper_profiles.py",
)


def build_report():
    if sha256((ROOT / SOURCE_PDF).read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("frozen paper checksum differs")
    rows = []
    for name in ("PARAM-I", "PARAM-II", "PARAM-III"):
        params = PaperParams(name, "literal-density-width")
        phases = {}
        for phase, leaves in (("master", 2 * params.rank),
                              ("signature", params.columns)):
            certificate = literal_product_certificate(
                degree=params.degree, upper_polynomials=leaves,
                rounding_squared=params.r_squared)
            if (certificate["whole_chain_bound_nontrivial"] or
                    certificate["mathematical_algorithm34_to_ideal_sequential_discrete_tv_upper_exact"] != "1"):
                raise AssertionError("original literal-width route unexpectedly nontrivial")
            phases[phase] = certificate
        rows.append({"profile": name, "paper_parameters": params.record(), **phases})
    return {
        "schema": SCHEMA,
        "paper": {"path": SOURCE_PDF, "sha256": SOURCE_SHA256},
        "source_sha256": {name: sha256((ROOT / name).read_bytes()).hexdigest()
                          for name in SOURCE_FILES},
        "rows": rows,
        "scope": "all-center mathematical Algorithm 4 product-normalizer sufficient bound at original literal-width Table 4 sizes; no fixed-root pivot or IBS law certified",
        "actual_tv_measured": False,
        "exact_algorithm34_to_ideal_joint_tv_upper": None,
        "receipt_generated_on_fixed_roots": True,
        "fixed_roots_are_witnesses": True,
        "bound_scope": "every_plan_passing_complete_gate_set",
        "guard_built_into_backend": True,
        "all_gate_passing_setup_roots_covered": True,
        "accepted_setup_root_distribution_bound": None,
        "accepted_setup_root_distribution_reason":
            r"the gate-set mass P(A\B), P(B\G) and the accepted-root distribution "
            r"relative to mu_A remain unbounded; beta_bad remains null",
        "full_ibs_tv_upper": None,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("--output already exists")
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"rows": len(report["rows"]), "nontrivial_chains": 0,
                      "security_claim": report["security_claim"]}))


if __name__ == "__main__":
    main()
