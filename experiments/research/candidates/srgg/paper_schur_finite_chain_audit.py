"""Audit finite source-Schur versus mathematical Algorithms 3--4 on six fixed roots.

Only public bounds and source hashes leave this process.  The deterministic
roots are test fixtures; they do not model the distribution of accepted Setup
roots or the complete IBS service.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import platform

from sage.version import version as sage_version

from ibme.core.randomness import DeterministicRandom
from .paper_parameters import PaperParams
from .paper_profiles import SOURCE_PDF, SOURCE_SHA256
from .paper_schur_backend import SourceSchurBackend
from .paper_schur_finite_chain import fixed_root_finite_chain_certificate
from .paper_schur_normalizer import fixed_root_normalizer_certificate
from .paper_schur_numerical import SchurNumericalAudit


SCHEMA = "IBME/SRGG-SCHUR-FIXED-ROOT-FINITE-CHAIN/1"
ROOT = Path(__file__).resolve().parents[4]
SOURCE_FILES = (
    "experiments/research/candidates/srgg/paper_schur_finite_chain.py",
    "experiments/research/candidates/srgg/paper_schur_finite_chain_audit.py",
    "experiments/research/candidates/srgg/paper_schur_numerical.py",
    "experiments/research/candidates/srgg/paper_schur_normalizer.py",
    "experiments/research/candidates/srgg/paper_schur_samplef.py",
    "experiments/research/candidates/srgg/paper_schur_fourier.py",
    "experiments/research/candidates/srgg/paper_schur_backend.py",
    "experiments/research/candidates/srgg/paper_parameters.py",
    "experiments/research/candidates/srgg/wide_scalar.py",
    "experiments/research/candidates/srgg/aggregate_budget.py",
)


def build_report():
    if sha256((ROOT / SOURCE_PDF).read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("frozen paper checksum differs")
    rows = []
    for profile in ("PARAM-I", "PARAM-II", "PARAM-III"):
        for interpretation in ("table-standard-deviation", "literal-density-width"):
            params = PaperParams(profile, interpretation)
            seed = ("paper-baseline-" + profile + "-" + interpretation).encode("ascii")
            backend = SourceSchurBackend(rng=DeterministicRandom(seed))
            _, master = backend.setup(params)
            master_audit = SchurNumericalAudit(backend._master_plan(params, master.witness))
            key = backend.key_extract(master, b"Alice")
            signature_audit = SchurNumericalAudit(backend._sign_plan(key))
            phases = {}
            for label, audit in (("master", master_audit), ("signature", signature_audit)):
                numerical = audit.public_certificate()
                if not numerical["all_ideal_schur_pivot_eigenvalues_at_least_64"]:
                    raise AssertionError("fixed-root pivot floor missing")
                phases[label] = {
                    "numerical_input": numerical,
                    "finite_chain": fixed_root_finite_chain_certificate(audit),
                    "ideal_schur_normalizer": fixed_root_normalizer_certificate(audit),
                }
            rows.append({
                "profile": profile, "interpretation": interpretation,
                "paper_parameters": params.record(),
                "rng": "DeterministicRandom TEST FIXTURE ONLY",
                "seed_sha256": sha256(seed).hexdigest(),
                "identity_bytes": 5, "setup_attempts": backend.setup_attempts,
                "extraction_calls": backend.extract_calls,
                "master": phases["master"], "signature": phases["signature"],
                "private_material_exported": False,
                "receipt_generated_on_fixed_roots": True,
                "fixed_roots_are_witnesses": True,
                "bound_scope": "every_plan_passing_complete_gate_set",
                "guard_built_into_backend": True,
                "all_gate_passing_setup_roots_covered": True,
                "accepted_setup_root_distribution_bound": None,
                "accepted_setup_root_distribution_reason":
                    r"the gate-set mass P(A\B), P(B\G) and the accepted-root distribution "
                    r"relative to mu_A remain unbounded; beta_bad remains null",
                "complete_issuance_signature_history_law": None,
            })
            # Witness, master secret and issued key are discarded with scope.
    return {
        "schema": SCHEMA,
        "paper": {"path": SOURCE_PDF, "sha256": SOURCE_SHA256},
        "source_sha256": {name: sha256((ROOT / name).read_bytes()).hexdigest()
                          for name in SOURCE_FILES},
        "environment": {"python": platform.python_version(),
                        "sage": sage_version, "platform": platform.platform()},
        "rows": rows,
        "scope": ("six deterministic accepted roots as witnesses; guarded backend; the finite integer "
                  "Algorithm 3--4 chain applies to every complete-gate plan"),
        "bound_scope": "every_plan_passing_complete_gate_set",
        "guard_built_into_backend": True,
        "rom_used": True, "teaching_parameters": False,
        "independent_uniform_bytes_assumed_for_tv": True,
        "tests_or_functional_lifecycle_repeated_by_this_report": False,
        "source_schur_finite_vs_exact_algorithm34_only": True,
        "finite_vs_ideal_joint_integer_tv": None,
        "all_accepted_setup_root_distribution_tv": None,
        "full_IBS_service_history_tv": None,
        "native_strong_security_proven": False,
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
    print(json.dumps({"rows": len(report["rows"]),
                      "security_claim": report["security_claim"]}))


if __name__ == "__main__":
    main()
