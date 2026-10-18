"""Reproduce fixed-root local Schur numerical certificates without key export."""
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
from .paper_schur_numerical import SchurNumericalAudit
from .paper_schur_normalizer import fixed_root_normalizer_certificate


SCHEMA = "IBME/SRGG-SCHUR-FIXED-ROOT-NUMERICAL-RECEIPT/1"
ROOT = Path(__file__).resolve().parents[4]
SOURCE_FILES = (
    "experiments/research/candidates/srgg/paper_schur_numerical_audit.py",
    "experiments/research/candidates/srgg/paper_schur_numerical.py",
    "experiments/research/candidates/srgg/paper_schur_normalizer.py",
    "experiments/research/candidates/srgg/paper_schur_samplef.py",
    "experiments/research/candidates/srgg/paper_schur_fourier.py",
    "experiments/research/candidates/srgg/paper_schur_backend.py",
    "experiments/research/candidates/srgg/paper_parameters.py",
    "experiments/research/candidates/srgg/paper_rounding_budget.py",
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
            first = master_audit.public_certificate()
            second = signature_audit.public_certificate()
            first_normalizer = fixed_root_normalizer_certificate(master_audit)
            second_normalizer = fixed_root_normalizer_certificate(signature_audit)
            if (first_normalizer["ideal_sequential_vs_joint_integer_tv_dyadic_upper"] is None
                    or second_normalizer["ideal_sequential_vs_joint_integer_tv_dyadic_upper"] is None):
                raise AssertionError("fixed-root ideal Schur normalizer gate not certified")
            for certificate in (first, second):
                if (certificate["full_target_integer_tv_upper_including_abort"] is not None
                        or not certificate["witness_dependent_diagnostics_redacted"]):
                    raise AssertionError("local public certificate scope drift")
            rows.append({"profile": profile, "interpretation": interpretation,
                "randomness": "DeterministicRandom TEST ONLY",
                "seed_sha256": sha256(seed).hexdigest(),
                "identity_bytes": 5, "setup_attempts": backend.setup_attempts,
                "extraction_calls": backend.extract_calls,
                "master": first, "signature": second,
                "master_ideal_normalizer": first_normalizer,
                "signature_ideal_normalizer": second_normalizer,
                "full_source_schur_integer_tv_including_abort": None,
                "accepted_setup_root_distribution_bound": None,
                "private_material_exported": False})
            # Private witness and signing key live only in this process.
    return {"schema": SCHEMA,
        "paper": {"path": SOURCE_PDF, "sha256": SOURCE_SHA256},
        "source_sha256": {name: sha256((ROOT/name).read_bytes()).hexdigest()
                          for name in SOURCE_FILES},
        "environment": {"python": platform.python_version(),
                        "sage": sage_version, "platform": platform.platform()},
        "rows": rows, "rom_used": True, "teaching_parameters": False,
        "tests_or_functional_lifecycle_repeated_by_this_report": False,
        "actual_entropy_bytes": None,
        "scope": "six deterministic fixed accepted roots and issued keys; local interval numerical gates only",
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None}


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
