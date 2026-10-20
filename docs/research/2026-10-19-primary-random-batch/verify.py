"""Read-only verifier for the primary A09/R4 random-input batch."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from experiments.research.random_batch_acceptance import (  # noqa: E402
    validate_public_report,
)


COMMIT = "85a93e2a1243d141b5febd153223a91f44e8159e"
RECEIPT_SHA256 = "21f1bb84052004749dc172e396328f683ae46290011fd6cee7cc0e1b31b88de9"


def require(condition, label):
    if not condition:
        raise AssertionError(label)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git_blob(path: str) -> bytes:
    process = subprocess.run(
        ["git", "show", f"{COMMIT}:{path}"],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    require(process.returncode == 0, "missing source-commit blob: " + path)
    return process.stdout


def verify(self_test: bool) -> tuple[int, int]:
    raw = (HERE / "receipt.json").read_bytes()
    require(sha256(raw) == RECEIPT_SHA256, "receipt digest")
    report = json.loads(raw)
    observed = validate_public_report(report, expected_commit=COMMIT)

    roots = report["roots"]
    providers = roots[0]["source_providers"]
    require(all(root["source_providers"] == providers for root in roots), "provider sets differ")
    for path, expected in providers.items():
        require(sha256(git_blob(path)) == expected, "provider differs from source commit: " + path)

    suites = json.loads(git_blob("ci/c-combinations.json"))
    selected = [row for row in suites if row.get("name") == report["suite_name"]]
    require(len(selected) == 1, "selected suite missing or duplicated at source commit")
    require(selected[0]["selection"] == {
        "hibe": "latte",
        "hibe_params": "seed32",
        "ibs": "cert-ml-dsa",
        "ibs_params": "ml-dsa-44",
        "transport": "hybrid",
        "protocol": "byteauth-v1",
        "signature_format": "reference",
        "allow_mock": False,
    }, "source-commit manifest selection")

    provenance = json.loads((HERE / "native-provenance.json").read_bytes())
    require(provenance["schema"] == "IBME-A09-NATIVE-PROVENANCE/1", "provenance schema")
    require(provenance["status"] == "passed", "provenance status")
    require(provenance["source_commit"] == COMMIT, "provenance commit")
    require(provenance["receipt"]["sha256"] == RECEIPT_SHA256, "provenance receipt digest")
    from ibme.hibe.latte.native.build import source_id as latte_source_id
    from ibme.ibs.certified.native.build import source_id as mldsa_source_id

    require(provenance["latte"]["source_id"] == latte_source_id(), "LATTE source id")
    require(provenance["mldsa44"]["source_id"] == mldsa_source_id(), "ML-DSA source id")
    for section in ("latte", "mldsa44"):
        require(len(provenance[section]["binary_sha256"]) == 64, section + " binary digest")
        int(provenance[section]["binary_sha256"], 16)
    require(provenance["claims"] == {
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
        "post_run_query_is_security_proof": False,
    }, "provenance claims")

    negative_controls = 0
    if self_test:
        mutations = []
        changed = copy.deepcopy(report)
        changed["roots"][0]["cases"][0]["checks"]["honest_roundtrip"] = False
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["suite"]["allow_mock"] = True
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["execution"]["failed_samples_retried"] = True
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["roots"][1]["cryptographic_randomness"]["bytes"] = 0
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["roots"][2]["cases"][0]["message_hex"] = "00"
        mutations.append(changed)
        for changed in mutations:
            try:
                validate_public_report(changed, expected_commit=COMMIT)
            except AssertionError:
                negative_controls += 1
            else:
                raise AssertionError("mutated receipt was accepted")
    return observed + len(providers) * len(roots), negative_controls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    checks, negatives = verify(args.self_test)
    print(
        f"validated 60 batch outcomes and {checks - 60} source-provider bindings; "
        f"{negatives} negative controls passed"
    )


if __name__ == "__main__":
    main()
