"""Read-only checks on actual public A records; no cryptographic replay."""
from copy import deepcopy
import json
from pathlib import Path
from pathlib import PurePosixPath

import pytest

from experiments.research.verify_backend_optimization import validate_batch

FOLDER = Path(__file__).resolve().parents[1]/"docs/research/2026-10-20-multi-backend-optimization"


def inputs():
    return [json.loads((FOLDER/name).read_bytes()) for name in
            ("A.json", "installation.json", "source-manifest.json")]


def test_actual_installed_A_receipt_and_native_verification_counts():
    data, installation, manifest = inputs()
    result = validate_batch(data, installation, manifest)
    assert result["decrypt"]["median_root_speedup"] > 0


def test_current_security_snapshot_keeps_the_same_math_and_observations():
    from ibme.core.security import security_fields
    from experiments.research.backend_optimization_probe import expected_suite

    data, installation, manifest = deepcopy(inputs())
    current = expected_suite("A")
    data.update(security_fields(current.to_dict()))
    for record in data["records"]:
        record.update(security_fields(current.to_dict()), suite=current.to_dict(), suite_digest=current.digest)
    result = validate_batch(data, installation, manifest)
    original, _, _ = inputs()
    assert result == validate_batch(original, installation, manifest)
    # The fixture on disk remains the original historical execution snapshot.
    assert original["security_claim"] == "none"


@pytest.mark.parametrize("field,value", (("backend_admitted", 0), ("parameters_are_formal", 1),
    ("security_claim", "NIST-5"), ("security_claim", "project-admitted")))
def test_mixed_or_unrecognized_security_snapshots_are_rejected(field, value):
    data, installation, manifest = deepcopy(inputs())
    data[field] = value
    with pytest.raises(ValueError, match="security"):
        validate_batch(data, installation, manifest)


@pytest.mark.parametrize("spelling", ("parent", "dot", "double-slash"))
def test_noncanonical_provider_paths_are_rejected_even_with_matching_manifest(spelling):
    data, installation, manifest = deepcopy(inputs())
    provider = next(iter(data["records"][0]["providers"].values()))
    root = installation["runtime_root"]
    relative = str(PurePosixPath(provider["path"]).relative_to(root))
    separator = {"parent": "/../checkout/", "dot": "/./", "double-slash": "//"}[spelling]
    provider["path"] = root+separator+relative
    changed_relative = str(PurePosixPath(provider["path"]).relative_to(root))
    manifest["files"][changed_relative] = provider["sha256"]
    with pytest.raises(ValueError, match="canonical"):
        validate_batch(data, installation, manifest)


@pytest.mark.parametrize("bad_digest", (None, "not-a-source-digest"))
def test_matching_malformed_provider_digests_cannot_certify_a_source(bad_digest):
    data, installation, manifest = deepcopy(inputs())
    first = next(iter(data["records"][0]["providers"].values()))
    path = first["path"]
    for record in data["records"]:
        for provider in record["providers"].values():
            if provider["path"] == path:
                provider["sha256"] = bad_digest
    manifest["files"][str(PurePosixPath(path).relative_to(installation["runtime_root"]))] = bad_digest
    with pytest.raises(ValueError, match="source digest"):
        validate_batch(data, installation, manifest)


@pytest.mark.parametrize("tamper", ("failure", "provider", "count", "summary", "suite", "roots"))
def test_tampered_receipts_do_not_inherit_success(tamper):
    data, installation, manifest = deepcopy(inputs())
    first = data["records"][0]
    if tamper == "failure":
        first["status"] = "failed"
    elif tamper == "provider":
        next(iter(first["providers"].values()))["sha256"] = "0"*64
    elif tamper == "count":
        row = next(r for r in first["phases"] if r["name"] == "decrypt" and r["mode"] == "on")
        row["native_calls"]["mldsa:verify"] = 2
    elif tamper == "summary":
        data["summary"]["decrypt"]["median_root_speedup"] = 1000
    elif tamper == "suite":
        first["suite"]["hybrid_limits"]["max_payload_bytes"] += 1
    else:
        data["records"][1]["root"] = 0
    with pytest.raises(ValueError):
        validate_batch(data, installation, manifest)
