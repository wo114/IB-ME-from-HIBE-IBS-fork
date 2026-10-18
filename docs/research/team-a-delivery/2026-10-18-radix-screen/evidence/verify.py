"""Audit only committed PUBLIC receipts and Git blobs; never opens key states.

Run from the repository with Windows Python, whose Git resolves this worktree.
The original mathematical/provider provenance and the later decision policy
are checked against their distinct commits.
"""

import gzip
from hashlib import sha256
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
CHECK = ROOT/"docs/research/team-a-delivery/2026-10-18-3m-feasibility/evidence/check-sources.py"


def main():
    spec = importlib.util.spec_from_file_location("public_provider_audit", CHECK)
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    original_bytes = gzip.decompress((HERE/"original-screen.json.gz").read_bytes())
    revised_bytes = gzip.decompress((HERE/"screen.json.gz").read_bytes())
    original, revised = json.loads(original_bytes), json.loads(revised_bytes)
    policy = revised["reclassification"]
    assert sha256(original_bytes).hexdigest() == policy["input_sha256"]
    assert revised["source_commit"] == original["source_commit"] == policy["input_source_commit"]
    assert checker.blob_hash(policy["source_commit"], "experiments/research/structured_radix_screen.py") == policy["source_module_sha256"]
    assert len(revised["rows"]) == len(original["rows"]) == 288
    immutable = ("complete_group", "root_lwe", "ciphertext_lwe", "finite_projection", "estimator_results", "allocation")
    for before, after in zip(original["rows"], revised["rows"]):
        for key in immutable:
            assert before[key] == after[key], key
        for key in before["resources"]:
            if key not in ("resident_research_budget_bytes", "necessary_payload_fits_research_budget"):
                assert before["resources"][key] == after["resources"][key], key
        assert after["decision"]["hardware_budget_is_advisory"]
    provider_counts = {"original_screen":checker.check_record(original), "reclassified_screen":checker.check_record(revised)}
    falcon_path = ROOT/"docs/research/2026-10-18-full-system-falcon/evidence/latte-falcon512.json"
    falcon = json.loads(falcon_path.read_bytes())
    assert falcon["status"] == "passed" and falcon["repetitions"] == 3
    for record in falcon["records"]:
        assert record["generation"]["status"] == record["restore"]["status"] == "passed"
        assert record["restore"]["entropy_bytes"] == record["restore"]["entropy_reads"] == 0
        assert record["restore"]["state_unchanged"]
    provider_counts["falcon_benchmark"] = checker.check_record(falcon)
    runner = "experiments/research/full_system_benchmark.py"
    assert checker.blob_hash(falcon["source_commit"], runner) == checker.blob_hash("6b5305a", runner)
    assert all(provider_counts.values())
    result = dict(status="passed", provider_occurrences=provider_counts,
        distinct_commit_provider_pairs=len(checker.CACHE), unchanged_mathematical_rows=288,
        input_sha256=policy["input_sha256"], policy_source_commit=policy["source_commit"],
        original_math_model_source_commit=original["source_commit"],
        full_benchmark_runner_matches_prior_MLDSA_baseline=True, private_state_files_opened=0)
    text = json.dumps(result, indent=2)+"\n"
    (HERE/"verification.json").write_text(text, encoding="utf-8")
    print(text, end="")


if __name__ == "__main__": main()
