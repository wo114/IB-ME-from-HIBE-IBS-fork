"""Aggregate PUBLIC complete-system receipts; no cross-security-group ranking."""

from hashlib import sha256
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
FILES = (
    ROOT/"docs/research/2026-10-18-full-system-baseline/evidence/latte-mldsa44.json",
    ROOT/"docs/research/2026-10-18-full-system-falcon/evidence/latte-falcon512.json",
    HERE/"latte-luo-compact.json",
)


def main():
    checker_path = ROOT/"docs/research/team-a-delivery/2026-10-18-3m-feasibility/evidence/check-sources.py"
    spec = importlib.util.spec_from_file_location("providers_check",checker_path)
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    output = []
    for path in FILES:
        raw = path.read_bytes()
        report = json.loads(raw)
        assert report["status"] == "passed" and report["repetitions"] == 3 and report["warm_repetitions_per_state"] == 3
        assert (report["identity_bytes"],report["message_bytes"]) == (64,32)
        assert report["cross_security_group_ranking"] is False
        for record in report["records"]:
            assert record["restore"]["entropy_reads"] == record["restore"]["entropy_bytes"] == 0
            assert record["restore"]["state_unchanged"]
        count = checker.check_record(report)
        runner = "experiments/research/full_system_benchmark.py"
        assert checker.blob_hash(report["source_commit"],runner) == checker.blob_hash("6b5305a",runner)
        sizes = [x for r in report["records"] for x in r["generation"]["full_ciphertext_bytes"]]
        output.append(dict(file=path.relative_to(ROOT).as_posix(),file_sha256=sha256(raw).hexdigest(),
            source_commit=report["source_commit"],provider_occurrences_verified=count,
            security_group=report["security_group"],suite=report["suite"],
            cold_states=3,warm_pairs=9,restored_decryptions=9,all_successful=True,
            ciphertext_bytes=dict(count=len(sizes),minimum=min(sizes),maximum=max(sizes)),
            timing_seconds=report["timing_seconds"],environment=report["environment"],
            observed_process_tree_rss_bytes=max(p["sampled_process_tree_peak_rss_bytes"]
                for r in report["records"] for mode in ("generation","restore") for p in r[mode]["phases"])))
    result = dict(status="passed",schema="THREE-PROFILE-FULL-SYSTEM-EVIDENCE/1",profiles=output,
        same_benchmark_runner_verified=True,same_input_lengths_and_measurement_boundaries=True,
        equal_security_targets_established=False,cross_security_group_ranking=False,
        profile_count_is_not_HIBE_algorithm_count=True,private_state_files_opened=0,
        security_claim="none",backend_admitted=False,parameters_are_formal=False)
    (HERE/"comparison.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps(dict(status="passed",profiles=len(output),
        provider_occurrences=sum(row["provider_occurrences_verified"] for row in output),
        same_benchmark_runner_verified=True,private_state_files_opened=0),indent=2))


if __name__ == "__main__": main()
