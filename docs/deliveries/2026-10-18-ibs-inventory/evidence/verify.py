"""Verify public receipts and source lineage; never open experiment private state."""

import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import statistics
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SOURCE = "fc1f342faecd16bc80b63dbc851e7f67601e36a0"
GIT_BLOBS = {}
BENCHMARK_FILES = set()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(name):
    return json.loads((HERE / name).read_bytes())


def git_blob(relative):
    if relative not in GIT_BLOBS:
        GIT_BLOBS[relative] = subprocess.check_output(
            ["git", "show", SOURCE + ":" + relative], cwd=ROOT)
    return GIT_BLOBS[relative]


def digest_variants(raw):
    # The collector captured actual Windows/WSL-mounted bytes. Git has LF.
    # Accept only LF/CRLF spelling of identical content, including for a
    # recipient checking this receipt from a Linux checkout.
    normalized = raw.replace(b"\r\n", b"\n")
    return {sha256(raw).hexdigest(), sha256(normalized).hexdigest(),
            sha256(normalized.replace(b"\n", b"\r\n")).hexdigest()}


def check_inventory_sources(data):
    require(data["audited_runtime_source_commit"] == SOURCE, "source commit changed")
    require(data["audit_script_sha256"] in digest_variants((HERE / "audit.py").read_bytes()),
            "collector differs from captured source")
    for relative, expected in data["source_providers"].items():
        require(relative.startswith(("src/", "experiments/")) and
                relative.endswith(".py") and ".." not in Path(relative).parts,
                "unexpected source path")
        blob = git_blob(relative)
        require(expected in digest_variants(blob), "captured source hash changed: " + relative)
        require(blob.replace(b"\r\n", b"\n") ==
                (ROOT / relative).read_bytes().replace(b"\r\n", b"\n"),
                "working source differs from recorded Git source: " + relative)


def check_benchmark_sources(value, inherited=SOURCE):
    count = 0
    if isinstance(value, dict):
        revision = value.get("source_commit", inherited)
        require(revision == SOURCE, "benchmark source commit differs")
        for provider in value.get("source_providers", {}).values():
            path = provider["path"].replace("\\", "/")
            anchors = [anchor for anchor in ("/src/ibme/", "/experiments/research/")
                       if anchor in path]
            require(len(anchors) == 1, "unexpected benchmark source root")
            relative = path[path.index(anchors[0]) + 1:]
            require(relative.endswith(".py") and ".." not in Path(relative).parts,
                    "unexpected benchmark source path")
            blob = git_blob(relative)
            require(provider["sha256"] in digest_variants(blob),
                    "benchmark provider hash changed: " + relative)
            require(blob.replace(b"\r\n", b"\n") ==
                    (ROOT / relative).read_bytes().replace(b"\r\n", b"\n"),
                    "benchmark working source changed: " + relative)
            BENCHMARK_FILES.add(relative)
            count += 1
        for key, child in value.items():
            if key != "source_providers":
                count += check_benchmark_sources(child, revision)
    elif isinstance(value, list):
        count += sum(check_benchmark_sources(child, inherited) for child in value)
    return count


def verify():
    inventory = read("inventory-current.json")
    check_inventory_sources(inventory)
    require(inventory["counts"] == dict(complete_research_ibs_algorithms=10,
            default_selector_algorithms=6, not_in_default_selector_algorithms=4),
            "unexpected inventory counts")
    require(inventory["project_secure_random_read_calls"] == 0 and
            inventory["key_generation_signing_or_private_state_read_performed"] is False,
            "metadata collection crossed execution boundary")
    broken = deepcopy(inventory)
    broken["source_providers"][next(iter(broken["source_providers"]))] = "0" * 64
    try:
        check_inventory_sources(broken)
    except ValueError as error:
        require("captured source hash changed" in str(error), "unrelated tamper failure")
    else:
        raise ValueError("tampered provider digest was accepted")

    benchmark = read("latte-c64b.json")
    functional = read("c64b-functional.json")
    canonical, original = read("c64b-suite.json"), read("c64b-candidate.json")
    require(len(canonical) == len(original) == 1, "unexpected suite size")
    selection = canonical[0]["selection"]
    require(selection == original[0]["selection"] == benchmark["selection"] ==
            inventory["c64b_candidate"]["selection"] == functional["results"][0]["selection"],
            "parameters changed between metadata, functionality, and measurement")
    require(benchmark["source_commit"] == SOURCE and benchmark["status"] == "passed",
            "benchmark failed or source changed")
    occurrences = check_benchmark_sources(benchmark)
    require(occurrences > 0, "benchmark captured no source providers")
    # The functional runner does not capture providers. Check its current
    # source independently, without attributing a runtime capture to it.
    runner = "experiments/run_combination_matrix.py"
    runner_blob = git_blob(runner)
    require(runner_blob.replace(b"\r\n", b"\n") ==
            (ROOT / runner).read_bytes().replace(b"\r\n", b"\n"), "functional runner changed")
    require(functional["status"] == "pass" and functional["executed_cases"] == 1 and
            functional["executed_checks"] == 34, "functional case/check counts changed")
    require(len(functional["results"][0]["checks"]) == 34 and
            all(row["status"] == "pass" for row in functional["results"][0]["checks"]),
            "functional check failed")
    for record in (inventory, benchmark, functional):
        require(record["security_claim"] == "none" and record["backend_admitted"] is False
                and record["parameters_are_formal"] is False, "security metadata changed")

    require(len(benchmark["records"]) == benchmark["repetitions"] == 3 and
            benchmark["warm_repetitions_per_state"] == 3, "repetition counts changed")
    phases, wires, sizes = [], [], []
    for row in benchmark["records"]:
        generation, restore = row["generation"], row["restore"]
        require(generation["status"] == restore["status"] == "passed", "worker failed")
        require(generation["entropy_reads"] > 0 and generation["entropy_bytes"] > 0,
                "generation recorded no private entropy")
        require(restore["entropy_reads"] == restore["entropy_bytes"] == 0 and
                restore["state_unchanged"] is True, "restore consumed entropy or wrote state")
        require(generation["native_engine_rebuild"] is False and
                restore["native_engine_rebuild"] is False, "native engine rebuilt")
        require(generation["native_operation_counts_after_runtime_build"]["latte:extract"] == 1,
                "leaf generation was not measured")
        wires.extend(generation["full_ciphertext_bytes"])
        sizes.append(generation["sizes"])
        phases.extend(generation["phases"] + restore["phases"])
    require(len(wires) == 12, "unexpected ciphertext sample count")
    for name, summary in benchmark["timing_seconds"].items():
        observations = [phase["seconds"] for phase in phases if phase["name"] == name]
        require(observations == summary["observations"], "timing observations changed: " + name)
        require(len(observations) == summary["count"], "timing count changed: " + name)
        require(statistics.median(observations) == summary["median"], "median changed: " + name)
    require(all(phase["status"] == "passed" for phase in phases), "measured phase failed")
    for name in ("warm-encrypt", "warm-decrypt", "restored-decrypt"):
        require(benchmark["timing_seconds"][name]["count"] == 9, "missing warm/restore sample")

    return dict(schema="PUBLIC-IBS-VERIFICATION/1", status="passed", source_commit=SOURCE,
        inventory_source_files=len(inventory["source_providers"]),
        benchmark_provider_occurrences=occurrences,
        distinct_benchmark_commit_file_pairs=len(BENCHMARK_FILES),
        functional_runner_independent_source_sha256=sha256(runner_blob).hexdigest(),
        functional_receipt_has_no_runtime_provider_capture=True,
        tampered_inventory_provider_digest_rejected=True,
        source_normalization="LF/CRLF only; actual capture hashes retained",
        metadata_collection_private_random_reads=0, verification_private_state_files_opened=0,
        benchmark_independent_states=3, warm_encryptions=9, warm_decryptions=9,
        restored_decryptions=9, restores_zero_entropy_and_unchanged=True,
        functional_cases=1, functional_checks=34,
        timing_medians_seconds={k: v["median"] for k, v in benchmark["timing_seconds"].items()},
        full_ciphertext_bytes=dict(count=len(wires), minimum=min(wires), maximum=max(wires)),
        sampled_process_tree_peak_rss_bytes=max(p["sampled_process_tree_peak_rss_bytes"] for p in phases),
        persisted_object_bytes={name: dict(minimum=min(s[name] for s in sizes),
            maximum=max(s[name] for s in sizes)) for name in sizes[0]},
        artifact_sha256={name: sha256((HERE / name).read_bytes()).hexdigest() for name in
            ("inventory-current.json", "latte-c64b.json", "c64b-functional.json",
             "c64b-suite.json", "c64b-candidate.json", "native-provenance.json")},
        security_claim="none", backend_admitted=False, parameters_are_formal=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = verify()
    encoded = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
    print(encoded, end="")
