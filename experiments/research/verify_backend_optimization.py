"""Read-only consistency/provenance checks; does not replay cryptography."""
import argparse
import json
import math
from pathlib import Path, PurePosixPath
import statistics

from .backend_optimization_probe import expected_suite, summarize_pairs

LABELS = ("A", "B", "C", "Luo", "Falcon")
CHECKS = {"truncated", "appended", "duplicated", "byte-change", "valid-outer-invalid-inner",
          "ibs-reached-and-false", "wrong-receiver", "wrong-sender", "both-wrong"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_batch(data, installation, manifest):
    label = data["label"]
    require(label in LABELS and data["status"] == "passed", "batch status/label")
    count = 1 if label == "C" else 3
    require(data["independent_roots"] == count and len(data["records"]) == count, "root count")
    require({r["root"] for r in data["records"]} == set(range(count)), "distinct root indices")
    require(data["security_claim"] == "none" and data["backend_admitted"] is False
            and data["parameters_are_formal"] is False and data["cross_security_group_ranking"] is False,
            "batch claim changed")
    suite = expected_suite(label)
    for record in data["records"]:
        require(record["status"] == "passed" and record["label"] == label, "root failed")
        require(record["source_commit"] == installation["source_commit"] == manifest["source_commit"], "source mismatch")
        require(record["wheel_sha256"] == installation["wheel_sha256"] == manifest["wheel_sha256"], "wheel mismatch")
        require(record["suite"] == suite.to_dict() and record["suite_digest"] == suite.digest, "frozen Suite mismatch")
        require(record["identity_bytes"] == 64 and record["message_bytes"] == 32, "input mismatch")
        require(record["no_outer_retry"] is True and record["randomness"] == "fresh system CSPRNG", "generation policy")
        require(record["security_claim"] == "none" and record["backend_admitted"] is False
                and record["parameters_are_formal"] is False, "root claim changed")
        require(set(record["checks"]) == CHECKS and all(x is True for x in record["checks"].values()), "negative controls failed")
        root = PurePosixPath(installation["runtime_root"])
        require(bool(record["providers"]), "no observed source providers")
        for name, provider in record["providers"].items():
            path = PurePosixPath(provider["path"])
            require(path.is_relative_to(root), "source checkout used as installed runtime")
            relative = str(path.relative_to(root))
            require(provider["sha256"] == manifest["files"].get(relative), "provider source digest mismatch: "+name)
        require(all(r["status"] == "passed" and math.isfinite(r["seconds"]) and r["seconds"] > 0 for r in record["phases"]), "failed phase")
        repetitions = data["repetitions_per_root"]
        if label == "C":
            originals = [r for r in record["phases"] if r["name"] == "original-stateless-decrypt"]
            prepared = [r for r in record["phases"] if r["name"] == "prepared-decrypt"]
            preparation = [r for r in record["phases"] if r["name"] == "receiver-preparation"]
            require(len(originals) == 2 and len(preparation) == 1 and len(prepared) == repetitions, "C phase counts")
            require(all(r["native_calls"].get("hibe:derive") == 1 for r in originals+preparation), "C real derivation count")
            require(all(r["native_calls"].get("hibe:derive", 0) == 0 and r["entropy"]["bytes"] == 0 for r in prepared), "C prepared path sampled again")
            require(record["prepared_session"]["leaf_key_bytes"] > 0, "C retained leaf accounting")
        else:
            for operation in ("encrypt", "decrypt"):
                for mode in ("off", "on"):
                    rows = [r for r in record["phases"] if r["name"] == operation and r["mode"] == mode]
                    require(len(rows) == repetitions, "paired phase counts")
                    if label in ("A", "Falcon") and operation == "decrypt":
                        family = "mldsa" if label == "A" else "falcon"
                        require(all(r["native_calls"].get(family+":verify") == (2 if mode == "off" else 1) for r in rows), "certificate verification not reduced as specified")
            if label == "B":
                require(record["cache"]["entries"] == 1 and record["cache"]["misses"] == 1
                        and record["cache"]["hits"] >= repetitions, "B preparation not reused")
    if label != "C":
        require(summarize_pairs(data["records"]) == data["summary"], "stored summary disagrees with raw observations")
    return summarize(data)


def summarize(data):
    if data["label"] != "C":
        return {name:dict(off_seconds=statistics.median(row["root_off_medians"]),
                         on_seconds=statistics.median(row["root_on_medians"]),
                         median_root_speedup=row["median_root_speedup"],
                         root_speedup_min=min(row["root_speedups"]), root_speedup_max=max(row["root_speedups"]))
                for name,row in data["summary"].items()}
    record = data["records"][0]
    values = lambda name: [r["seconds"] for r in record["phases"] if r["name"] == name]
    original = statistics.median(values("original-stateless-decrypt"))
    prepared = statistics.median(values("prepared-decrypt"))
    preparation = values("receiver-preparation")[0]
    return dict(original_decrypt_seconds=original, prepared_decrypt_seconds=prepared,
                preparation_seconds=preparation, leaf_key_bytes=record["prepared_session"]["leaf_key_bytes"],
                repeated_decrypt_ratio=original/prepared,
                amortized_seconds={str(n):(preparation+n*prepared)/n for n in (1,2,3,10,100)},
                independent_roots=1, paired_benchmark=False)


def verify(directory):
    installation = json.loads((directory/"installation.json").read_bytes())
    manifest = json.loads((directory/"source-manifest.json").read_bytes())
    result, environments = {}, []
    for label in LABELS:
        data = json.loads((directory/(label+".json")).read_bytes())
        result[label] = validate_batch(data, installation, manifest)
        environments.extend(r["environment"] for r in data["records"])
    require(all(e == environments[0] for e in environments), "different declared benchmark environments")
    return dict(status="consistent", scope="read-only metadata, counts and arithmetic; not a cryptographic rerun",
                source_commit=installation["source_commit"], summary=result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
