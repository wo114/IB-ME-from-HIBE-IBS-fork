"""Read-only standard-library verification; no private objects or entropy."""
import gzip
from hashlib import sha256
import json
from pathlib import Path
import re
from statistics import median
from render_tables import render

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def describe(values):
    return {"count": len(values), "min": min(values), "median": median(values), "max": max(values)} if values else None


def verify():
    manifest = json.loads((HERE/"MANIFEST.json").read_text())
    for relative, digest in manifest["files_sha256"].items():
        path = ROOT/relative
        require(path.resolve().is_relative_to(ROOT), "manifest path escapes root")
        require(sha256(path.read_bytes()).hexdigest() == digest, "manifest file mismatch: "+relative)
    report = json.loads((HERE/"benchmark.json").read_text())
    for name, expected_text in render(report).items():
        require((HERE/name).read_text(encoding="utf-8") == expected_text, "generated table differs: "+name)
    require(report["schema"] == "IBME/SRGG-COMPACT-BENCHMARK/1", "report schema")
    for relative, digest in report["source_sha256"].items():
        require(sha256((ROOT/relative).read_bytes()).hexdigest() == digest, "runtime source mismatch: "+relative)
    require(report["source_bytes_unchanged_during_measurement"] is True, "sources changed during run")
    require(report["schedule"] == {
        "profiles": ["PARAM-I", "PARAM-II", "PARAM-III"], "interpretation": "table-standard-deviation",
        "independent_secure_random_roots_per_profile": 3, "warm_sign_verify_per_root": 3,
        "paired_codec_repetitions_per_object": 5, "identity_bytes": 64, "message_bytes": 32,
        "external_failure_replacement": False, "restore_order_alternates_by_run": True}, "schedule mismatch")
    rows = report["runs"]
    expected = {(p, i, m) for p in ("PARAM-I", "PARAM-II", "PARAM-III") for i in range(3)
                for m in ("generate", "restore-json", "restore-compact")}
    require(len(rows) == 27 and {(x["profile_name"], x["run_index"], x["mode"]) for x in rows} == expected,
            "fixed schedule has missing or duplicate workers")
    checks = 0
    for row in rows:
        if row["status"] != "passed":
            continue
        require(row["process_exit_code"] == 0 and row["external_stop_reason"] is None, "passed worker was stopped")
        raw_name = row["profile_name"].lower()+"-"+str(row["run_index"])+"-"+row["mode"]+".json"
        require(json.loads((HERE/"evidence"/raw_name).read_text()) == row, "worker raw row differs")
        reference = json.loads((ROOT/"docs/research/team-b-delivery/2026-10-18-srgg-source-schur"/
            ("param-"+{"PARAM-I": "i", "PARAM-II": "ii", "PARAM-III": "iii"}[row["profile_name"]]+
             "-bounded-final-lifecycle.json")).read_text())
        require(row["published_inputs"] == reference["published_inputs"] and
                row["profile"] == reference["profile"], "published parameters changed")
        require(row["identity_bytes"] == 64 and row["message_bytes"] == 32 and
                row["randomness"] == "SecureRandom", "measurement input/randomness mismatch")
        require(row["numerical_options"] == reference["numerical_options"], "numerical options changed")
        expected_checks = ({"first-verify", "codecs-zero-entropy"} | {f"warm-verify-{i}" for i in range(3)} |
            {name+"-compact-json-equality" for name in ("public", "master", "key", "signature")} |
            {f"{name}-{variant}-roundtrip-{i}" for name in ("public", "master", "key", "signature")
             for variant in ("json", "compact") for i in range(5)} if row["mode"] == "generate" else
            {"cached-key-zero-entropy", "restored-old-signature-valid", "restored-key-resigned"})
        require(set(row["checks"]) == expected_checks, "missing or unexpected functional checks")
        require(row["private_material_exported"] is False and all(v is True for v in row["checks"].values()),
                "private-data flag or functional failure")
        require(row["security_claim"] == "none" and row["backend_admitted"] is False and
                row["parameters_are_formal"] is False and row["nist_security_category"] is None,
                "security metadata changed")
        checks += len(row["checks"])
        if row["mode"] == "generate":
            require(row["dense_coefficient_matrix_materialized"] is False and
                    row["checks"]["codecs-zero-entropy"] is True, "dense expansion or codec entropy")
        else:
            require(row["extraction_calls"] == 0 and row["setup_attempts"] == 0 and
                    row["checks"]["cached-key-zero-entropy"] is True, "restoration regenerated a key")
        samples = []
        sample_path = (HERE/row["rss_samples"]).resolve()
        require(sample_path.is_relative_to(HERE/"evidence"), "RSS path escapes evidence")
        with gzip.open(sample_path, "rt", encoding="utf-8") as handle:
            for line in handle:
                value = json.loads(line)
                require(set(value) == {"offset_ns", "self_rss_bytes", "tree_rss_bytes"} and
                        all(type(x) is int and x >= 0 for x in value.values()) and
                        value["tree_rss_bytes"] >= value["self_rss_bytes"] and
                        (not samples or value["offset_ns"] >= samples[-1]["offset_ns"]), "RSS sample fields/order")
                samples.append(value)
        live = [x for x in samples if x["self_rss_bytes"] > 0]
        require(row["rss_sample_count"] == len(live) and row["sampled_tree_peak_rss_bytes"] ==
                max((x["tree_rss_bytes"] for x in live), default=None) and row["sampled_self_peak_rss_bytes"] ==
                max((x["self_rss_bytes"] for x in live), default=None), "RSS maximum/count mismatch")
        for phase in row["phases"]:
            start = round(phase["start_offset_seconds"]*1e9)
            end = start+round(phase["seconds"]*1e9)
            within = [x for x in live if start <= x["offset_ns"] <= end]
            require(phase["rss_sample_count"] == len(within) and phase["sampled_tree_peak_rss_bytes"] ==
                    max((x["tree_rss_bytes"] for x in within), default=None) and phase["sampled_self_peak_rss_bytes"] ==
                    max((x["self_rss_bytes"] for x in within), default=None), "phase RSS mismatch")
    for profile in report["schedule"]["profiles"]:
        for mode in ("generate", "restore-json", "restore-compact"):
            selected = [x for x in rows if x["profile_name"] == profile and x["mode"] == mode]
            passed = [x for x in selected if x["status"] == "passed"]
            summary = report["summary"][profile]["modes"][mode]
            require(summary["scheduled"] == len(selected) and summary["passed"] == len(passed), "worker statistics")
            require(summary["process_wall_seconds"] == describe([x["process_wall_seconds"] for x in passed]),
                    "process time statistics")
            for field in ("sampled_tree_peak_rss_bytes", "kernel_lifetime_peak_rss_bytes"):
                require(summary[field] == describe([x[field] for x in passed if x.get(field) is not None]),
                        "RSS summary mismatch")
            groups = {}
            for row in passed:
                phases = {}
                for phase in row["phases"]:
                    phases.setdefault(re.sub(r"-\d+$", "", phase["name"]), []).append(phase["seconds"])
                for name, values in phases.items():
                    groups.setdefault(name, []).append(median(values))
            require(summary["phase_seconds_per_run_medians"] == {k: describe(v) for k, v in groups.items()},
                    "within-root repeats counted as independent roots")
        generated = [x for x in rows if x["profile_name"] == profile and x["mode"] == "generate" and x["status"] == "passed"]
        for name in ("public", "master", "key", "signature"):
            pairs = [x["object_sizes_bytes"][name] for x in generated]
            size = report["summary"][profile]["object_sizes_bytes"][name]
            require(all(size[k] == describe([x[k] for x in pairs]) for k in ("json", "compact")) and
                    size["paired_json_over_compact_ratio"] == describe([x["json"]/x["compact"] for x in pairs]),
                    "wire statistics mismatch")
    require(report["status"] == ("passed" if all(x["status"] == "passed" for x in rows)
                                  else "completed-with-failures"), "failure rows were hidden")
    return {"status": report["status"], "workers": len(rows), "functional_checks": checks,
            "manifest_files": len(manifest["files_sha256"]), "source_files": len(report["source_sha256"])}


if __name__ == "__main__":
    print(json.dumps(verify(), sort_keys=True))
