"""Read-only checks of observations, ablation, artifact hashes and Git sources."""
import hashlib
import io
import json
from pathlib import Path
import statistics
import subprocess
import tarfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
checks = 0


def require(condition, message):
    global checks
    if not condition:
        raise AssertionError(message)
    checks += 1


def main():
    report = json.loads((HERE / "placement.json").read_bytes())
    provenance = json.loads((HERE / "provenance.json").read_bytes())
    wheel = json.loads((HERE / "wheel-manifest.json").read_bytes())
    for name, digest in provenance["artifacts"].items():
        require(hashlib.sha256((HERE / name).read_bytes()).hexdigest() == digest, "artifact hash " + name)
    require(report["status"] == "passed" and len(report["records"]) == 18, "18 completed blocks")
    require(report["independent_roots"] == 3 and report["samples_per_block"] == 5, "three states/five samples")
    require(report["identity_bytes"] == 64 and report["message_bytes"] == 32, "fixed inputs")
    require(report["security_claim"] == "none" and report["backend_admitted"] is False
            and report["parameters_are_formal"] is False, "security metadata unchanged")
    require(wheel["wheel_sha256"] == report["prepared_runtime"]["wheel_sha256"] == provenance["wheel_sha256"], "same wheel")
    reference = report["records"][0]
    for row in report["records"]:
        for field in ("suite_digest", "loaded_module_sha256", "diagnostic_native_calls",
                      "diagnostic_source_validation_calls", "diagnostic_entropy"):
            require(row[field] == reference[field], "unchanged " + field)
        require(row["fixed_state_unchanged"] and row["zero_entropy_restore"], "fixed state restored")
        require(row["diagnostic_source_validation_calls"] == dict(latte=2, mldsa=4), "source verification retained")
        require(row["diagnostic_entropy"] == dict(bytes=65644, reads=5), "fresh encryption entropy use")
        require(len(row["full_ciphertext_bytes"]) == 5, "complete ciphertext sizes")
        for operation in ("encrypt", "decrypt"):
            require(len(row["seconds"][operation]) == 5 and all(t > 0 for t in row["seconds"][operation]), "valid observations")
    for state in range(3):
        rows = [r for r in report["records"] if r["state_index"] == state]
        order = [r["variant"] for r in sorted(rows, key=lambda r: r["block_index"])]
        require(order == list(reversed(order)), "balanced mirrored order")
        require(set(order) == {"source", "windows_wheel", "wsl_wheel"}, "three ablation placements")
    for variant in report["timing_seconds"]:
        for operation in ("encrypt", "decrypt"):
            values = [t for row in report["records"] if row["variant"] == variant for t in row["seconds"][operation]]
            summary = report["timing_seconds"][variant][operation]
            require(len(values) == summary["count"] == 30, "30 observations per arm")
            require(values == summary["observations"] and statistics.median(values) == summary["median"], "summary arithmetic")
            for state in range(3):
                values = [t for row in report["records"] if row["variant"] == variant
                          and row["state_index"] == state for t in row["seconds"][operation]]
                require(len(values) == 10 and statistics.median(values) == report["per_state_median_seconds"][variant][operation][state], "per-state plot arithmetic")
    generation = json.loads((HERE / "generation.json").read_bytes())
    require(len({s["public_key_sha256"] for s in generation["states"]}) == 3, "three distinct generated public keys")
    for state in generation["states"]:
        require(state["generation_status"] == state["restore_status"] == "passed"
                and state["generation_done"] and state["restore_entropy_bytes"] == 0, "completed original state")
    cli = json.loads((HERE / "cli.json").read_bytes())
    require(cli["parameters"] == report["suite"], "CLI uses the measured suite")
    require(cli["status"] == "passed" and len(cli["commands"]) == 15, "15 real CLI cases")
    require(cli["restore"]["entropy_bytes"] == 0 and cli["restore"]["original_state_unchanged"], "zero-entropy CLI replay")
    for command in cli["commands"]:
        require(command["code"] == command["expected_code"] and command["exception"] is None, "CLI expected result")
    # One Git archive avoids hundreds of Git processes. It contains tracked
    # public source only and is read in memory, never extracted to disk.
    raw = subprocess.run(["git", "archive", "--format=tar", report["source_commit"], "src/ibme",
                          "experiments"], cwd=ROOT, check=True,
                         stdout=subprocess.PIPE).stdout
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        sources = {entry.name: archive.extractfile(entry).read() for entry in archive if entry.isfile()}
    exact, normalized, digests = 0, 0, set()
    for name, digest in wheel["files"].items():
        if not name.startswith(("ibme/", "experiments/")):
            continue
        path = "src/" + name if name.startswith("ibme/") else name
        raw = sources[path]
        value = hashlib.sha256(raw).hexdigest()
        if value == digest:
            exact += 1
        else:
            # Windows checkout can carry CRLF. Only known text files permit
            # newline normalization; no arbitrary binary rewrite is accepted.
            require(Path(name).suffix in (".py", ".c", ".h", ".json", ".html", ".js", ".css", ".md", ".txt"), "text normalization only")
            local = (ROOT / path).read_bytes()
            require(hashlib.sha256(local).hexdigest() == digest and local.replace(b"\r\n", b"\n") == raw.replace(b"\r\n", b"\n"), "Git/checkout text correspondence")
            normalized += 1
        digests.add(digest)
        require(True, "packaged Git source")
    for row in report["records"]:
        for digest in row["loaded_module_sha256"].values():
            require(digest in digests, "loaded provider exists in fixed wheel/Git")
    for provider in cli["providers"].values():
        require(provider["sha256"] in digests, "CLI provider exists in fixed wheel/Git")
        require(Path(provider["path"]).as_posix().startswith(report["prepared_runtime"]["runtime_root"] + "/"), "CLI used the installed runtime")
    for name in ("profile-source.json", "profile-wsl.json"):
        profile = json.loads((HERE / name).read_bytes())
        require(profile["suite_digest"] == report["suite_digest"] and profile["repetitions"] == 5, "same profiled suite")
    print(json.dumps(dict(status="passed", checks=checks, packaged_git_files=exact+normalized,
                         git_exact=exact, git_text_newline_normalized=normalized,
                         loaded_provider_checks=len(report["records"])*len(reference["loaded_module_sha256"])), sort_keys=True))


if __name__ == "__main__":
    main()
