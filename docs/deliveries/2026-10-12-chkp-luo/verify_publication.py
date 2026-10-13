"""Read-only publication checks; no private state or cryptographic sampling.

Historical manifests remain tied to their original Git source, not silently
rewritten after integration. Run from a checkout with the recorded Git history.
This checks consistency and receipt semantics, not experimental authenticity.
"""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
HANDOFF = "4ea086eee8b0f4c31d0b724b5b8a732aff8bbffb"
UPSTREAM = "14f11634840e21751f9f8d0122dddf8651ee4eef"
CHKP = "docs/research/2026-10-12-chkp-closure"
LUO = "docs/research/2026-10-12-luo-final-acceptance"
REGISTRY = "src/ibme/assembly/registry.py"
ADDITION = (
    "    # Public optional entry, with no Sage import on non-Sage hosts. The caller\n"
    "    # supplies the private arithmetic executable through an explicit local\n"
    "    # environment setting; suite JSON cannot specify executables or imports.\n"
    "    from ibme.hibe.mp12_chkp import default_backend_spec\n"
    "    specs.append(default_backend_spec())\n"
)


def need(condition, message):
    if not condition:
        raise ValueError(message)


def blob(commit, name):
    return subprocess.check_output(["git", "show", commit + ":" + name], cwd=ROOT)


def digest(data):
    return sha256(data).hexdigest()


def normalized(data):
    # Only live source comparison tolerates checkout line endings. Historical
    # manifest hashes and archived experiment evidence are checked exactly.
    return data.replace(b"\r\n", b"\n")


def run():
    sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
    from experiments.research import audit_chkp_delivery as gate
    from ibme.hibe.chkp import research_params
    result = dict(
        passed=False, handoff=HANDOFF, upstream=UPSTREAM,
        experiments_rerun=False, private_state_read=False,
        historical_execution_authenticated=False,
        security_claim="none", backend_admitted=False, parameters_are_formal=False,
    )
    manifest_bytes = (ROOT / CHKP / "source-manifest.json").read_bytes()
    need(manifest_bytes == blob(HANDOFF, CHKP + "/source-manifest.json"),
         "historical CHKP manifest changed")
    manifest = json.loads(manifest_bytes)
    evidence = gate.manifest_files(ROOT / CHKP, manifest["evidence_files"], source=False)
    for item in manifest["evidence_files"]:
        need(digest(blob(HANDOFF, CHKP + "/" + item["path"])) == item["sha256"],
             "CHKP evidence not committed at handoff: " + item["path"])
    changed_sources = []
    for item in manifest["source_files"]:
        name = item["path"]
        gate.relative(name)
        original = blob(manifest["source_commit"], name)
        need(digest(original) == item["sha256"], "historical Git source hash: " + name)
        live = (ROOT / name).read_bytes()
        if normalized(live) != normalized(original):
            changed_sources.append(name)
            if name == "pyproject.toml":
                need(normalized(live) == normalized(blob(UPSTREAM, name)),
                     "packaging differs from the reviewed upstream entry")
                continue
            need(name == REGISTRY, "unreviewed current source difference: " + name)
            old = normalized(original).decode("utf-8")
            expected = old.removesuffix("    return BackendRegistry(specs)\n")
            need(expected != old, "unexpected baseline registry footer")
            expected += ADDITION + "    return BackendRegistry(specs)\n"
            need(normalized(live).decode("utf-8") == expected,
                 "registry differs beyond the upstream MP12 registration")
    need(changed_sources == ["pyproject.toml", REGISTRY], "unexpected integrated source changes")
    preserved = [
        "pyproject.toml", "src/ibme/hibe/mp12_chkp/__init__.py",
        "src/ibme/lattice/research/__init__.py",
        *["experiments/research/first_suite/" + name + ".py" for name in (
            "computational_parameter_plan", "computational_root", "hibe_probe",
            "hibe_reference", "hibe_registry")],
    ]
    for name in preserved:
        need(normalized((ROOT / name).read_bytes()) == normalized(blob(UPSTREAM, name)),
             "upstream installed API changed: " + name)

    suite, params = gate.selected_suite(), research_params()
    need(suite.digest == manifest["suite_digest"], "CHKP suite changed")
    for name in gate.REQUIRED:
        receipt = gate.document(evidence[name])
        gate.safe_flags(receipt, required=True)
        group, phase = Path(name).parts[1], Path(name).stem
        if group == "lifecycle":
            gate.lifecycle_receipt(receipt, phase, params)
        elif group == "combination":
            need("failure_type" not in receipt and type(receipt.get("repetition_count")) is int
                 and receipt["repetition_count"] == 1, "invalid combination repetition")
            gate.validate_receipt(receipt, phase, suite)
        else:
            need(type(receipt.get("repetition_count")) is int and receipt["repetition_count"] == 1,
                 "invalid CLI repetition")
            source = gate.relative(receipt.get("provenance", {}).get(
                "source_relative", "test-results/unused-setup-source"))
            need(len(source.parts) > 1 and source.parts[0] == "test-results", "CLI source path")
            gate.validate_cli_receipt(receipt, phase, suite, ROOT.joinpath(*source.parts))
    need(gate.resume_receipts(evidence, params), "missing preserved recovery history")
    historical = json.loads((ROOT / CHKP / "public-audit-result.json").read_bytes())
    need(historical["passed"] is True and historical["phases_checked"] == len(gate.REQUIRED),
         "original audit receipt missing")

    luo_manifest = (ROOT / LUO / "MANIFEST.json").read_bytes()
    need(luo_manifest == blob(HANDOFF, LUO + "/MANIFEST.json"), "Luo manifest changed")
    luo = json.loads(luo_manifest)
    for name, expected in luo["files"].items():
        gate.relative(name)
        need(digest((ROOT / LUO / name).read_bytes()) == expected, "Luo archive hash: " + name)
        need(digest(blob(HANDOFF, LUO + "/" + name)) == expected, "Luo Git archive hash: " + name)
    result.update(
        passed=True, historical_source_commit=manifest["source_commit"],
        historical_source_git_blobs_checked=len(manifest["source_files"]),
        chkp_evidence_files_checked=len(evidence), chkp_phases_checked=len(gate.REQUIRED),
        luo_final_files_checked=len(luo["files"]), historical_failure_preserved=True,
        current_source_differences=changed_sources, upstream_api_files_preserved=preserved,
        suite_digest=suite.digest,
        limitation="Git/content and receipt consistency; not a fresh end-to-end run or security proof.",
    )
    return result


if __name__ == "__main__":
    try:
        answer = run()
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError) as exc:
        print(json.dumps(dict(passed=False, error=str(exc)), ensure_ascii=False, indent=2))
        raise SystemExit(2)
    print(json.dumps(answer, ensure_ascii=False, indent=2))
