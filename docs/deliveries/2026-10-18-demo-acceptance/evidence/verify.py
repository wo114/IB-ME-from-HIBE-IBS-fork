"""Read-only validation of this fixed demo acceptance, without native operations."""
import hashlib
import json
from pathlib import Path
import runpy
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def main():
    checks = 0

    def require(condition, label):
        nonlocal checks
        if not condition:
            raise ValueError(label)
        checks += 1

    def load(name):
        return json.loads((HERE / name).read_text(encoding="utf-8"))

    manifest = load("provenance.json")
    for name, expected in manifest["public_files"].items():
        require(hashlib.sha256((HERE / name).read_bytes()).hexdigest() == expected, name)
    for name, expected in manifest["final_source_files"].items():
        require(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected, name)
    for name, provider in manifest["providers"].items():
        raw = (ROOT / provider["path"]).read_bytes()
        require(hashlib.sha256(raw).hexdigest() == provider["sha256"], name + " SHA256")
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        require(blob == provider["git_blob_sha1"], name + " Git blob")

    builders = {
        "latte": "src/ibme/hibe/latte/native/build.py",
        "mldsa": "src/ibme/ibs/certified/native/build.py",
        "falcon": "src/ibme/ibs/certified/falcon_native/build.py",
    }
    for family, relative in builders.items():
        # Only the pure fingerprint helper executes, never the build main.
        helper = runpy.run_path(str(ROOT / relative))["source_id"]
        require(helper() == load(family + "-build.json")["source_id"], family + " source ABI")

    cards = json.loads((ROOT / "docs/deliveries/2026-10-18-main-showcase-cards/evidence/cards.json").read_text(encoding="utf-8"))["cards"]
    suites = {card["suite"]["ibs"]: card["suite"] for card in cards}
    cli = load("cli-mldsa44-raw.json")
    require(cli["status"] == "passed", "CLI status")
    require(cli["source_commit"] == manifest["cli_original_declared_commit"], "raw CLI tag unchanged")
    require(manifest["cli_declared_commit_is_incorrect"] is True, "label correction explicit")
    require(len(manifest["providers"]) == 131, "provider count")
    require(cli["parameters"] == suites["cert-ml-dsa"], "CLI complete parameters")
    require((cli["identity_bytes"], cli["message_bytes"]) == (64, 32), "CLI inputs")
    require(len(cli["commands"]) == 15, "CLI command count")
    for row in cli["commands"]:
        require(row["code"] == row["expected_code"], row["name"])
        require("stdout" not in row and "stderr" not in row, "no private CLI diagnostics")
    restore = cli["restore"]
    require(restore["status"] == "passed" and restore["original_state_unchanged"], "restore state")
    require(restore["entropy_bytes"] == restore["command"]["entropy_bytes"] == 0, "restore zero entropy")
    require(restore["new_root_or_keys_or_signature"] is False, "restore no generation")

    modes = {"normal", "wrong_sender", "wrong_receiver", "both_wrong", "tamper", "truncate"}
    for name in ("ui-mldsa44.json", "ui-falcon512.json", "ui-luo-compact.json"):
        record = load(name)
        require(record["suite"] == suites[record["suite"]["ibs"]], name + " exact suite")
        require(record["sizes"]["message"] == 38, name + " UTF8 message bytes")
        require(record["security"]["claim"] == "none", name + " claim")
        require(record["security"]["backend_admitted"] is False, name + " admission")
        require(record["security"]["parameters_are_formal"] is False, name + " parameters")
        observations = [row for row in record["observations"] if row["operation"] == "decrypt"]
        require(len(observations) == 6 and {row["mode"] for row in observations} == modes, name + " modes")
        for row in observations:
            require(row["expectation_met"] is True and row["bottom"] == (row["mode"] != "normal"), name + " " + row["mode"])
        require(not ({"master", "sender_key", "receiver_key", "wire", "message", "last_message", "identities"} & record.keys()), name + " public-only")
    require(load("falcon-profile-mismatch-before-fix.json")["suite"]["ibs_params"]["base_algorithm"] == "falcon-padded-1024", "original Falcon mismatch retained")
    require(load("ui-falcon512.json")["suite"]["ibs_params"]["base_algorithm"] == "falcon-padded-512", "corrected Falcon512")
    browser = load("browser-checks.json")
    require(sum(len(profile["checks"]) for profile in browser["profiles"]) == 18, "18 browser scenarios")
    require(browser["initial_primary_page_refresh_reconnect"] is True, "refresh reconnect")
    require(browser["service_restart_drops_ephemeral_session"] is True, "web restart boundary")
    suites_xml = list(ET.parse(HERE / "webui-catalog.xml").iter("testsuite"))
    require(sum(int(s.attrib["tests"]) for s in suites_xml) == 38, "38 targeted tests")
    require(all(int(s.attrib[k]) == 0 for s in suites_xml for k in ("failures", "errors", "skipped")), "tests no failure or skip")
    print(json.dumps(dict(status="passed", checks=checks, cli_commands=15,
                         zero_entropy_restore=True, browser_scenarios=18,
                         key_generations_by_verifier=0, private_state_reads=0)))


if __name__ == "__main__":
    main()
