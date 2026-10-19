"""Verify this public integration receipt using only the Python standard library.

No private state, Sage, native library, randomness or cryptographic experiment
is used. Source hashes bind the recorded run to the delivered implementation.
"""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def verify():
    checks = 0
    def check(condition, label):
        nonlocal checks
        if not condition: raise ValueError(label)
        checks += 1
    manifest = json.loads((HERE/"manifest.json").read_bytes())
    for path, digest in manifest["source_files"].items():
        target = (ROOT/path).resolve()
        check(target.is_relative_to(ROOT), "source outside checkout")
        check(hashlib.sha256(target.read_bytes()).hexdigest() == digest, "source changed: "+path)
    for path, digest in manifest["artifacts"].items():
        target = (HERE/path).resolve()
        check(target.is_relative_to(HERE), "artifact outside delivery")
        check(hashlib.sha256(target.read_bytes()).hexdigest() == digest, "artifact changed: "+path)
    receipt = json.loads((HERE/"evidence/integration.json").read_bytes())
    check(receipt["status"] == "passed" and receipt["profile"] == "PARAM-I", "actual profile")
    check(manifest["implementation_commit"].startswith(receipt["source_commit"]), "execution source")
    check(receipt["repetitions"] == 1 and receipt["identity_bytes"] == 64 and receipt["message_bytes"] == 32, "input counts")
    suite = receipt["parameters"]
    check(suite["ibs"] == "sageloli-rsis" and suite["ibs_version"] == "Sageloli-RSIS-structured-v3", "v3 selection")
    check(suite["hibe"] == "latte" and suite["transport"] == "hybrid" and suite["protocol"] == "byteauth-v1", "actual composition")
    check((suite["ibs_params"]["d"], suite["ibs_params"]["k"], suite["ibs_params"]["l"]) == (2048,65,132), "full paper dimensions")
    check(suite["hybrid_limits"]["max_payload_bytes"] == 8*2**20, "explicit payload budget")
    for record in (receipt, suite, receipt["acceptance"]):
        check(record["security_claim"] == "none" and record["backend_admitted"] is False
              and record["parameters_are_formal"] is False, "unchanged safety metadata")
    names = [row["name"] for row in receipt["commands"]]
    check(len(names) == len(set(names)) == 15, "15 actual CLI steps")
    rejected = {"wrong-sender", "wrong-receiver", "both-wrong", "truncated", "appended", "duplicate", "changed"}
    check(rejected <= set(names), "required CLI rejections")
    for row in receipt["commands"]:
        check(row["code"] == row["expected_code"] == (1 if row["name"] in rejected else 0), "CLI result")
        check(row["exception"] is None, "CLI unexpected exception")
        if row["name"] in ("same-sender", "same-receiver"):
            check(row["entropy_bytes"] == row["entropy_reads"] == 0, "fixed key entropy")
    calls = {name: sum(row["calls"].get(name,0) for row in receipt["commands"])
             for name in ("ring:setup", "ring:sign", "ring:verify")}
    check(calls["ring:setup"] == 1 and calls["ring:sign"] >= 1 and calls["ring:verify"] >= 1, "real v3 calls")
    matrix = receipt["acceptance"]
    check(matrix["status"] == "pass" and matrix["execution"] == "executed", "real combination acceptance")
    check(matrix["executed_checks"] == len(matrix["checks"]) >= 32 and
          all(row["status"] == "pass" for row in matrix["checks"]), "complete checked outcomes")
    required = {"honest_roundtrip", "wrong_sender", "wrong_receiver", "both_wrong", "restored_decrypt",
                "inner_authentication_rejects", "inner_rejection_reached_ibs", "empty_roundtrip"}
    check(required <= {row["name"] for row in matrix["checks"]}, "acceptance coverage")
    check(matrix["sizes"]["signature"] == 3227824 and receipt["ciphertext_bytes"] > 3227824, "actual large signature and ciphertext")
    for restored in (receipt["restore"], json.loads((HERE/"evidence/installed-restore.json").read_bytes())):
        check(restored["status"] == "passed" and restored["original_state_unchanged"] is True, "unchanged original state")
        row = restored["command"]
        check(row["code"] == 0 and row["exception"] is None and row["entropy_bytes"] == row["entropy_reads"] == 0, "zero-entropy recovery")
        check(not any(row["calls"].get("ring:"+name,0) for name in ("setup", "key_extract", "sign")), "no regeneration/signing")
    installed = json.loads((HERE/"evidence/installation.json").read_bytes())
    check(installed["wheel_contains_native_source"] and installed["all_project_providers_installed"], "independent wheel")
    for name, row in receipt["providers"].items():
        check(manifest["source_files"].get(row["repository_path"]) == row["sha256"], "CLI provider: "+name)
    for name, row in installed["providers"].items():
        check(manifest["source_files"].get(row["repository_path"]) == row["sha256"], "installed provider: "+name)
    native_source = ROOT/"experiments/research/candidates/sageloli/ring/native.cpp"
    native_id = hashlib.sha256(native_source.read_bytes()+b"-O3 -fopenmp -lflint -lgmp v1").hexdigest()
    check(receipt["native"]["source_id"] == installed["native"]["source_id"] == native_id, "native source binding")
    tests = ET.parse(HERE/"evidence/regression.xml").getroot().findall(".//testcase")
    check(len(tests) == 148 and all(not any(row.find(tag) is not None for tag in ("failure","error","skipped")) for row in tests), "148 regression passes")
    portable = json.loads((HERE/"evidence/windows-portable.json").read_bytes())
    check(portable["status"] == "passed" and len(portable["checks"]) == 8, "Windows public discovery")
    return dict(status="passed", checks=checks, private_state_read=False, experiments_rerun=False,
                cryptographic_security_certified=False, parameters_are_formal=False)


if __name__ == "__main__": print(json.dumps(verify(), sort_keys=True))
