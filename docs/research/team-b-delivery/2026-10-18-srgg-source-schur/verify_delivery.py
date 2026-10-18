"""Read-only byte and scope checks for this frozen public SRGG delivery."""
from hashlib import sha256
import json
from pathlib import Path
import xml.etree.ElementTree as ET


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def require(condition, message):
    if not condition:
        raise SystemExit("delivery check failed: "+message)


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def safe_path(relative):
    require(type(relative) is str and relative and not Path(relative).is_absolute(), "relative path required")
    target = (ROOT/relative).resolve()
    require(target.is_relative_to(ROOT), "path escaped repository")
    require(target.is_file(), "missing file: "+relative)
    return target


def main():
    manifest = json.loads((HERE/"MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest["files"]
    require(type(entries) is dict and 1 <= len(entries) <= 1024, "manifest size")
    for name, record in entries.items():
        path = safe_path(name)
        require(path.stat().st_size == record["bytes"], "byte count: "+name)
        require(digest(path) == record["sha256"], "SHA-256: "+name)
    validation = json.loads((HERE/"validation.json").read_text(encoding="utf-8"))
    for name, expected in validation["selected_current_source_sha256"].items():
        require(digest(safe_path(name)) == expected, "source binding: "+name)
    for name in validation["final_lifecycle_receipts"]:
        record = json.loads(safe_path(name).read_text(encoding="utf-8"))
        require(record["backend_class"].endswith(".SourceSchurBackend"), "explicit source backend")
        require(record["status"] == "functional-pass", "lifecycle result")
        require(len(record["checks"]) == 37 and all(record["checks"].values()), "lifecycle checks")
        require(record["signature_attempt_entropy"]["cap_installed_by_backend"] is True, "attempt cap installed")
        require(record["signature_call_entropy"]["global_service_lifetime_entropy_cap_bytes"] is None, "lifetime claim")
        for sampler in (record["master_sampler"], record["signature_sampler"]):
            require(sampler["full_target_integer_tv_upper_including_abort"] is None, "no borrowed joint TV")
            require(sampler["joint_sampler_law_certificate_reused"] is False, "joint-law separation")
            require(sampler["parameter_widths_changed"] is False, "original widths")
        require(record["security_claim"] == "none" and record["backend_admitted"] is False
                and record["parameters_are_formal"] is False and record["nist_security_category"] is None,
                "security markers")
        require(record["private_material_exported"] is False, "private material")
    require(len(validation["final_lifecycle_receipts"]) == 7, "seven final lifecycles")
    suites = ET.parse(HERE/"regression.xml").getroot().findall("testsuite")
    counts = {name: sum(int(suite.get(name, "0")) for suite in suites)
              for name in ("tests", "failures", "errors", "skipped")}
    require(counts == validation["final_regression"]["counts"], "JUnit/validation counts")
    require(counts["failures"] == counts["errors"] == counts["skipped"] == 0, "final test success")
    exact = json.loads((HERE/"exact-preflight.json").read_text(encoding="utf-8"))
    require(digest(safe_path(exact["source_provenance"]["imported_module_snapshot"]))
            == exact["source_provenance"]["frozen_snapshot_sha256"], "historical exact snapshot")
    require(exact["status"] == "bounded-preparation-timeout", "preserved bounded failure")
    preflight = json.loads((HERE/"hardness-preflight-current.json").read_text(encoding="utf-8"))
    for name, expected in preflight["source_sha256"].items():
        require(digest(safe_path(name)) == expected, "current structural preflight source: "+name)
    require(preflight["attack_executions"] == preflight["sampler_draws"] == 0, "preflight execution scope")
    require(validation["hibe_involved"] is False and validation["pushed"] is False, "delivery scope")
    print(json.dumps({"status": "verified", "manifest_files": len(entries),
                      "selected_sources": len(validation["selected_current_source_sha256"]),
                      "final_tests": counts["tests"], "final_lifecycles": 7,
                      "security_claim": "none"}, sort_keys=True))


if __name__ == "__main__":
    main()
