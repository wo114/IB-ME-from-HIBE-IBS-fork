"""Verify the publication's portable source bindings and actual test counts."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

HISTORICAL_COMMIT = "2180286c432ce8ea5d44d32091d2ef7b9393c1e2"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def historical_bytes(root: Path, relative: str) -> bytes:
    return subprocess.check_output(
        ["git", "show", f"{HISTORICAL_COMMIT}:{relative}"], cwd=root)


def verify_target_receipt(receipt: dict) -> None:
    expected = {"n": 2048, "q": 274877976577, "k": 39, "l": 2, "p": 2,
                "sigma": 2.0, "sigma_r": 1.0, "identity_bytes": 86,
                "max_message_bytes": 32, "message_mode": "seed32"}
    require(receipt.get("parameters") == expected, "C2 target parameters differ")
    require(receipt.get("schema") == "IBME/LAI/C2-TARGET-RECEIPT/1", "C2 receipt schema changed")
    require(receipt.get("all_ok") is True, "C2 target receipt did not pass")
    honest = receipt["honest"]
    require(honest["rc"] == 0 and honest["matches"] is True
            and honest["output_bytes"] == receipt["message_bytes"], "C2 honest receipt differs")
    wrong = receipt["wrong_identity"]
    require(set(wrong) == {"wrong_receiver", "wrong_sender", "both_wrong"}, "C2 identity cases missing")
    require(all(value["bottom"] is True and value["rc"] == 1 and value["output_bytes"] == 0
                for value in wrong.values()), "C2 wrong-identity receipt differs")
    outer = receipt["outer_tamper"]
    require(outer["rc"] == 0 and outer["all_ok"] is True, "C2 outer tamper failed")
    require(set(outer["cases"]) == {"tampered_context", "tampered_signature", "tampered_inner_bytes",
                                     "truncated_ct", "appended_ct"}, "C2 tamper cases missing")
    require(all(value["rejected"] is True for value in outer["cases"].values()), "C2 tamper accepted")
    require(receipt["target_c2_rerun_this_batch"] is True, "C2 receipt scope changed")
    require(receipt["security_claim"] == "none" and receipt["backend_admitted"] is False
            and receipt["parameters_are_formal"] is False, "C2 security metadata changed")


def main(*, historical=False) -> None:
    directory = Path(__file__).resolve().parent
    root = directory.parents[3]
    if historical:
        bindings = json.loads(historical_bytes(
            root, "docs/research/team-c-delivery/2026-10-19-lai-publication/source-bindings.json"))
    else:
        bindings = json.loads((directory / "source-bindings.json").read_text(encoding="utf-8"))
    snapshot_count = 0
    for relative, expected in bindings["sha256_lf"].items():
        path = root / relative
        require(path.resolve().is_relative_to(root.resolve()), "binding escapes repository")
        raw = historical_bytes(root, relative) if historical else path.read_bytes()
        actual = hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest()
        if actual != expected and not historical:
            snapshot = bindings.get("publication_snapshots", {}).get(relative)
            require(snapshot is not None, "source binding differs: " + relative)
            target = (directory / snapshot["path"]).resolve()
            require(target.is_relative_to(directory.resolve()), "snapshot escapes publication")
            raw = target.read_bytes()
            actual = hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest()
            snapshot_count += 1
        require(actual == expected, "source binding differs: " + relative)

    if historical:
        validation = json.loads(historical_bytes(
            root, "docs/research/team-c-delivery/2026-10-19-lai-publication/validation.json"))
    else:
        validation = json.loads((directory / "validation.json").read_text(encoding="utf-8"))
    all_names: set[tuple[str, str]] = set()
    total = 0
    for name, expected_count in (("primitive.xml", 57), ("integration.xml", 210)):
        raw = (historical_bytes(
            root, "docs/research/team-c-delivery/2026-10-19-lai-publication/evidence/" + name)
            if historical else (directory / "evidence" / name).read_bytes())
        xml = ET.fromstring(raw)
        cases = list(xml.iter("testcase"))
        require(len(cases) == expected_count, "test count differs: " + name)
        for case in cases:
            require(not any(case.find(tag) is not None for tag in ("failure", "error", "skipped")),
                    "test did not pass: " + case.attrib.get("name", ""))
            identity = (case.attrib.get("classname", ""), case.attrib.get("name", ""))
            require(identity not in all_names, "duplicate test case")
            all_names.add(identity)
        require(all("hostname" not in node.attrib for node in xml.iter()), "hostname not redacted")
        total += len(cases)
    require(total == validation["pytest_total"] == 267, "combined count differs")
    require(validation["security_claim"] == "none", "security claim changed")
    require(validation["backend_admitted"] is False, "admission changed")
    require(validation["parameters_are_formal"] is False, "parameter status changed")
    require(validation["nist_security_category"] is None, "NIST category changed")
    if historical:
        require(validation["target_c2_rerun_this_batch"] is False,
                "historical C2 rerun scope changed")
    else:
        require(validation["target_c2_rerun_this_batch"] is True, "C2 rerun scope changed")
        receipt_path = directory / "evidence" / "target-c2-receipt.json"
        require(receipt_path.exists(), "C2 receipt missing")
        require(hashlib.sha256(receipt_path.read_bytes()).hexdigest() == validation["target_c2_receipt_sha256"],
                "C2 receipt digest differs")
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        verify_target_receipt(receipt)
    require(validation["windows_without_sage"]["status"] == "passed", "Windows discovery failed")
    require(validation["shell_workspace_checks"]["cases"] == 4, "shell case count differs")
    print(json.dumps({"status": "passed", "source_bindings": len(bindings["sha256_lf"]),
                      "pytest_passed": total,
                      "target_c2_rerun": validation["target_c2_rerun_this_batch"],
                      "publication_snapshots_used": snapshot_count,
                      "source_mode": "historical Git 2180286" if historical else "checkout plus explicit publication snapshots"}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--historical', action='store_true',
                        help='check the original publication Git snapshot after later integration changes')
    main(historical=parser.parse_args().historical)
