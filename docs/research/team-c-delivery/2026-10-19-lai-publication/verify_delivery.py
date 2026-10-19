"""Verify the publication's portable source bindings and actual test counts."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> None:
    directory = Path(__file__).resolve().parent
    root = directory.parents[3]
    bindings = json.loads((directory / "source-bindings.json").read_text(encoding="utf-8"))
    for relative, expected in bindings["sha256_lf"].items():
        path = root / relative
        require(path.resolve().is_relative_to(root.resolve()), "binding escapes repository")
        actual = hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        require(actual == expected, "source binding differs: " + relative)
    validation = json.loads((directory / "validation.json").read_text(encoding="utf-8"))
    all_names: set[tuple[str, str]] = set()
    total = 0
    for name, expected in (("primitive.xml", 57), ("integration.xml", 210)):
        xml = ET.parse(directory / "evidence" / name).getroot()
        cases = list(xml.iter("testcase"))
        require(len(cases) == expected, "test count differs: " + name)
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
    require(validation["target_c2_rerun_this_batch"] is False, "C2 rerun scope changed")
    require(validation["windows_without_sage"]["status"] == "passed", "Windows discovery failed")
    require(validation["shell_workspace_checks"]["cases"] == 4, "shell case count differs")
    print(json.dumps({"status": "passed", "source_bindings": len(bindings["sha256_lf"]),
                      "pytest_passed": total, "target_c2_rerun": False}))


if __name__ == "__main__":
    main()
