"""Check the final local repair snapshot with standard Python, including -O."""
from hashlib import sha256
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    manifest = json.loads((HERE / "MANIFEST.json").read_text(encoding="utf-8"))
    require(manifest["schema"] == "IBME/SRGG-DEEPSEEK-REPAIRS-MANIFEST/1", "manifest schema")
    for relative, expected in manifest["files_sha256"].items():
        path = ROOT / relative
        require(not Path(relative).is_absolute() and path.resolve().is_relative_to(ROOT), "unsafe path")
        require(sha256(path.read_bytes()).hexdigest() == expected, "file differs: " + relative)
    value = json.loads((HERE / "validation.json").read_text(encoding="utf-8"))
    counts = value["full_regression"]
    require(value["status"] == "passed" and counts["passed"] > 0 and
            counts["failed"] == counts["errors"] == counts["skipped"] == 0, "regression is incomplete")
    require(value["security_claim"] == "none" and value["backend_admitted"] is False and
            value["parameters_are_formal"] is False and value["nist_security_category"] is None,
            "security metadata drift")
    sources = json.loads((HERE / "runtime-source-sha256.json").read_text(encoding="utf-8"))
    for relative, expected in sources.items():
        require(sha256((ROOT / relative).read_bytes()).hexdigest() == expected, "runtime source differs")
    require(value["runtime_sources_unchanged"] is True, "runtime source changed during tests")
    print(json.dumps({"status": "passed", "manifest_files": len(manifest["files_sha256"]),
                      "runtime_sources": len(sources), "regression_passed": counts["passed"]}, sort_keys=True))


if __name__ == "__main__":
    main()
