"""Verify the frozen public SRGG runtime package; safe under python -O."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
PACKAGE = Path("docs/research/team-b-delivery/2026-10-18-srgg-serial-runtime")
SOURCE_SHA256 = "258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152"
EXPECTED = {
    "papers/2025_efficient_ibs_jia.pdf",
    "experiments/research/candidates/srgg/paper_runtime_benchmark.py",
    "tests/test_srgg_paper_runtime_benchmark.py",
    *(str(PACKAGE / name) for name in (
        "README_zh-CN.md", "README.md", "validation.json", "verify_delivery.py",
        "param-i-table-sd.json", "param-ii-table-sd.json", "param-iii-table-sd.json")),
}


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _read_json(path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)


def verify():
    manifest = _read_json(ROOT / PACKAGE / "MANIFEST.json")
    if manifest.get("schema") != "IBME/SRGG-PAPER-SERIAL-RUNTIME-MANIFEST/1":
        raise ValueError("manifest schema mismatch")
    paths = manifest.get("paths")
    if type(paths) is not dict or set(paths) != EXPECTED:
        raise ValueError("manifest path set mismatch")
    for name, expected in paths.items():
        path = (ROOT / name).resolve()
        if not path.is_relative_to(ROOT) or not path.is_file():
            raise ValueError("missing or escaped package path")
        if type(expected) is not str or len(expected) != 64:
            raise ValueError("invalid manifest digest")
        if sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("package hash mismatch: " + name)
    if paths["papers/2025_efficient_ibs_jia.pdf"] != SOURCE_SHA256:
        raise ValueError("frozen source PDF mismatch")
    validation = _read_json(ROOT / PACKAGE / "validation.json")
    if (validation.get("test_passed") != 2 or validation.get("test_failed") != 0
            or validation.get("test_skipped") != 0
            or validation.get("author_1000_run_median_reproduced") is not False
            or validation.get("author_C_rANS_implementation_reproduced") is not False
            or validation.get("security_claim") != "none"):
        raise ValueError("validation scope mismatch")
    rows = []
    for label, filename in (("PARAM-I", "param-i-table-sd.json"),
                            ("PARAM-II", "param-ii-table-sd.json"),
                            ("PARAM-III", "param-iii-table-sd.json")):
        receipt = _read_json(ROOT / PACKAGE / filename)
        workload = receipt.get("workload", {})
        if (receipt.get("schema") != "IBME/SRGG-PAPER-SERIAL-RUNTIME/1"
                or receipt.get("status") != "functional-pass"
                or receipt.get("profile", {}).get("profile_name") != label
                or receipt.get("profile", {}).get("interpretation") != "table-standard-deviation"
                or receipt.get("original_table4", {}).get("source_sha256") != SOURCE_SHA256
                or workload.get("cycles") != 3
                or workload.get("verify_fixed_calls") != 1000
                or workload.get("verify_fixed_reuses_final_signature") is not True
                or workload.get("production_random") is not True
                or workload.get("host_cpu_isolated") is not False
                or receipt.get("private_material_exported") is not False
                or receipt.get("author_C_rANS_implementation_reproduced") is not False
                or receipt.get("author_1000_run_median_reproduced") is not False
                or receipt.get("security_claim") != "none"
                or receipt.get("backend_admitted") is not False
                or receipt.get("parameters_are_formal") is not False
                or receipt.get("nist_security_category") is not None):
            raise ValueError("runtime receipt scope mismatch: " + filename)
        if (len(receipt.get("attempts", {}).get("setup_attempts", [])) != 3
                or len(receipt.get("attempts", {}).get("sign_attempts", [])) != 3
                or receipt.get("timings", {}).get("verify_fixed", {}).get("wall", {}).get("count") != 1000):
            raise ValueError("runtime call count mismatch: " + filename)
        rows.append(label)
    return {"status": "verified", "rows": rows, "bound_files": len(paths),
            "security_claim": "none"}


if __name__ == "__main__":
    print(json.dumps(verify(), sort_keys=True))
