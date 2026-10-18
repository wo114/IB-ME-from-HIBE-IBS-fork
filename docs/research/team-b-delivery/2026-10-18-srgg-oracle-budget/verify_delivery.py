"""Verify the frozen SRGG finite oracle rejection receipt and its sources."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PREFIX = "docs/research/team-b-delivery/2026-10-18-srgg-oracle-budget/"
PDF = "papers/2025_efficient_ibs_jia.pdf"
PDF_SHA256 = "258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152"
SOURCES = {
    "experiments/research/candidates/srgg/paper_oracle_budget.py",
    "experiments/research/candidates/srgg/paper_algebra.py",
    "experiments/research/candidates/srgg/structured_execution.py",
    "experiments/research/candidates/wang_pw/hashing.py",
    "src/ibme/core/encoding.py",
    "experiments/research/candidates/srgg/paper_profiles.py",
}
REQUIRED = SOURCES | {PDF, "tests/test_srgg_paper_oracle_budget.py"} | {
    PREFIX + name for name in (
        "README_zh-CN.md", "README.md", "proof.md", "validation.json",
        "oracle-budget.json", "verify_delivery.py",
    )
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def _json(raw: bytes):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)


def _file(name: str) -> bytes:
    _require(type(name) is str and name and "\\" not in name, "canonical path required")
    _require(all(part not in ("", ".", "..") for part in name.split("/")),
             "unsafe package path")
    rel = Path(name)
    _require(not rel.is_absolute() and rel.as_posix() == name, "noncanonical package path")
    target = (ROOT / rel).resolve()
    _require(target.is_relative_to(ROOT) and target.is_file(), "package file absent: " + name)
    return target.read_bytes()


def main() -> None:
    manifest = _json(_file(PREFIX + "MANIFEST.json"))
    entries = manifest.get("entries")
    _require(manifest.get("schema") == "IBME/SRGG-PAPER-ORACLE-BUDGET-MANIFEST/1"
             and type(entries) is dict and set(entries) == REQUIRED,
             "manifest scope mismatch")
    for name, entry in entries.items():
        raw = _file(name)
        _require(type(entry) is dict and set(entry) == {"bytes", "sha256"}
                 and type(entry["bytes"]) is int and entry["bytes"] == len(raw)
                 and type(entry["sha256"]) is str
                 and entry["sha256"] == sha256(raw).hexdigest(),
                 "manifest byte/hash mismatch: " + name)

    _require(sha256(_file(PDF)).hexdigest() == PDF_SHA256, "paper checksum mismatch")
    receipt = _json(_file(PREFIX + "oracle-budget.json"))
    validation = _json(_file(PREFIX + "validation.json"))
    _require(validation.get("schema") == "IBME/SRGG-PAPER-ORACLE-BUDGET-VALIDATION/1"
             and validation.get("paper_sha256") == PDF_SHA256
             and (validation.get("test_passed"), validation.get("test_failed"),
                  validation.get("test_skipped")) == (10, 0, 0)
             and validation.get("rom_model_is_a_premise") is True
             and validation.get("concrete_SHAKE_to_ROM_bound") is None,
             "validation exceeds finite ideal-byte evidence")
    _require(receipt.get("schema") == "IBME/SRGG-PAPER-ORACLE-BUDGET/1"
             and receipt.get("paper") == {
                 "path": PDF, "sha256": PDF_SHA256,
                 "locations": "Table 4 PDF p.10; source algorithm hash inputs checked in code",
             }
             and receipt.get("actual_SHAKE_distribution_to_ideal_RO_TV_upper") is None
             and receipt.get("full_RO_or_QROM_game_bound") is None,
             "frozen receipt scope mismatch")
    for obj in (validation, receipt):
        _require(obj.get("security_claim") == "none"
                 and obj.get("backend_admitted") is False
                 and obj.get("parameters_are_formal") is False
                 and obj.get("nist_security_category") is None,
                 "unearned security claim")
    source_hashes = receipt.get("source_sha256")
    _require(type(source_hashes) is dict and set(source_hashes) == SOURCES,
             "source binding scope mismatch")
    for name in SOURCES:
        _require(source_hashes[name] == sha256(_file(name)).hexdigest(),
                 "source differs from frozen receipt: " + name)

    from experiments.research.candidates.srgg.paper_oracle_budget import report
    _require(report() == receipt, "live Table 4 rejection budget differs from receipt")
    rows = receipt["rows"]
    _require(type(rows) is list and len(rows) == 3
             and [(row["profile"], row["joint_exhaustion_probability_strictly_below_2_negative"])
                  for row in rows] == [("PARAM-I", 1012), ("PARAM-II", 1011),
                                      ("PARAM-III", 1010)],
             "three original-row bounds changed")
    print(json.dumps({"status": "verified", "entries": len(entries),
                      "rows": 3, "premise": "ideal uniform XOF bytes",
                      "security_claim": "none"}, sort_keys=True))


if __name__ == "__main__":
    main()
